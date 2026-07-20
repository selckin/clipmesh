use anyhow::{bail, Context, Result};
use snow::{Builder, StatelessTransportState};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
/// Noise caps a single record (ciphertext) at 65535 bytes.
const NOISE_MAX: usize = 65535;
const TAG_LEN: usize = 16;
/// Max plaintext per Noise record.
const CHUNK: usize = NOISE_MAX - TAG_LEN;
/// Reassembly capacity kept between messages. A single large clipboard payload
/// would otherwise leave its whole footprint resident for the connection's
/// lifetime, and the mesh holds roughly two connections per peer — so one 32 MiB
/// copy could pin 64 MiB per peer indefinitely, long after the copy is gone.
const PLAIN_BUF_KEEP: usize = 64 * 1024;

pub struct SendHalf<W> {
    io: W,
    st: Arc<StatelessTransportState>,
    nonce: u64,
    /// Ciphertext scratch, sized once to the largest a Noise record can be.
    /// Reused across sends rather than reallocated (and re-zeroed) per message.
    out: Vec<u8>,
    /// Assembly space for the first chunk only: the 4-byte length prefix plus
    /// as much payload as fits. Every later chunk is a slice of the caller's
    /// plaintext, written through without a copy.
    head: Vec<u8>,
}

pub struct RecvHalf<R> {
    io: R,
    st: Arc<StatelessTransportState>,
    nonce: u64,
    plain_buf: Vec<u8>,
    /// Plaintext scratch for one decrypted record; see `SendHalf::out`.
    out: Vec<u8>,
    max_message: usize,
}

/// Perform the Noise NNpsk0 handshake and split the stream into owned
/// send/recv halves sharing a stateless transport (separate nonces per
/// direction, so the halves can live in independent tasks).
pub async fn handshake<S>(
    io: S,
    psk: &[u8; 32],
    initiator: bool,
    max_message: usize,
) -> Result<(SendHalf<WriteHalf<S>>, RecvHalf<ReadHalf<S>>)>
where
    S: AsyncRead + AsyncWrite,
{
    let builder = Builder::new(NOISE_PARAMS.parse().expect("valid noise params")).psk(0, psk);
    let mut hs = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };

    let (mut rd, mut wr) = tokio::io::split(io);
    let mut buf = vec![0u8; NOISE_MAX];
    let mut payload = vec![0u8; NOISE_MAX];
    if initiator {
        // -> e (with psk0)
        let n = hs.write_message(&[], &mut buf)?;
        write_record(&mut wr, &buf[..n]).await?;
        // <- e, ee
        let msg = read_record(&mut rd).await?;
        hs.read_message(&msg, &mut payload)
            .context("noise handshake failed (PSK mismatch?)")?;
    } else {
        let msg = read_record(&mut rd).await?;
        hs.read_message(&msg, &mut payload)
            .context("noise handshake failed (PSK mismatch?)")?;
        let n = hs.write_message(&[], &mut buf)?;
        write_record(&mut wr, &buf[..n]).await?;
    }

    let st = Arc::new(hs.into_stateless_transport_mode()?);
    Ok((
        SendHalf {
            io: wr,
            st: st.clone(),
            nonce: 0,
            out: vec![0u8; NOISE_MAX],
            head: Vec::with_capacity(CHUNK),
        },
        RecvHalf {
            io: rd,
            st,
            nonce: 0,
            plain_buf: Vec::new(),
            out: vec![0u8; NOISE_MAX],
            max_message,
        },
    ))
}

async fn write_record<W: AsyncWrite + Unpin>(io: &mut W, data: &[u8]) -> Result<()> {
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await?;
    Ok(())
}

async fn read_record<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > NOISE_MAX {
        bail!("record too large: {len}");
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

impl<W: AsyncWrite + Unpin> SendHalf<W> {
    /// Send one logical message of any size (chunked into Noise records).
    ///
    /// The length prefix and the payload are chunked as one logical stream, but
    /// never concatenated into one buffer: only the first chunk is assembled,
    /// and the rest are slices of `plaintext` encrypted straight out of the
    /// caller's buffer. Concatenating would copy the whole message — up to
    /// `max_payload_size` — on every send, per connection.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let len = u32::try_from(plaintext.len()).context("message too large for framing")?;
        const HEADER: usize = 4;
        let head_payload = plaintext.len().min(CHUNK - HEADER);

        self.head.clear();
        self.head.extend_from_slice(&len.to_be_bytes());
        self.head.extend_from_slice(&plaintext[..head_payload]);
        // Distinct fields, so these borrows don't overlap.
        let (io, st, nonce, out) = (&mut self.io, &*self.st, &mut self.nonce, &mut self.out);
        write_chunk(io, st, nonce, out, &self.head).await?;

        for chunk in plaintext[head_payload..].chunks(CHUNK) {
            write_chunk(io, st, nonce, out, chunk).await?;
        }
        Ok(())
    }
}

/// Encrypt one chunk under the next nonce and write it as a length-prefixed
/// record. Free-standing (rather than a method) so the caller can hold a borrow
/// of `SendHalf::head` while passing the other fields.
async fn write_chunk<W: AsyncWrite + Unpin>(
    io: &mut W,
    st: &StatelessTransportState,
    nonce: &mut u64,
    out: &mut [u8],
    chunk: &[u8],
) -> Result<()> {
    let n = st.write_message(*nonce, chunk, out)?;
    *nonce += 1;
    write_record(io, &out[..n]).await
}

impl<R: AsyncRead + Unpin> RecvHalf<R> {
    /// Receive one logical message. Errors are terminal for the connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.plain_buf.len() >= 4 {
                let len = u32::from_be_bytes(self.plain_buf[..4].try_into().unwrap()) as usize;
                if len > self.max_message {
                    bail!("message too large: {len} > {}", self.max_message);
                }
                if self.plain_buf.len() >= 4 + len {
                    let msg = self.plain_buf[4..4 + len].to_vec();
                    self.plain_buf.drain(..4 + len);
                    // Release the reassembly space an outsized message grew,
                    // instead of holding its high-water mark for the life of
                    // the connection.
                    if self.plain_buf.capacity() > PLAIN_BUF_KEEP
                        && self.plain_buf.len() <= PLAIN_BUF_KEEP
                    {
                        self.plain_buf.shrink_to(PLAIN_BUF_KEEP);
                    }
                    return Ok(msg);
                }
            }
            let record = read_record(&mut self.io).await?;
            let n = self
                .st
                .read_message(self.nonce, &record, &mut self.out)
                .context("decrypt failed (tampering or desync)")?;
            self.nonce += 1;
            self.plain_buf.extend_from_slice(&self.out[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 8 * 1024 * 1024;

    async fn pair(
        psk_a: [u8; 32],
        psk_b: [u8; 32],
    ) -> (
        anyhow::Result<(
            SendHalf<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            RecvHalf<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        )>,
        anyhow::Result<(
            SendHalf<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            RecvHalf<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        )>,
    ) {
        let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
        tokio::join!(
            handshake(a, &psk_a, true, MAX),
            handshake(b, &psk_b, false, MAX),
        )
    }

    #[tokio::test]
    async fn round_trips_messages_both_ways() {
        let psk = [7u8; 32];
        let (ca, cb) = pair(psk, psk).await;
        let (mut atx, mut arx) = ca.unwrap();
        let (mut btx, mut brx) = cb.unwrap();

        atx.send(b"hello").await.unwrap();
        assert_eq!(brx.recv().await.unwrap(), b"hello");

        btx.send(b"world").await.unwrap();
        assert_eq!(arx.recv().await.unwrap(), b"world");

        // several messages in sequence (nonce bookkeeping)
        for i in 0..10u8 {
            atx.send(&[i]).await.unwrap();
        }
        for i in 0..10u8 {
            assert_eq!(brx.recv().await.unwrap(), vec![i]);
        }
    }

    #[tokio::test]
    async fn chunks_messages_larger_than_one_noise_record() {
        let psk = [7u8; 32];
        let (ca, cb) = pair(psk, psk).await;
        let (mut atx, _) = ca.unwrap();
        let (_, mut brx) = cb.unwrap();

        let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        atx.send(&big).await.unwrap();
        assert_eq!(brx.recv().await.unwrap(), big);
    }

    /// `send` splits the 4-byte length prefix and the payload across Noise
    /// records without ever concatenating them, so the sizes where a chunk
    /// boundary lands exactly on (or beside) the prefix are the ones that would
    /// break. Walk them explicitly.
    #[tokio::test]
    async fn round_trips_messages_at_every_chunk_boundary() {
        const HEADER: usize = 4;
        let sizes = [
            0, // header only, no payload
            1,
            CHUNK - HEADER - 1, // first record one byte short of full
            CHUNK - HEADER,     // first record exactly full, nothing left over
            CHUNK - HEADER + 1, // spills a single byte into a second record
            CHUNK,
            CHUNK + 1,
            2 * CHUNK - HEADER, // second record exactly full
            2 * CHUNK,
        ];
        let psk = [7u8; 32];
        let (ca, cb) = pair(psk, psk).await;
        let (mut atx, _) = ca.unwrap();
        let (_, mut brx) = cb.unwrap();

        for size in sizes {
            let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            atx.send(&msg).await.unwrap();
            let got = brx.recv().await.unwrap();
            assert_eq!(got.len(), size, "wrong length for a {size}-byte message");
            assert_eq!(got, msg, "corrupted round trip for a {size}-byte message");
        }
    }

    /// A single outsized message must not pin its whole footprint for the
    /// connection's lifetime — the mesh keeps ~2 connections per peer.
    #[tokio::test]
    async fn reassembly_buffer_does_not_retain_a_large_messages_footprint() {
        let psk = [7u8; 32];
        let (ca, cb) = pair(psk, psk).await;
        let (mut atx, _) = ca.unwrap();
        let (_, mut brx) = cb.unwrap();

        let big = vec![0xABu8; 3 * 1024 * 1024];
        atx.send(&big).await.unwrap();
        assert_eq!(brx.recv().await.unwrap().len(), big.len());
        assert!(
            brx.plain_buf.capacity() <= PLAIN_BUF_KEEP,
            "held {} bytes of reassembly capacity after a {}-byte message",
            brx.plain_buf.capacity(),
            big.len()
        );

        // Still usable afterwards.
        atx.send(b"after").await.unwrap();
        assert_eq!(brx.recv().await.unwrap(), b"after");
    }

    #[tokio::test]
    async fn handshake_fails_with_mismatched_psk() {
        let (ca, cb) = pair([1u8; 32], [2u8; 32]).await;
        assert!(cb.is_err(), "responder must reject wrong PSK");
        assert!(ca.is_err(), "initiator side must also fail (peer hung up)");
    }

    #[tokio::test]
    async fn recv_rejects_messages_over_the_cap() {
        let psk = [7u8; 32];
        let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
        let (ca, cb) = tokio::join!(
            handshake(a, &psk, true, MAX),
            handshake(b, &psk, false, 1024), // tiny receive cap
        );
        let (mut atx, _) = ca.unwrap();
        let (_, mut brx) = cb.unwrap();

        atx.send(&vec![0u8; 100_000]).await.unwrap();
        assert!(brx.recv().await.is_err());
    }
}
