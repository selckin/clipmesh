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

pub struct SendHalf<W> {
    io: W,
    st: Arc<StatelessTransportState>,
    nonce: u64,
}

pub struct RecvHalf<R> {
    io: R,
    st: Arc<StatelessTransportState>,
    nonce: u64,
    plain_buf: Vec<u8>,
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
        SendHalf { io: wr, st: st.clone(), nonce: 0 },
        RecvHalf { io: rd, st, nonce: 0, plain_buf: Vec::new(), max_message },
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
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(4 + plaintext.len());
        framed.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        framed.extend_from_slice(plaintext);
        let mut out = vec![0u8; NOISE_MAX];
        for chunk in framed.chunks(CHUNK) {
            let n = self.st.write_message(self.nonce, chunk, &mut out)?;
            self.nonce += 1;
            write_record(&mut self.io, &out[..n]).await?;
        }
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> RecvHalf<R> {
    /// Receive one logical message. Errors are terminal for the connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; NOISE_MAX];
        loop {
            if self.plain_buf.len() >= 4 {
                let len = u32::from_be_bytes(self.plain_buf[..4].try_into().unwrap()) as usize;
                if len > self.max_message {
                    bail!("message too large: {len} > {}", self.max_message);
                }
                if self.plain_buf.len() >= 4 + len {
                    let msg = self.plain_buf[4..4 + len].to_vec();
                    self.plain_buf.drain(..4 + len);
                    return Ok(msg);
                }
            }
            let record = read_record(&mut self.io).await?;
            let n = self
                .st
                .read_message(self.nonce, &record, &mut out)
                .context("decrypt failed (tampering or desync)")?;
            self.nonce += 1;
            self.plain_buf.extend_from_slice(&out[..n]);
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
        anyhow::Result<(SendHalf<tokio::io::WriteHalf<tokio::io::DuplexStream>>, RecvHalf<tokio::io::ReadHalf<tokio::io::DuplexStream>>)>,
        anyhow::Result<(SendHalf<tokio::io::WriteHalf<tokio::io::DuplexStream>>, RecvHalf<tokio::io::ReadHalf<tokio::io::DuplexStream>>)>,
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
