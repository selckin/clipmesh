//! Shared exponential reconnect backoff.
//!
//! One type for all three retry loops in the daemon — the two watcher threads
//! (file and clipboard) and the peer dial loop. They differ in their tuning and
//! in *when* they consider an attempt successful, not in the escalation rule, so
//! they share the state machine and supply their own policy.

use rand::Rng;
use std::time::Duration;

/// Exponential backoff with a ceiling and optional jitter.
///
/// `next_delay()` returns the delay to wait and escalates for the attempt after it;
/// `reset()` drops back to the minimum. Callers decide what counts as success —
/// the watchers reset when a run stayed up long enough to look healthy, the dial
/// loop when a connection lived that long — which is the one thing that genuinely
/// differs between them.
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    /// Fraction of the delay added as random jitter, as a divisor: `2` means up
    /// to half the delay. `None` for no jitter.
    ///
    /// The dial loop wants it so that peers which lost a switch (or a laptop
    /// waking) don't all redial in lockstep; the watchers are per-host and have
    /// nothing to desynchronise from.
    jitter_divisor: Option<u32>,
    current: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Backoff {
            min,
            max,
            jitter_divisor: None,
            current: min,
        }
    }

    /// Add up to `1/divisor` of each delay as random jitter.
    pub fn with_jitter(mut self, divisor: u32) -> Self {
        self.jitter_divisor = Some(divisor.max(1));
        self
    }

    /// The delay to wait before the next attempt, escalating for the one after.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * 2).min(self.max);
        match self.jitter_divisor {
            Some(d) => delay + Duration::from_millis(jitter_ms(delay, d)),
            None => delay,
        }
    }

    /// Drop back to the minimum: the last attempt is judged a success. Private:
    /// callers express success through `reset_if_stable`, which is the policy.
    fn reset(&mut self) {
        self.current = self.min;
    }

    /// `reset()` if the attempt lasted at least `stable_after`, else leave the
    /// escalation in place. The watchers' notion of success.
    pub fn reset_if_stable(&mut self, ran_for: Duration, stable_after: Duration) {
        if ran_for >= stable_after {
            self.reset();
        }
    }
}

fn jitter_ms(delay: Duration, divisor: u32) -> u64 {
    let span = delay.as_millis() as u64 / u64::from(divisor);
    if span == 0 {
        return 0;
    }
    rand::thread_rng().gen_range(0..=span)
}

/// Restart policy shared by the long-lived watcher threads, so the two
/// supervisors can't drift apart.
pub const RESTART_MIN: Duration = Duration::from_secs(1);
pub const RESTART_MAX: Duration = Duration::from_secs(30);
/// A run shorter than this counts as a failure and escalates backoff.
pub const RESTART_STABLE_AFTER: Duration = Duration::from_secs(5);

/// A [`Backoff`] tuned for a watcher-thread restart loop.
pub fn watcher_restart() -> Backoff {
    Backoff::new(RESTART_MIN, RESTART_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> Backoff {
        Backoff::new(Duration::from_secs(1), Duration::from_secs(30))
    }

    #[test]
    fn doubles_each_attempt_and_stops_at_the_ceiling() {
        let mut b = fixed();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        for _ in 0..10 {
            b.next_delay();
        }
        assert_eq!(b.next_delay(), Duration::from_secs(30), "capped at max");
    }

    #[test]
    fn reset_returns_to_the_minimum() {
        let mut b = fixed();
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn reset_if_stable_only_resets_after_a_long_enough_run() {
        let stable = Duration::from_secs(5);
        let mut b = fixed();
        b.next_delay(); // now at 2s
        b.reset_if_stable(Duration::from_millis(10), stable);
        assert_eq!(
            b.next_delay(),
            Duration::from_secs(2),
            "short run keeps escalating"
        );

        let mut b = fixed();
        b.next_delay();
        b.reset_if_stable(Duration::from_secs(10), stable);
        assert_eq!(b.next_delay(), Duration::from_secs(1), "healthy run resets");
    }

    #[test]
    fn jitter_never_shortens_a_delay_and_is_bounded() {
        let mut b = Backoff::new(Duration::from_secs(4), Duration::from_secs(4)).with_jitter(2);
        for _ in 0..50 {
            let d = b.next_delay();
            assert!(
                d >= Duration::from_secs(4) && d <= Duration::from_secs(6),
                "jittered delay {d:?} outside [4s, 6s]"
            );
        }
    }
}
