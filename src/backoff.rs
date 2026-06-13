//! Shared reconnect backoff for the watcher threads (clipboard and file).

use std::time::Duration;

/// Exponential backoff with a ceiling, reset to the minimum once a run lasted
/// long enough to look healthy. `prev` is the last delay, `ran_for` how long the
/// just-ended run lived: a short-lived run doubles the delay (capped at `max`),
/// a run of at least `stable_after` resets it to `min`.
pub fn next_delay(
    prev: Duration,
    ran_for: Duration,
    min: Duration,
    max: Duration,
    stable_after: Duration,
) -> Duration {
    if ran_for < stable_after {
        (prev * 2).min(max)
    } else {
        min
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_off_then_resets_after_a_stable_run() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        let stable = Duration::from_secs(5);
        // A short-lived run escalates the backoff (doubles), capped at max.
        assert_eq!(
            next_delay(min, Duration::from_millis(10), min, max, stable),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_delay(
                Duration::from_secs(20),
                Duration::from_millis(10),
                min,
                max,
                stable
            ),
            max
        );
        // A run that stayed up long enough resets the backoff to the minimum.
        assert_eq!(
            next_delay(max, Duration::from_secs(10), min, max, stable),
            min
        );
    }
}
