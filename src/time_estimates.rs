//! Contains structs and methods for calculating estimated time
//! needed to crack a given password.
//!
//! # Example
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use zxcvbn::zxcvbn;
//! use zxcvbn::time_estimates::CrackTimes;
//!
//! let entropy = zxcvbn("password123", &[]);
//! assert_eq!(entropy.crack_times().guesses(), 596);
//! assert_eq!(entropy.crack_times().online_throttling_100_per_hour().to_string(), "5 hours");
//! assert_eq!(entropy.crack_times().online_no_throttling_10_per_second().to_string(), "59 seconds");
//! assert_eq!(entropy.crack_times().offline_slow_hashing_1e4_per_second().to_string(), "less than a second");
//! assert_eq!(entropy.crack_times().offline_fast_hashing_1e10_per_second().to_string(), "less than a second");
//! #
//! #     Ok(())
//! # }
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::scoring::Score;

/// Back-of-the-envelope crack time estimations, in seconds, based on a few scenarios.
///
/// When created from `Entropy::crack_times()`, these estimates continue to
/// use the unsaturated logarithmic magnitude internally even if
/// `Entropy::guesses()` has saturated at `u64::MAX`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "ser", derive(serde::Deserialize, serde::Serialize))]
pub struct CrackTimes {
    guesses: u64,
    #[cfg_attr(
        feature = "ser",
        serde(deserialize_with = "crate::serialization_utils::deserialize_f64_null_as_nan")
    )]
    guesses_log10: f64,
}

impl PartialEq for CrackTimes {
    fn eq(&self, other: &Self) -> bool {
        self.guesses == other.guesses
            && self.guesses_log10.to_bits() == other.guesses_log10.to_bits()
    }
}

impl Eq for CrackTimes {}

impl Hash for CrackTimes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.guesses.hash(state);
        self.guesses_log10.to_bits().hash(state);
    }
}

impl CrackTimes {
    /// Get the time needed to crack a password based on the amount of guesses needed.
    ///
    /// # Arguments
    /// * `guesses` - The number of guesses needed to crack a password.
    ///
    /// This constructor only receives the integer guess count. If you already
    /// have an `Entropy`, prefer `Entropy::crack_times()` so saturated guess
    /// counts can still retain their unsaturated logarithmic magnitude.
    pub fn new(guesses: u64) -> Self {
        Self::new_with_log10(guesses, (guesses as f64).log10())
    }

    pub(crate) fn new_with_log10(guesses: u64, guesses_log10: f64) -> Self {
        CrackTimes {
            guesses,
            guesses_log10,
        }
    }

    /// Get the integer guess count used for this crack-time estimate.
    ///
    /// This value may saturate at `u64::MAX`. Use `Entropy::guesses_log10()`
    /// when you need the true order of magnitude for very large search spaces.
    pub fn guesses(self) -> u64 {
        self.guesses
    }

    #[cfg(test)]
    pub(crate) fn guesses_log10(self) -> f64 {
        self.guesses_log10
    }

    /// Online attack on a service that rate-limits password attempts.
    pub fn online_throttling_100_per_hour(self) -> CrackTimeSeconds {
        if self.guesses == u64::MAX {
            CrackTimeSeconds::Float(10f64.powf(self.guesses_log10 + 36.0f64.log10()))
        } else {
            CrackTimeSeconds::Integer(self.guesses.saturating_mul(36))
        }
    }

    /// Online attack on a service that doesn't rate-limit,
    /// or where an attacker has outsmarted rate-limiting.
    pub fn online_no_throttling_10_per_second(self) -> CrackTimeSeconds {
        if self.guesses == u64::MAX {
            CrackTimeSeconds::Float(10f64.powf(self.guesses_log10 - 1.0))
        } else {
            CrackTimeSeconds::Float(self.guesses as f64 / 10.00)
        }
    }

    /// Offline attack, assumes multiple attackers.
    /// Proper user-unique salting, and a slow hash function
    /// such as bcrypt, scrypt, PBKDF2.
    pub fn offline_slow_hashing_1e4_per_second(self) -> CrackTimeSeconds {
        if self.guesses == u64::MAX {
            CrackTimeSeconds::Float(10f64.powf(self.guesses_log10 - 4.0))
        } else {
            CrackTimeSeconds::Float(self.guesses as f64 / 10_000.00)
        }
    }

    /// Offline attack with user-unique salting but a fast hash function
    /// such as SHA-1, SHA-256, or MD5. A wide range of reasonable numbers
    /// anywhere from one billion to one trillion guesses per second,
    /// depending on number of cores and machines, ballparking at 10 billion per second.
    pub fn offline_fast_hashing_1e10_per_second(self) -> CrackTimeSeconds {
        if self.guesses == u64::MAX {
            CrackTimeSeconds::Float(10f64.powf(self.guesses_log10 - 10.0))
        } else {
            CrackTimeSeconds::Float(self.guesses as f64 / 10_000_000_000.00)
        }
    }
}

/// Represents the time to crack a password.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "ser", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "ser", serde(untagged))]
pub enum CrackTimeSeconds {
    /// The number of seconds needed to crack a password, expressed as an integer.
    Integer(u64),
    /// The number of seconds needed to crack a password, expressed as a float.
    Float(f64),
}

impl fmt::Display for CrackTimeSeconds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let seconds = match self {
            CrackTimeSeconds::Integer(i) => *i,
            CrackTimeSeconds::Float(f) => *f as u64,
        };
        const MINUTE: u64 = 60;
        const HOUR: u64 = MINUTE * 60;
        const DAY: u64 = HOUR * 24;
        const MONTH: u64 = DAY * 31;
        const YEAR: u64 = MONTH * 12;
        const CENTURY: u64 = YEAR * 100;
        if seconds < 1 {
            write!(f, "less than a second")
        } else if seconds < MINUTE {
            let base = seconds;
            write!(f, "{} second{}", base, if base > 1 { "s" } else { "" })
        } else if seconds < HOUR {
            let base = seconds / MINUTE;
            write!(f, "{} minute{}", base, if base > 1 { "s" } else { "" })
        } else if seconds < DAY {
            let base = seconds / HOUR;
            write!(f, "{} hour{}", base, if base > 1 { "s" } else { "" })
        } else if seconds < MONTH {
            let base = seconds / DAY;
            write!(f, "{} day{}", base, if base > 1 { "s" } else { "" })
        } else if seconds < YEAR {
            let base = seconds / MONTH;
            write!(f, "{} month{}", base, if base > 1 { "s" } else { "" })
        } else if seconds < CENTURY {
            let base = seconds / YEAR;
            write!(f, "{} year{}", base, if base > 1 { "s" } else { "" })
        } else {
            write!(f, "centuries")
        }
    }
}

impl From<CrackTimeSeconds> for std::time::Duration {
    fn from(s: CrackTimeSeconds) -> std::time::Duration {
        match s {
            // TODO: Use `from_secs_f64` when it is stable
            CrackTimeSeconds::Float(f) => std::time::Duration::from_secs(f as u64),
            CrackTimeSeconds::Integer(i) => std::time::Duration::from_secs(i),
        }
    }
}

pub(crate) fn estimate_attack_times(guesses: u64, guesses_log10: f64) -> (CrackTimes, Score) {
    (
        CrackTimes::new_with_log10(guesses, guesses_log10),
        calculate_score(guesses),
    )
}

fn calculate_score(guesses: u64) -> Score {
    const DELTA: u64 = 5;
    if guesses < 1_000 + DELTA {
        Score::Zero
    } else if guesses < 1_000_000 + DELTA {
        Score::One
    } else if guesses < 100_000_000 + DELTA {
        Score::Two
    } else if guesses < 10_000_000_000 + DELTA {
        Score::Three
    } else {
        Score::Four
    }
}

#[cfg(test)]
mod tests {
    use super::{CrackTimeSeconds, CrackTimes};

    #[test]
    fn test_crack_times_preserves_unsaturated_behavior() {
        let crack_times = CrackTimes::new(100);
        assert_eq!(crack_times.guesses(), 100);
        assert_eq!(
            crack_times.online_throttling_100_per_hour(),
            CrackTimeSeconds::Integer(3600)
        );
        assert_eq!(
            crack_times.online_no_throttling_10_per_second(),
            CrackTimeSeconds::Float(10.0)
        );
    }

    #[test]
    fn test_crack_times_uses_unsaturated_log10_when_guesses_saturate() {
        let crack_times = CrackTimes::new_with_log10(u64::MAX, 25.0);
        assert_eq!(crack_times.guesses(), u64::MAX);
        assert_eq!(crack_times.guesses_log10(), 25.0);

        assert_eq!(
            crack_times.offline_fast_hashing_1e10_per_second(),
            CrackTimeSeconds::Float(1e15)
        );

        let CrackTimeSeconds::Float(seconds) = crack_times.online_throttling_100_per_hour() else {
            panic!("expected float crack time for saturated guesses");
        };
        assert!((seconds.log10() - (25.0 + 36.0f64.log10())).abs() < f64::EPSILON);
    }
}
