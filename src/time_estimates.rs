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
//! let entropy = zxcvbn("password123", &[])?;
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

/// Back-of-the-envelope crack time estimations, in seconds, based on a few scenarios.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct CrackTimes {
    guesses: u64,
}

impl CrackTimes {
    /// Get the time needed to crack a password based on the amount of guesses needed.
    ///
    /// # Arguments
    /// * `guesses` - The number of guesses needed to crack a password.
    pub fn new(guesses: u64) -> Self {
        CrackTimes { guesses }
    }

    /// Get the amount of guesses needed to crack the password.
    pub fn guesses(self) -> u64 {
        self.guesses
    }

    /// Online attack on a service that rate-limits password attempts.
    pub fn online_throttling_100_per_hour(self) -> CrackTimeSeconds {
        CrackTimeSeconds::Integer(self.guesses.saturating_mul(36))
    }

    /// Online attack on a service that doesn't rate-limit,
    /// or where an attacker has outsmarted rate-limiting.
    pub fn online_no_throttling_10_per_second(self) -> CrackTimeSeconds {
        CrackTimeSeconds::Float(self.guesses as f64 / 10.00)
    }

    /// Offline attack, assumes multiple attackers.
    /// Proper user-unique salting, and a slow hash function
    /// such as bcrypt, scrypt, PBKDF2.
    pub fn offline_slow_hashing_1e4_per_second(self) -> CrackTimeSeconds {
        CrackTimeSeconds::Float(self.guesses as f64 / 10_000.00)
    }

    /// Offline attack with user-unique salting but a fast hash function
    /// such as SHA-1, SHA-256, or MD5. A wide range of reasonable numbers
    /// anywhere from one billion to one trillion guesses per second,
    /// depending on number of cores and machines, ballparking at 10 billion per second.
    pub fn offline_fast_hashing_1e10_per_second(self) -> CrackTimeSeconds {
        CrackTimeSeconds::Float(self.guesses as f64 / 10_000_000_000.00)
    }
}

/// Represents the time to crack a password.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "ser", derive(Serialize))]
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

pub(crate) fn estimate_attack_times(guesses: u64) -> (CrackTimes, u8) {
    (CrackTimes::new(guesses), calculate_score(guesses))
}

fn calculate_score(guesses: u64) -> u8 {
    const DELTA: u64 = 5;
    if guesses < 1_000 + DELTA {
        0
    } else if guesses < 1_000_000 + DELTA {
        1
    } else if guesses < 100_000_000 + DELTA {
        2
    } else if guesses < 10_000_000_000 + DELTA {
        3
    } else {
        4
    }
}
