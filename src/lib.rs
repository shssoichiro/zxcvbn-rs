#![doc = include_str!("../README.md")]
#![recursion_limit = "128"]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

#[macro_use]
#[cfg(feature = "builder")]
extern crate derive_builder;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate quick_error;

#[cfg(feature = "ser")]
extern crate serde;
#[cfg(feature = "ser")]
#[macro_use]
extern crate serde_derive;
use std::time::Duration;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub use crate::matching::Match;

mod adjacency_graphs;
pub mod feedback;
mod frequency_lists;
/// Defines structures for matches found in a password
pub mod matching;
mod scoring;
pub mod time_estimates;

/// Contains the results of an entropy calculation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct Entropy {
    /// Estimated guesses needed to crack the password
    guesses: u64,
    /// Order of magnitude of `guesses`
    guesses_log10: f64,
    /// List of back-of-the-envelope crack time estimations based on a few scenarios.
    crack_times: time_estimates::CrackTimes,
    /// Overall strength score from 0-4.
    /// Any score less than 3 should be considered too weak.
    score: u8,
    /// Verbal feedback to help choose better passwords. Set when `score` <= 2.
    feedback: Option<feedback::Feedback>,
    /// The list of patterns the guess calculation was based on
    sequence: Vec<Match>,
    /// How long it took to calculate the answer.
    calc_time: Duration,
}

impl Entropy {
    /// The estimated number of guesses needed to crack the password.
    pub fn guesses(&self) -> u64 {
        self.guesses
    }

    /// The order of magnitude of `guesses`.
    pub fn guesses_log10(&self) -> f64 {
        self.guesses_log10
    }

    /// List of back-of-the-envelope crack time estimations based on a few scenarios.
    pub fn crack_times(&self) -> time_estimates::CrackTimes {
        self.crack_times
    }

    /// Overall strength score from 0-4.
    /// Any score less than 3 should be considered too weak.
    pub fn score(&self) -> u8 {
        self.score
    }

    /// Feedback to help choose better passwords. Set when `score` <= 2.
    pub fn feedback(&self) -> &Option<feedback::Feedback> {
        &self.feedback
    }

    /// The list of patterns the guess calculation was based on
    pub fn sequence(&self) -> &[Match] {
        &self.sequence
    }

    /// How long it took to calculate the answer.
    pub fn calculation_time(&self) -> Duration {
        self.calc_time
    }
}

quick_error! {
    #[derive(Debug, Clone, Copy)]
    /// Potential errors that may be returned from `zxcvbn`
    pub enum ZxcvbnError {
        /// Indicates that a blank password was passed in to `zxcvbn`
        BlankPassword {
            display("Zxcvbn cannot evaluate a blank password")
        }
        /// Indicates an error converting Duration to/from the standard library implementation
        DurationOutOfRange {
            display("Zxcvbn calculation time created a duration out of range")
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn duration_since_epoch() -> Result<Duration, ZxcvbnError> {
    match js_sys::Date::new_0().get_time() as u64 {
        u64::MIN | u64::MAX => Err(ZxcvbnError::DurationOutOfRange),
        millis => Ok(Duration::from_millis(millis)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn duration_since_epoch() -> Result<Duration, ZxcvbnError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| ZxcvbnError::DurationOutOfRange)
}

/// Takes a password string and optionally a list of user-supplied inputs
/// (e.g. username, email, first name) and calculates the strength of the password
/// based on entropy, using a number of different factors.
pub fn zxcvbn(password: &str, user_inputs: &[&str]) -> Result<Entropy, ZxcvbnError> {
    if password.is_empty() {
        return Err(ZxcvbnError::BlankPassword);
    }

    let start_time = duration_since_epoch()?;

    // Only evaluate the first 100 characters of the input.
    // This prevents potential DoS attacks from sending extremely long input strings.
    let password = password.chars().take(100).collect::<String>();

    let sanitized_inputs = user_inputs
        .iter()
        .enumerate()
        .map(|(i, x)| (x.to_lowercase(), i + 1))
        .collect();

    let matches = matching::omnimatch(&password, &sanitized_inputs);
    let result = scoring::most_guessable_match_sequence(&password, &matches, false);
    let calc_time = duration_since_epoch()? - start_time;
    let (crack_times, score) = time_estimates::estimate_attack_times(result.guesses);
    let feedback = feedback::get_feedback(score, &result.sequence);

    Ok(Entropy {
        guesses: result.guesses,
        guesses_log10: result.guesses_log10,
        crack_times,
        score,
        feedback,
        sequence: result.sequence,
        calc_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    quickcheck! {
        fn test_zxcvbn_doesnt_panic(password: String, user_inputs: Vec<String>) -> TestResult {
            let inputs = user_inputs.iter().map(|s| s.as_ref()).collect::<Vec<&str>>();
            zxcvbn(&password, &inputs).ok();
            TestResult::from_bool(true)
        }

        #[cfg(feature = "ser")]
        fn test_zxcvbn_serialisation_doesnt_panic(password: String, user_inputs: Vec<String>) -> TestResult {
            let inputs = user_inputs.iter().map(|s| s.as_ref()).collect::<Vec<&str>>();
            serde_json::to_string(&zxcvbn(&password, &inputs).ok()).ok();
            TestResult::from_bool(true)
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn() {
        let password = "r0sebudmaelstrom11/20/91aaaa";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.guesses_log10 as u16, 14);
        assert_eq!(entropy.score, 4);
        assert!(!entropy.sequence.is_empty());
        assert!(entropy.feedback.is_none());
        assert!(entropy.calc_time.as_nanos() > 0);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn_unicode() {
        let password = "𐰊𐰂𐰄𐰀𐰁";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.score, 1);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_zxcvbn_unicode_2() {
        let password = "r0sebudmaelstrom丂/20/91aaaa";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.score, 4);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_13() {
        let password = "Imaginative-Say-Shoulder-Dish-0";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.score, 4);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_15_example_1() {
        let password = "TestMeNow!";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.guesses, 372_010_000);
        assert!((entropy.guesses_log10 - 8.57055461430783).abs() < f64::EPSILON);
        assert_eq!(entropy.score, 3);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_issue_15_example_2() {
        let password = "hey<123";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.guesses, 1_010_000);
        assert!((entropy.guesses_log10 - 6.004321373782642).abs() < f64::EPSILON);
        assert_eq!(entropy.score, 2);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_overflow_safety() {
        let password = "!QASW@#EDFR$%TGHY^&UJKI*(OL";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.guesses, u64::max_value());
        assert_eq!(entropy.score, 4);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_unicode_mb() {
        let password = "08märz2010";
        let entropy = zxcvbn(password, &[]).unwrap();
        assert_eq!(entropy.guesses, 100010000);
        assert_eq!(entropy.score, 3);
    }
}
