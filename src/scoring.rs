#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct GuessCalculation {
    /// Estimated guesses needed to crack the password
    pub guesses: u64,
    /// Order of magnitude of `guesses`
    pub guesses_log10: u16,
    /// Overall strength score from 0-4.
    pub score: u8,
    /// The list of patterns the guess calculation was based on
    pub sequence: Vec<String>,
}

#[doc(hidden)]
pub fn most_guessable_match_sequence(password: &str,
                                     matches: &[super::matching::Match])
                                     -> GuessCalculation {
    unimplemented!()
}
