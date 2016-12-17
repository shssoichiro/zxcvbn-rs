//! Contains structs and methods related to generating feedback strings
//! for providing help for the user to generate stronger passwords.

/// Verbal feedback to help choose better passwords
#[derive(Debug, Clone)]
pub struct Feedback {
    /// Explains what's wrong, e.g. "This is a top-10 common password". Not always set.
    pub warning: Option<String>,
    /// A possibly-empty list of suggestions to help choose a less guessable password.
    /// E.g. "Add another word or two".
    pub suggestions: Vec<String>,
}

#[doc(hidden)]
pub fn get_feedback(score: u8, sequence: &[String]) -> Option<Feedback> {
    if score >= 3 {
        return None;
    }

    unimplemented!()
}
