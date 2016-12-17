//! Contains structs and methods related to generating feedback strings
//! for providing help for the user to generate stronger passwords.

use super::matching::Match;

/// Verbal feedback to help choose better passwords
#[derive(Debug, Clone, Default)]
pub struct Feedback {
    /// Explains what's wrong, e.g. "This is a top-10 common password". Not always set.
    pub warning: Option<&'static str>,
    /// A possibly-empty list of suggestions to help choose a less guessable password.
    /// E.g. "Add another word or two".
    pub suggestions: Vec<&'static str>,
}

#[doc(hidden)]
pub fn get_feedback(score: u8, sequence: &[Match]) -> Option<Feedback> {
    if sequence.is_empty() {
        // default feedback
        return Some(Feedback {
            warning: None,
            suggestions: vec!["Use a few words, avoid common phrases.",
                              "No need for symbols, digits, or uppercase letters."],
        });
    }
    if score >= 3 {
        return None;
    }

    let longest_match = sequence.iter().max_by_key(|x| x.token.len()).unwrap();
    let mut feedback = get_match_feedback(longest_match, sequence.len() == 1);
    let extra_feedback = "Add another word or two. Uncommon words are better.";

    feedback.suggestions.insert(0, extra_feedback);
    Some(feedback)
}

fn get_match_feedback(cur_match: &Match, is_sole_match: bool) -> Feedback {
    match cur_match.pattern {
        "dictionary" => get_dictionary_match_feedback(cur_match, is_sole_match),
        "spatial" => {
            Feedback {
                warning: Some(if cur_match.turns == Some(1) {
                    "Straight rows of keys are easy to guess."
                } else {
                    "Short keyboard patterns are easy to guess."
                }),
                suggestions: vec!["Use a longer keyboard pattern with more turns."],
            }
        }
        "repeat" => {
            let base_token = cur_match.base_token.as_ref().unwrap();
            Feedback {
                warning: Some(if base_token.len() == 1 {
                    "Repeats like \"aaa\" are easy to guess."
                } else {
                    "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\"."
                }),
                suggestions: vec!["Avoid repeated words and characters."],
            }
        }
        "sequence" => {
            Feedback {
                warning: Some("Sequences like abc or 6543 are easy to guess."),
                suggestions: vec!["Avoid sequences."],
            }
        }
        "regex" => {
            if cur_match.regex_name == Some("recent_year") {
                Feedback {
                    warning: Some("Recent years are easy to guess."),
                    suggestions: vec!["Avoid recent years.",
                                      "Avoid years that are associated with you."],
                }
            } else {
                Feedback::default()
            }
        }
        "date" => {
            Feedback {
                warning: Some("Dates are often easy to guess."),
                suggestions: vec!["Avoid dates and years that are associated with you."],
            }
        }
        _ => unreachable!(),
    }
}

fn get_dictionary_match_feedback(cur_match: &Match, is_sole_match: bool) -> Feedback {
    let warning = match cur_match.dictionary_name {
        Some("passwords") => {
            Some(if is_sole_match && !cur_match.l33t && !cur_match.reversed {
                let rank = cur_match.rank.unwrap();
                if rank <= 10 {
                    "This is a top-10 common password."
                } else if rank <= 100 {
                    "This is a top-100 common password."
                } else {
                    "This is a very common password."
                }
            } else {
                "This is similar to a commonly used password."
            })
        }
        Some("english") => {
            if is_sole_match {
                Some("A word by itself is easy to guess.")
            } else {
                None
            }
        }
        Some("surnames") |
        Some("female_names") |
        Some("male_names") => {
            Some(if is_sole_match {
                "Names and surnames by themselves are easy to guess."
            } else {
                "Common names and surnames are easy to guess."
            })
        }
        _ => None,
    };

    let mut suggestions = Vec::new();
    let word = &cur_match.token;
    if word.is_empty() {
        return Feedback::default();
    }

    if word.chars().next().unwrap().is_uppercase() {
        suggestions.push("Capitalization doesn't help very much.");
    } else if word.chars().all(char::is_uppercase) {
        suggestions.push("All-uppercase is almost as easy to guess as all-lowercase.");
    }

    if cur_match.reversed && word.len() >= 4 {
        suggestions.push("Reversed words aren't much harder to guess.");
    }
    if cur_match.l33t {
        suggestions.push("Predictable substitutions like '@' instead of 'a' don't help very much.");
    }

    Feedback {
        warning: warning,
        suggestions: suggestions,
    }
}
