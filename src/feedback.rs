//! Contains structs and methods related to generating feedback strings
//! for providing help for the user to generate stronger passwords.

use matching::Match;
use matching::patterns::*;

/// Verbal feedback to help choose better passwords
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
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
            suggestions: vec![
                "Use a few words, avoid common phrases.",
                "No need for symbols, digits, or uppercase letters.",
            ],
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
        MatchPattern::Dictionary(ref pattern) => {
            get_dictionary_match_feedback(cur_match, pattern, is_sole_match)
        }
        MatchPattern::Spatial(ref pattern) => Feedback {
            warning: Some(if pattern.turns == 1 {
                "Straight rows of keys are easy to guess."
            } else {
                "Short keyboard patterns are easy to guess."
            }),
            suggestions: vec!["Use a longer keyboard pattern with more turns."],
        },
        MatchPattern::Repeat(ref pattern) => Feedback {
            warning: Some(if pattern.base_token.len() == 1 {
                "Repeats like \"aaa\" are easy to guess."
            } else {
                "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\"."
            }),
            suggestions: vec!["Avoid repeated words and characters."],
        },
        MatchPattern::Sequence(_) => Feedback {
            warning: Some("Sequences like abc or 6543 are easy to guess."),
            suggestions: vec!["Avoid sequences."],
        },
        MatchPattern::Regex(ref pattern) => {
            if pattern.regex_name == "recent_year" {
                Feedback {
                    warning: Some("Recent years are easy to guess."),
                    suggestions: vec![
                        "Avoid recent years.",
                        "Avoid years that are associated with you.",
                    ],
                }
            } else {
                Feedback::default()
            }
        }
        MatchPattern::Date(_) => Feedback {
            warning: Some("Dates are often easy to guess."),
            suggestions: vec!["Avoid dates and years that are associated with you."],
        },
        _ => Feedback {
            warning: None,
            suggestions: vec![],
        },
    }
}

fn get_dictionary_match_feedback(
    cur_match: &Match,
    pattern: &DictionaryPattern,
    is_sole_match: bool,
) -> Feedback {
    let warning = match pattern.dictionary_name {
        "passwords" => Some(if is_sole_match && !pattern.l33t && !pattern.reversed {
            let rank = pattern.rank;
            if rank <= 10 {
                "This is a top-10 common password."
            } else if rank <= 100 {
                "This is a top-100 common password."
            } else {
                "This is a very common password."
            }
        } else {
            "This is similar to a commonly used password."
        }),
        "english" => {
            if is_sole_match {
                Some("A word by itself is easy to guess.")
            } else {
                None
            }
        }
        "surnames" | "female_names" | "male_names" => Some(if is_sole_match {
            "Names and surnames by themselves are easy to guess."
        } else {
            "Common names and surnames are easy to guess."
        }),
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

    if pattern.reversed && word.len() >= 4 {
        suggestions.push("Reversed words aren't much harder to guess.");
    }
    if pattern.l33t {
        suggestions.push("Predictable substitutions like '@' instead of 'a' don't help very much.");
    }

    Feedback {
        warning: warning,
        suggestions: suggestions,
    }
}
