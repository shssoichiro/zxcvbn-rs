use crate::frequency_lists::DictionaryType;
use crate::matching::Match;
use std::collections::HashMap;

/// Pattern type used to detect a match
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "ser", derive(Serialize))]
#[cfg_attr(feature = "ser", serde(tag = "pattern"))]
#[cfg_attr(feature = "ser", serde(rename_all = "lowercase"))]
pub enum MatchPattern {
    /// A match based on a word in a dictionary
    Dictionary(DictionaryPattern),
    /// A match based on keys being close to one another on the keyboard
    Spatial(SpatialPattern),
    /// A match based on repeating patterns
    Repeat(RepeatPattern),
    /// A match based on sequences of characters, e.g. "abcd"
    Sequence(SequencePattern),
    /// A match based on one of the regex patterns used in zxcvbn.
    Regex(RegexPattern),
    /// A match based on date patterns
    Date(DatePattern),
    /// A match based on bruteforce attempting to guess a password
    BruteForce,
}

impl MatchPattern {
    #[cfg(test)]
    pub(crate) fn variant(&self) -> &str {
        match *self {
            MatchPattern::Dictionary(_) => "dictionary",
            MatchPattern::Spatial(_) => "spatial",
            MatchPattern::Repeat(_) => "repeat",
            MatchPattern::Sequence(_) => "sequence",
            MatchPattern::Regex(_) => "regex",
            MatchPattern::Date(_) => "date",
            MatchPattern::BruteForce => "bruteforce",
        }
    }
}

impl Default for MatchPattern {
    fn default() -> Self {
        MatchPattern::BruteForce
    }
}

/// A match based on a word in a dictionary
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct DictionaryPattern {
    /// Word that has been found in a dictionary.
    pub matched_word: String,
    /// Rank of the the word found in a dictionary.
    pub rank: usize,
    /// Name of the dictionary in which a word has been found.
    pub dictionary_name: DictionaryType,
    /// Whether a reversed word has been found in a dictionary.
    pub reversed: bool,
    /// Whether a l33t-substituted word has been found in a dictionary.
    pub l33t: bool,
    /// Substitutions used for the match.
    pub sub: Option<HashMap<char, char>>,
    /// String for displaying the substitutions used for the match.
    pub sub_display: Option<String>,
    /// Number of variations of the matched dictionary word.
    pub uppercase_variations: u64,
    /// Number of variations of the matched dictionary word.
    pub l33t_variations: u64,
    /// Estimated number of tries for guessing the dictionary word.
    pub base_guesses: u64,
}

/// A match based on keys being close to one another on the keyboard
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct SpatialPattern {
    /// Name of the graph for which a spatial match has been found.
    pub graph: String,
    /// Number of turns in the matched spatial pattern.
    pub turns: usize,
    /// Number of shifts in the matched spatial pattern.
    pub shifted_count: usize,
}

/// A match based on repeating patterns
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct RepeatPattern {
    /// Base token that repeats in the matched pattern.
    pub base_token: String,
    /// Matches for the repeating token.
    pub base_matches: Vec<Match>,
    /// Estimated number of tries for guessing the repeating token.
    pub base_guesses: u64,
    /// Number of repetitions in the matched pattern.
    pub repeat_count: usize,
}

/// A match based on sequences of characters, e.g. "abcd"
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct SequencePattern {
    /// Name of the sequence that was matched.
    pub sequence_name: &'static str,
    /// Size of the sequence that was matched.
    pub sequence_space: u8,
    /// Whether the matched sequence is ascending.
    pub ascending: bool,
}

/// A match based on one of the regex patterns used in zxcvbn.
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct RegexPattern {
    /// Name of the regular expression that was matched.
    pub regex_name: &'static str,
    /// Matches of the regular expression.
    pub regex_match: Vec<String>,
}

/// A match based on date patterns
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct DatePattern {
    /// Separator of a date that was matched.
    pub separator: String,
    /// Year that was matched.
    pub year: i32,
    /// Month that was matched.
    pub month: i8,
    /// Day that was matched.
    pub day: i8,
}
