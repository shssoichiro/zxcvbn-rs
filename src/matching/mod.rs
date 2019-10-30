/// Defines potential patterns used to match against a password
pub mod patterns;

use self::patterns::*;
use crate::frequency_lists::DictionaryType;
use fancy_regex::Regex as FancyRegex;
use itertools::Itertools;
use regex::Regex;
use std::collections::HashMap;

/// A match of a predictable pattern in the password.
#[derive(Debug, Clone, PartialEq, Default, Builder)]
#[builder(default)]
#[cfg_attr(feature = "ser", derive(Serialize))]
pub struct Match {
    /// Beginning of the match.
    pub i: usize,
    /// End of the match.
    pub j: usize,
    /// Token that has been matched.
    pub token: String,
    /// Pattern type and details used to detect this match.
    #[cfg_attr(feature = "ser", serde(flatten))]
    pub pattern: MatchPattern,
    /// Estimated number of tries for guessing the match.
    pub guesses: Option<u64>,
}

impl Match {
    /// Get the range of the index of the chars that are included in the match.
    pub fn range_inclusive(&self) -> std::ops::RangeInclusive<usize> {
        self.i..=self.j
    }
}

#[allow(clippy::implicit_hasher)]
pub(crate) fn omnimatch(password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match> {
    let mut matches: Vec<Match> = MATCHERS
        .iter()
        .flat_map(|x| x.get_matches(password, user_inputs))
        .collect();
    matches.sort_unstable_by(|a, b| {
        use std::cmp::Ordering;
        let range1 = a.range_inclusive();
        let range2 = b.range_inclusive();
        match range1.start().cmp(range2.start()) {
            Ordering::Equal => range1.end().cmp(range2.end()),
            other => other,
        }
    });
    matches
}

lazy_static! {
    static ref L33T_TABLE: HashMap<char, Vec<char>> = {
        let mut table = HashMap::with_capacity(12);
        table.insert('a', vec!['4', '@']);
        table.insert('b', vec!['8']);
        table.insert('c', vec!['(', '{', '[', '<']);
        table.insert('e', vec!['3']);
        table.insert('g', vec!['6', '9']);
        table.insert('i', vec!['1', '!', '|']);
        table.insert('l', vec!['1', '|', '7']);
        table.insert('o', vec!['0']);
        table.insert('s', vec!['$', '5']);
        table.insert('t', vec!['+', '7']);
        table.insert('x', vec!['%']);
        table.insert('z', vec!['2']);
        table
    };
    static ref GRAPHS: HashMap<&'static str, &'static HashMap<char, Vec<Option<&'static str>>>> = {
        let mut table = HashMap::with_capacity(4);
        table.insert("qwerty", &*super::adjacency_graphs::QWERTY);
        table.insert("dvorak", &*super::adjacency_graphs::DVORAK);
        table.insert("keypad", &*super::adjacency_graphs::KEYPAD);
        table.insert("mac_keypad", &*super::adjacency_graphs::MAC_KEYPAD);
        table
    };
}

trait Matcher: Send + Sync {
    fn get_matches(&self, password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match>;
}

lazy_static! {
    static ref MATCHERS: [Box<dyn Matcher>; 8] = [
        Box::new(DictionaryMatch {}),
        Box::new(ReverseDictionaryMatch {}),
        Box::new(L33tMatch {}),
        Box::new(SpatialMatch {}),
        Box::new(RepeatMatch {}),
        Box::new(SequenceMatch {}),
        Box::new(RegexMatch {}),
        Box::new(DateMatch {}),
    ];
}

struct DictionaryMatch {}

impl Matcher for DictionaryMatch {
    fn get_matches(&self, password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        fn do_trials(
            matches: &mut Vec<Match>,
            password: &str,
            dictionary_name: DictionaryType,
            ranked_dict: &HashMap<&str, usize>,
        ) {
            let len = password.chars().count();
            let password_lower = password.to_lowercase();
            for i in 0..len {
                for j in i..len {
                    let word = password_lower
                        .chars()
                        .take(j + 1)
                        .skip(i)
                        .collect::<String>();
                    if let Some(rank) = ranked_dict.get(&word.as_str()).cloned() {
                        let pattern = MatchPattern::Dictionary(
                            DictionaryPatternBuilder::default()
                                .matched_word(word)
                                .rank(rank)
                                .dictionary_name(dictionary_name)
                                .build()
                                .unwrap(),
                        );
                        matches.push(
                            MatchBuilder::default()
                                .pattern(pattern)
                                .i(i)
                                .j(j)
                                .token(password.chars().take(j + 1).skip(i).collect())
                                .build()
                                .unwrap(),
                        );
                    }
                }
            }
        }

        let mut matches = Vec::new();

        for (dictionary_name, ranked_dict) in super::frequency_lists::RANKED_DICTIONARIES.iter() {
            do_trials(&mut matches, password, *dictionary_name, ranked_dict);
        }
        do_trials(
            &mut matches,
            password,
            DictionaryType::UserInputs,
            &user_inputs.iter().map(|(x, &i)| (x.as_str(), i)).collect(),
        );

        matches
    }
}

struct ReverseDictionaryMatch {}

impl Matcher for ReverseDictionaryMatch {
    fn get_matches(&self, password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        let reversed_password = password.chars().rev().collect::<String>();
        (DictionaryMatch {})
            .get_matches(&reversed_password, user_inputs)
            .into_iter()
            .map(|mut m| {
                // Reverse token back
                m.token = m.token.chars().rev().collect();
                if let MatchPattern::Dictionary(ref mut pattern) = m.pattern {
                    pattern.reversed = true;
                }
                let old_i = m.i;
                m.i = password.chars().count() - 1 - m.j;
                m.j = password.chars().count() - 1 - old_i;
                m
            })
            .collect()
    }
}

struct L33tMatch {}

impl Matcher for L33tMatch {
    fn get_matches(&self, password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        let mut matches = Vec::new();
        for sub in enumerate_l33t_replacements(&relevant_l33t_subtable(password)) {
            if sub.is_empty() {
                break;
            }
            let subbed_password = translate(password, &sub);
            for mut m4tch in (DictionaryMatch {}).get_matches(&subbed_password, user_inputs) {
                let token = password
                    .chars()
                    .take(m4tch.j + 1)
                    .skip(m4tch.i)
                    .collect::<String>();
                {
                    let pattern = if let MatchPattern::Dictionary(ref mut pattern) = m4tch.pattern {
                        pattern
                    } else {
                        unreachable!()
                    };
                    if token.to_lowercase() == pattern.matched_word {
                        // Only return the matches that contain an actual substitution
                        continue;
                    }
                    let match_sub: HashMap<char, char> = sub
                        .clone()
                        .into_iter()
                        .filter(|&(subbed_chr, _)| token.contains(subbed_chr))
                        .collect();
                    m4tch.token = token;
                    pattern.l33t = true;
                    pattern.sub_display = Some(
                        match_sub
                            .iter()
                            .map(|(k, v)| format!("{} -> {}", k, v))
                            .join(", "),
                    );
                    pattern.sub = Some(match_sub);
                }
                matches.push(m4tch);
            }
        }
        matches
            .into_iter()
            .filter(|x| !x.token.is_empty())
            .collect()
    }
}

fn translate(string: &str, chr_map: &HashMap<char, char>) -> String {
    string
        .chars()
        .map(|c| *chr_map.get(&c).unwrap_or(&c))
        .collect()
}

fn relevant_l33t_subtable(password: &str) -> HashMap<char, Vec<char>> {
    let password_chars: Vec<char> = password.chars().collect();
    let mut subtable: HashMap<char, Vec<char>> = HashMap::new();
    for (letter, subs) in L33T_TABLE.iter() {
        let relevant_subs: Vec<char> = subs
            .iter()
            .filter(|&x| password_chars.contains(x))
            .cloned()
            .collect();
        if !relevant_subs.is_empty() {
            subtable.insert(*letter, relevant_subs);
        }
    }
    subtable
}

fn enumerate_l33t_replacements(table: &HashMap<char, Vec<char>>) -> Vec<HashMap<char, char>> {
    /// Recursive function that does the work
    fn helper(
        table: &HashMap<char, Vec<char>>,
        subs: Vec<Vec<(char, char)>>,
        remaining_keys: &[char],
    ) -> Vec<Vec<(char, char)>> {
        if remaining_keys.is_empty() {
            return subs;
        }
        let (first_key, rest_keys) = remaining_keys.split_first().unwrap();
        let mut next_subs: Vec<Vec<(char, char)>> = Vec::new();
        for l33t_chr in &table[first_key] {
            for sub in &subs {
                let mut dup_l33t_index = None;
                for (i, item) in sub.iter().enumerate() {
                    if item.0 == *l33t_chr {
                        dup_l33t_index = Some(i);
                        break;
                    }
                }
                if let Some(idx) = dup_l33t_index {
                    let mut sub_alternative = sub.clone();
                    sub_alternative.remove(idx);
                    sub_alternative.push((*l33t_chr, *first_key));
                    next_subs.push(sub.clone());
                    next_subs.push(sub_alternative);
                } else {
                    let mut sub_extension = sub.clone();
                    sub_extension.push((*l33t_chr, *first_key));
                    next_subs.push(sub_extension);
                }
            }
        }
        helper(
            table,
            next_subs
                .into_iter()
                .map(|x| x.iter().unique().cloned().collect())
                .collect(),
            rest_keys,
        )
    }

    helper(
        table,
        vec![vec![]],
        table.keys().cloned().collect::<Vec<char>>().as_slice(),
    )
    .into_iter()
    .map(|sub| sub.into_iter().collect::<HashMap<char, char>>())
    .collect()
}

struct SpatialMatch {}

impl Matcher for SpatialMatch {
    fn get_matches(&self, password: &str, _user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        GRAPHS
            .iter()
            .flat_map(|(graph_name, graph)| spatial_match_helper(password, graph, graph_name))
            .collect()
    }
}

const SHIFTED_CHARS: [char; 49] = [
    '[', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 'Q', 'W', 'E', 'R', 'T',
    'Y', 'U', 'I', 'O', 'P', '{', '}', '|', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"',
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', ']',
];

fn spatial_match_helper(
    password: &str,
    graph: &HashMap<char, Vec<Option<&str>>>,
    graph_name: &str,
) -> Vec<Match> {
    let mut matches = Vec::new();
    let password_len = password.chars().count();
    if password_len <= 2 {
        return matches;
    }
    let mut i = 0;
    while i < password_len - 1 {
        let mut j = i + 1;
        let mut last_direction = None;
        let mut turns = 0;
        let mut shifted_count = if ["qwerty", "dvorak"].contains(&graph_name)
            && SHIFTED_CHARS.contains(&password.chars().nth(i).unwrap())
        {
            1
        } else {
            0
        };
        loop {
            let prev_char = password.chars().nth(j - 1).unwrap();
            let mut found = false;
            let found_direction;
            let mut cur_direction = -1;
            let adjacents = graph.get(&prev_char).cloned().unwrap_or_else(|| vec![]);
            // consider growing pattern by one character if j hasn't gone over the edge.
            if j < password_len {
                let cur_char = password.chars().nth(j).unwrap();
                for adj in adjacents {
                    cur_direction += 1;
                    if let Some(adj) = adj {
                        if let Some(adj_position) = adj.find(cur_char) {
                            found = true;
                            found_direction = cur_direction;
                            if adj_position == 1 {
                                // index 1 in the adjacency means the key is shifted,
                                // 0 means unshifted: A vs a, % vs 5, etc.
                                // for example, 'q' is adjacent to the entry '2@'.
                                // @ is shifted w/ index 1, 2 is unshifted.
                                shifted_count += 1;
                            }
                            if last_direction != Some(found_direction) {
                                // adding a turn is correct even in the initial case when last_direction is null:
                                // every spatial pattern starts with a turn.
                                turns += 1;
                                last_direction = Some(found_direction);
                            }
                            break;
                        }
                    }
                }
            }
            if found {
                // if the current pattern continued, extend j and try to grow again
                j += 1;
            } else {
                // otherwise push the pattern discovered so far, if any...
                if j - i > 2 {
                    // Don't consider length 1 or 2 chains
                    let pattern = MatchPattern::Spatial(
                        SpatialPatternBuilder::default()
                            .graph(graph_name.to_string())
                            .turns(turns)
                            .shifted_count(shifted_count)
                            .build()
                            .unwrap(),
                    );
                    matches.push(
                        MatchBuilder::default()
                            .pattern(pattern)
                            .i(i)
                            .j(j - 1)
                            .token(password.chars().take(j).skip(i).collect())
                            .build()
                            .unwrap(),
                    );
                }
                i = j;
                break;
            }
        }
    }
    matches
}

struct RepeatMatch {}

impl Matcher for RepeatMatch {
    fn get_matches(&self, password: &str, user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        if !password.is_ascii() {
            // FancyRegex doesn't play well with multibyte UTF-8 characters and causes panics.
            // Skip this matcher until a workaround is found.
            return Vec::new();
        }

        lazy_static! {
            static ref GREEDY_REGEX: FancyRegex = FancyRegex::new(r"(.+)\1+").unwrap();
            static ref LAZY_REGEX: FancyRegex = FancyRegex::new(r"(.+?)\1+").unwrap();
            static ref LAZY_ANCHORED_REGEX: FancyRegex = FancyRegex::new(r"^(.+?)\1+$").unwrap();
        }

        let mut matches = Vec::new();
        let mut last_index = 0;
        while last_index < password.chars().count() {
            let token = password.chars().skip(last_index).collect::<String>();
            let greedy_matches = GREEDY_REGEX.captures(&token).unwrap();
            if greedy_matches.is_none() {
                break;
            }
            let lazy_matches = LAZY_REGEX.captures(&token).unwrap();
            let greedy_matches = greedy_matches.unwrap();
            let lazy_matches = lazy_matches.unwrap();
            let m4tch;
            let base_token = if greedy_matches.at(0).unwrap().chars().count()
                > lazy_matches.at(0).unwrap().chars().count()
            {
                // greedy beats lazy for 'aabaab'
                //   greedy: [aabaab, aab]
                //   lazy:   [aa,     a]
                m4tch = greedy_matches;
                // greedy's repeated string might itself be repeated, eg.
                // aabaab in aabaabaabaab.
                // run an anchored lazy match on greedy's repeated string
                // to find the shortest repeated string
                LAZY_ANCHORED_REGEX
                    .captures(m4tch.at(0).unwrap())
                    .unwrap()
                    .unwrap()
                    .at(1)
                    .unwrap()
                    .to_string()
            } else {
                // lazy beats greedy for 'aaaaa'
                //   greedy: [aaaa,  aa]
                //   lazy:   [aaaaa, a]
                m4tch = lazy_matches;
                m4tch.at(1).unwrap().to_string()
            };
            let (i, j) = (
                m4tch.pos(0).unwrap().0 + last_index,
                m4tch.pos(0).unwrap().1 + last_index - 1,
            );
            // recursively match and score the base string
            let base_analysis = super::scoring::most_guessable_match_sequence(
                &base_token,
                &omnimatch(&base_token, user_inputs),
                false,
            );
            let base_matches = base_analysis.sequence;
            let base_guesses = base_analysis.guesses;
            let pattern = MatchPattern::Repeat(
                RepeatPatternBuilder::default()
                    .repeat_count(m4tch.at(0).unwrap().chars().count() / base_token.chars().count())
                    .base_token(base_token)
                    .base_guesses(base_guesses)
                    .base_matches(base_matches)
                    .build()
                    .unwrap(),
            );
            matches.push(
                MatchBuilder::default()
                    .pattern(pattern)
                    .i(i)
                    .j(j)
                    .token(m4tch.at(0).unwrap().to_string())
                    .build()
                    .unwrap(),
            );
            last_index = j + 1;
        }
        matches
    }
}

const MAX_DELTA: i32 = 5;

/// Identifies sequences by looking for repeated differences in unicode codepoint.
/// this allows skipping, such as 9753, and also matches some extended unicode sequences
/// such as Greek and Cyrillic alphabets.
///
/// for example, consider the input 'abcdb975zy'
///
/// password: a   b   c   d   b    9   7   5   z   y
/// index:    0   1   2   3   4    5   6   7   8   9
/// delta:        1   1   1  -2  -41  -2  -2  69   1
///
/// expected result:
/// `[(i, j, delta), ...] = [(0, 3, 1), (5, 7, -2), (8, 9, 1)]`
struct SequenceMatch {}

impl Matcher for SequenceMatch {
    fn get_matches(&self, password: &str, _user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        fn update(i: usize, j: usize, delta: i32, password: &str, matches: &mut Vec<Match>) {
            let delta_abs = delta.abs();
            if (j - i > 1 || delta_abs == 1) && (0 < delta_abs && delta_abs <= MAX_DELTA) {
                let token = password.chars().take(j + 1).skip(i).collect::<String>();
                let first_chr = token.chars().next().unwrap();
                let (sequence_name, sequence_space) = if first_chr.is_lowercase() {
                    ("lower", 26)
                } else if first_chr.is_uppercase() {
                    ("upper", 26)
                } else if first_chr.is_digit(10) {
                    ("digits", 10)
                } else {
                    // conservatively stick with roman alphabet size.
                    // (this could be improved)
                    ("unicode", 26)
                };
                let pattern = MatchPattern::Sequence(
                    SequencePatternBuilder::default()
                        .sequence_name(sequence_name)
                        .sequence_space(sequence_space)
                        .ascending(delta > 0)
                        .build()
                        .unwrap(),
                );
                matches.push(
                    MatchBuilder::default()
                        .pattern(pattern)
                        .i(i)
                        .j(j)
                        .token(token)
                        .build()
                        .unwrap(),
                );
            }
        }

        let mut matches = Vec::new();

        let password_len = password.chars().count();
        if password_len <= 1 {
            return matches;
        }

        let mut i = 0;
        let mut j;
        let mut last_delta = 0;

        for k in 1..password_len {
            let delta = password.chars().nth(k).unwrap() as i32
                - password.chars().nth(k - 1).unwrap() as i32;
            if last_delta == 0 {
                last_delta = delta;
            }
            if last_delta == delta {
                continue;
            }
            j = k - 1;
            update(i, j, last_delta, password, &mut matches);
            i = j;
            last_delta = delta;
        }
        update(i, password_len - 1, last_delta, password, &mut matches);
        matches
    }
}

struct RegexMatch {}

impl Matcher for RegexMatch {
    fn get_matches(&self, password: &str, _user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        let mut matches = Vec::new();
        for (&name, regex) in REGEXES.iter() {
            for capture in regex.captures_iter(password) {
                let token = &capture[0];
                let pattern = MatchPattern::Regex(
                    RegexPatternBuilder::default()
                        .regex_name(name)
                        .regex_match(
                            capture
                                .iter()
                                .map(|x| x.unwrap().as_str().to_string())
                                .collect(),
                        )
                        .build()
                        .unwrap(),
                );
                matches.push(
                    MatchBuilder::default()
                        .pattern(pattern)
                        .token(token.to_string())
                        .i(capture.get(0).unwrap().start())
                        .j(capture.get(0).unwrap().end() - 1)
                        .build()
                        .unwrap(),
                );
            }
        }
        matches
    }
}

lazy_static! {
    static ref REGEXES: HashMap<&'static str, Regex> = {
        let mut table = HashMap::with_capacity(1);
        table.insert("recent_year", Regex::new(r"19\d\d|200\d|201\d").unwrap());
        table
    };
}

/// a "date" is recognized as:
///   any 3-tuple that starts or ends with a 2- or 4-digit year,
///   with 2 or 0 separator chars (1.1.91 or 1191),
///   maybe zero-padded (01-01-91 vs 1-1-91),
///   a month between 1 and 12,
///   a day between 1 and 31.
///
/// note: this isn't true date parsing in that "feb 31st" is allowed,
/// this doesn't check for leap years, etc.
///
/// recipe:
/// start with regex to find maybe-dates, then attempt to map the integers
/// onto month-day-year to filter the maybe-dates into dates.
/// finally, remove matches that are substrings of other matches to reduce noise.
///
/// note: instead of using a lazy or greedy regex to find many dates over the full string,
/// this uses a ^...$ regex against every substring of the password -- less performant but leads
/// to every possible date match.
struct DateMatch {}

impl Matcher for DateMatch {
    fn get_matches(&self, password: &str, _user_inputs: &HashMap<String, usize>) -> Vec<Match> {
        let mut matches = Vec::new();

        let password_len = password.chars().count();
        // dates without separators are between length 4 '1191' and 8 '11111991'
        if password_len < 4 {
            return matches;
        }
        for i in 0..(password_len - 3) {
            for j in (i + 3)..(i + 8) {
                if j >= password_len {
                    break;
                }
                let token = password.chars().take(j + 1).skip(i).collect::<String>();
                if !MAYBE_DATE_NO_SEPARATOR_REGEX.is_match(&token) {
                    continue;
                }
                let mut candidates = Vec::new();
                for &(k, l) in &DATE_SPLITS[&token.chars().count()] {
                    let ymd = map_ints_to_ymd(
                        token.chars().take(k).collect::<String>().parse().unwrap(),
                        token
                            .chars()
                            .take(l)
                            .skip(k)
                            .collect::<String>()
                            .parse()
                            .unwrap(),
                        token.chars().skip(l).collect::<String>().parse().unwrap(),
                    );
                    if ymd.is_some() {
                        candidates.push(ymd.unwrap());
                    }
                }
                if candidates.is_empty() {
                    continue;
                }
                // at this point: different possible ymd mappings for the same i,j substring.
                // match the candidate date that likely takes the fewest guesses: a year closest to 2000.
                // (scoring.REFERENCE_YEAR).
                //
                // ie, considering '111504', prefer 11-15-04 to 1-1-1504
                // (interpreting '04' as 2004)
                let metric = |candidate: &(i32, i8, i8)| {
                    (candidate.0 - *super::scoring::REFERENCE_YEAR).abs()
                };
                let best_candidate = candidates.iter().min_by_key(|&c| metric(c)).unwrap();
                let pattern = MatchPattern::Date(
                    DatePatternBuilder::default()
                        .separator(String::new())
                        .year(best_candidate.0)
                        .month(best_candidate.1)
                        .day(best_candidate.2)
                        .build()
                        .unwrap(),
                );
                matches.push(
                    MatchBuilder::default()
                        .pattern(pattern)
                        .token(token)
                        .i(i)
                        .j(j)
                        .build()
                        .unwrap(),
                );
            }
        }

        // dates with separators are between length 6 '1/1/91' and 10 '11/11/1991'
        if password_len >= 6 {
            for i in 0..(password_len - 5) {
                for j in (i + 5)..(i + 10) {
                    if j >= password_len {
                        break;
                    }
                    let token = password.chars().take(j + 1).skip(i).collect::<String>();
                    let (ymd, separator) = {
                        let captures = MAYBE_DATE_WITH_SEPARATOR_REGEX.captures(&token);
                        if captures.is_none() {
                            continue;
                        }
                        let captures = captures.unwrap();
                        if captures[2] != captures[4] {
                            // Original code uses regex backreferences, Rust doesn't support these.
                            // Need to manually test that group 2 and 4 are the same
                            continue;
                        }
                        (
                            map_ints_to_ymd(
                                captures[1].parse().unwrap(),
                                captures[3].parse().unwrap(),
                                captures[5].parse().unwrap(),
                            ),
                            captures[2].to_string(),
                        )
                    };
                    if let Some(ymd) = ymd {
                        let pattern = MatchPattern::Date(
                            DatePatternBuilder::default()
                                .separator(separator)
                                .year(ymd.0)
                                .month(ymd.1)
                                .day(ymd.2)
                                .build()
                                .unwrap(),
                        );
                        matches.push(
                            MatchBuilder::default()
                                .pattern(pattern)
                                .token(token)
                                .i(i)
                                .j(j)
                                .build()
                                .unwrap(),
                        );
                    }
                }
            }
        }

        matches
            .iter()
            .filter(|&x| !matches.iter().any(|y| *x != *y && y.i <= x.i && y.j >= x.j))
            .cloned()
            .collect()
    }
}

/// Takes three ints and returns them in a (y, m, d) tuple
fn map_ints_to_ymd(first: u16, second: u16, third: u16) -> Option<(i32, i8, i8)> {
    // given a 3-tuple, discard if:
    //   middle int is over 31 (for all ymd formats, years are never allowed in the middle)
    //   middle int is zero
    //   any int is over the max allowable year
    //   any int is over two digits but under the min allowable year
    //   2 ints are over 31, the max allowable day
    //   2 ints are zero
    //   all ints are over 12, the max allowable month
    if second > 31 || second == 0 {
        return None;
    }
    let mut over_12 = 0;
    let mut over_31 = 0;
    let mut zero = 0;
    for &i in &[first, second, third] {
        if 99 < i && i < DATE_MIN_YEAR || i > DATE_MAX_YEAR {
            return None;
        }
        if i > 31 {
            over_31 += 1;
        }
        if i > 12 {
            over_12 += 1;
        }
        if i == 0 {
            zero += 1;
        }
    }
    if over_31 >= 2 || over_12 == 3 || zero >= 2 {
        return None;
    }

    // first look for a four digit year: yyyy + daymonth or daymonth + yyyy
    let possible_year_splits = &[(third, first, second), (first, second, third)];
    for &(year, second, third) in possible_year_splits {
        if DATE_MIN_YEAR <= year && year <= DATE_MAX_YEAR {
            let dm = map_ints_to_md(second, third);
            if let Some(dm) = dm {
                return Some((i32::from(year), dm.0, dm.1));
            } else {
                // for a candidate that includes a four-digit year,
                // when the remaining ints don't match to a day and month,
                // it is not a date.
                return None;
            }
        }
    }

    // given no four-digit year, two digit years are the most flexible int to match, so
    // try to parse a day-month out of (first, second) or (second, first)
    for &(year, second, third) in possible_year_splits {
        let dm = map_ints_to_md(second, third);
        if let Some(dm) = dm {
            let year = two_to_four_digit_year(year);
            return Some((i32::from(year), dm.0, dm.1));
        }
    }

    None
}

/// Takes two ints and returns them in a (m, d) tuple
fn map_ints_to_md(first: u16, second: u16) -> Option<(i8, i8)> {
    for &(d, m) in &[(first, second), (second, first)] {
        if 1 <= d && d <= 31 && 1 <= m && m <= 12 {
            return Some((m as i8, d as i8));
        }
    }
    None
}

fn two_to_four_digit_year(year: u16) -> u16 {
    if year > 99 {
        year
    } else if year > 50 {
        // 87 -> 1987
        year + 1900
    } else {
        // 15 -> 2015
        year + 2000
    }
}

const DATE_MIN_YEAR: u16 = 1000;
const DATE_MAX_YEAR: u16 = 2050;
lazy_static! {
    static ref DATE_SPLITS: HashMap<usize, Vec<(usize, usize)>> = {
        let mut table = HashMap::with_capacity(5);
        // for length-4 strings, eg 1191 or 9111, two ways to split:
        // 1 1 91 (2nd split starts at index 1, 3rd at index 2)
        // 91 1 1
        table.insert(4, vec![(1, 2), (2, 3)]);
        // 1 11 91
        // 11 1 91
        table.insert(5, vec![(1, 3), (2, 3)]);
        // 1 1 1991
        // 11 11 91
        // 1991 1 1
        table.insert(6, vec![(1, 2), (2, 4), (4, 5)]);
        // 1 11 1991
        // 11 1 1991
        // 1991 1 11
        // 1991 11 1
        table.insert(7, vec![(1, 3), (2, 3), (4, 5), (4, 6)]);
        // 11 11 1991
        // 1991 11 11
        table.insert(8, vec![(2, 4), (4, 6)]);
        table
    };
    static ref MAYBE_DATE_NO_SEPARATOR_REGEX: Regex = Regex::new(r"^\d{4,8}$").unwrap();
    static ref MAYBE_DATE_WITH_SEPARATOR_REGEX: Regex = Regex::new(r"^(\d{1,4})([\s/\\_.-])(\d{1,2})([\s/\\_.-])(\d{1,4})$").unwrap();
}

#[cfg(test)]
mod tests {
    use crate::matching;
    use crate::matching::patterns::*;
    use crate::matching::Matcher;
    use std::collections::HashMap;

    #[test]
    fn test_translate() {
        let chr_map = vec![('a', 'A'), ('b', 'B')]
            .into_iter()
            .collect::<HashMap<char, char>>();
        let test_data = [
            ("a", chr_map.clone(), "A"),
            ("c", chr_map.clone(), "c"),
            ("ab", chr_map.clone(), "AB"),
            ("abc", chr_map.clone(), "ABc"),
            ("aa", chr_map.clone(), "AA"),
            ("abab", chr_map.clone(), "ABAB"),
            ("", chr_map.clone(), ""),
            ("", HashMap::new(), ""),
            ("abc", HashMap::new(), "abc"),
        ];
        for &(string, ref map, result) in &test_data {
            assert_eq!(matching::translate(string, map), result);
        }
    }

    #[test]
    fn test_dictionary_matches_words_that_contain_other_words() {
        let matches = (matching::DictionaryMatch {}).get_matches("motherboard", &HashMap::new());
        let patterns = ["mother", "motherboard", "board"];
        let ijs = [(0, 5), (0, 10), (6, 10)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
        }
    }

    #[test]
    fn test_dictionary_matches_multiple_words_when_they_overlap() {
        let matches = (matching::DictionaryMatch {}).get_matches("1abcdef12", &HashMap::new());
        let patterns = ["1abcdef", "abcdef12"];
        let ijs = [(0, 6), (1, 8)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
        }
    }

    #[test]
    fn test_dictionary_ignores_uppercasing() {
        let matches = (matching::DictionaryMatch {}).get_matches("BoaRdZ", &HashMap::new());
        let patterns = ["BoaRd"];
        let ijs = [(0, 4)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
        }
    }

    #[test]
    fn test_dictionary_identifies_words_surrounded_by_non_words() {
        let matches = (matching::DictionaryMatch {}).get_matches("asdf1234&*", &HashMap::new());
        let patterns = ["asdf", "asdf1234"];
        let ijs = [(0, 3), (0, 7)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
        }
    }

    #[test]
    fn test_dictionary_matches_user_inputs() {
        use crate::frequency_lists::DictionaryType;
        let user_inputs = [("bejeebus".to_string(), 1)]
            .iter()
            .cloned()
            .collect::<HashMap<String, usize>>();
        let matches = (matching::DictionaryMatch {}).get_matches("bejeebus", &user_inputs);
        let patterns = ["bejeebus"];
        let ijs = [(0, 7)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.dictionary_name, DictionaryType::UserInputs);
        }
    }

    #[test]
    fn test_dictionary_matches_against_reversed_words() {
        let matches = (matching::ReverseDictionaryMatch {}).get_matches("rehtom", &HashMap::new());
        let patterns = ["rehtom"];
        let ijs = [(0, 5)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.reversed, true);
        }
    }

    #[test]
    fn test_reduces_l33t_table_to_only_relevant_substitutions() {
        let test_data = vec![
            ("", HashMap::new()),
            ("a", HashMap::new()),
            ("4", vec![('a', vec!['4'])].into_iter().collect()),
            ("4@", vec![('a', vec!['4', '@'])].into_iter().collect()),
            (
                "4({60",
                vec![
                    ('a', vec!['4']),
                    ('c', vec!['(', '{']),
                    ('g', vec!['6']),
                    ('o', vec!['0']),
                ]
                .into_iter()
                .collect(),
            ),
        ];
        for (pw, expected) in test_data {
            assert_eq!(matching::relevant_l33t_subtable(pw), expected);
        }
    }

    #[test]
    fn test_enumerates_sets_of_l33t_subs_a_password_might_be_using() {
        let test_data = vec![
            (HashMap::new(), vec![HashMap::new()]),
            (
                vec![('a', vec!['@'])].into_iter().collect(),
                vec![vec![('@', 'a')].into_iter().collect()],
            ),
            (
                vec![('a', vec!['@', '4'])].into_iter().collect(),
                vec![
                    vec![('@', 'a')].into_iter().collect(),
                    vec![('4', 'a')].into_iter().collect(),
                ],
            ),
            (
                vec![('a', vec!['@', '4']), ('c', vec!['('])]
                    .into_iter()
                    .collect(),
                vec![
                    vec![('@', 'a'), ('(', 'c')].into_iter().collect(),
                    vec![('4', 'a'), ('(', 'c')].into_iter().collect(),
                ],
            ),
        ];
        for (table, subs) in test_data {
            assert_eq!(matching::enumerate_l33t_replacements(&table), subs);
        }
    }

    #[test]
    fn test_dictionary_matches_against_l33t_words() {
        let matches = (matching::L33tMatch {}).get_matches("m0th3r", &HashMap::new());
        let patterns = ["m0th3r"];
        let ijs = [(0, 5)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.l33t, true);
        }
    }

    #[test]
    fn test_dictionary_matches_overlapping_l33ted_words() {
        let matches = (matching::L33tMatch {}).get_matches("p@ssw0rd", &HashMap::new());
        let patterns = ["p@ss", "@ssw0rd"];
        let ijs = [(0, 3), (1, 7)];
        for (k, &pattern) in patterns.iter().enumerate() {
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            let (i, j) = ijs[k];
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Dictionary(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.l33t, true);
        }
    }

    #[test]
    fn test_doesnt_match_when_multiple_l33t_subs_needed_for_same_letter() {
        let matches = (matching::L33tMatch {}).get_matches("p4@ssword", &HashMap::new());
        assert!(!matches.iter().any(|m| &m.token == "p4@ssword"));
    }

    #[test]
    fn test_doesnt_match_single_character_l33ted_words() {
        let matches = (matching::L33tMatch {}).get_matches("4 ( @", &HashMap::new());
        assert!(matches.is_empty());
    }

    #[test]
    fn test_doesnt_match_1_and_2_char_spatial_patterns() {
        for password in &["", "/", "qw", "*/"] {
            let result = (matching::SpatialMatch {}).get_matches(password, &HashMap::new());
            assert!(!result.into_iter().any(|m| m.token == *password));
        }
    }

    #[test]
    fn test_matches_spatial_patterns_surrounded_by_non_spatial_patterns() {
        let password = "6tfGHJ";
        let m = (matching::SpatialMatch {})
            .get_matches(password, &HashMap::new())
            .into_iter()
            .find(|m| m.token == *password)
            .unwrap();
        let p = if let MatchPattern::Spatial(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.graph, "qwerty".to_string());
        assert_eq!(p.turns, 2);
        assert_eq!(p.shifted_count, 3);
    }

    #[test]
    fn test_matches_pattern_as_a_keyboard_pattern() {
        let test_data = vec![
            ("12345", "qwerty", 1, 0),
            ("@WSX", "qwerty", 1, 4),
            ("6tfGHJ", "qwerty", 2, 3),
            ("hGFd", "qwerty", 1, 2),
            ("/;p09876yhn", "qwerty", 3, 0),
            ("Xdr%", "qwerty", 1, 2),
            ("159-", "keypad", 1, 0),
            ("*84", "keypad", 1, 0),
            ("/8520", "keypad", 1, 0),
            ("369", "keypad", 1, 0),
            ("/963.", "mac_keypad", 1, 0),
            ("*-632.0214", "mac_keypad", 9, 0),
            ("aoEP%yIxkjq:", "dvorak", 4, 5),
            (";qoaOQ:Aoq;a", "dvorak", 11, 4),
        ];
        for (password, keyboard, turns, shifts) in test_data {
            let matches = (matching::SpatialMatch {}).get_matches(password, &HashMap::new());
            let m = matches
                .into_iter()
                .find(|m| {
                    if let MatchPattern::Spatial(ref p) = m.pattern {
                        if m.token == *password && p.graph == keyboard {
                            return true;
                        }
                    };
                    false
                })
                .unwrap();
            let p = if let MatchPattern::Spatial(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.turns, turns);
            assert_eq!(p.shifted_count, shifts);
        }
    }

    #[test]
    fn test_doesnt_match_len_1_sequences() {
        for &password in &["", "a", "1"] {
            assert_eq!(
                (matching::SequenceMatch {}).get_matches(password, &HashMap::new()),
                Vec::new()
            );
        }
    }

    #[test]
    fn test_matches_overlapping_sequences() {
        let password = "abcbabc";
        let matches = (matching::SequenceMatch {}).get_matches(password, &HashMap::new());
        for &(pattern, i, j, ascending) in &[
            ("abc", 0, 2, true),
            ("cba", 2, 4, false),
            ("abc", 4, 6, true),
        ] {
            let m = matches
                .iter()
                .find(|m| m.token == *pattern && m.i == i && m.j == j)
                .unwrap();
            let p = if let MatchPattern::Sequence(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.ascending, ascending);
        }
    }

    #[test]
    fn test_matches_embedded_sequence_patterns() {
        let password = "!jihg22";
        let matches = (matching::SequenceMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| &m.token == "jihg").unwrap();
        let p = if let MatchPattern::Sequence(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.sequence_name, "lower");
        assert_eq!(p.ascending, false);
    }

    #[test]
    fn test_matches_pattern_as_sequence() {
        let test_data = [
            ("ABC", "upper", true),
            ("CBA", "upper", false),
            ("PQR", "upper", true),
            ("RQP", "upper", false),
            ("XYZ", "upper", true),
            ("ZYX", "upper", false),
            ("abcd", "lower", true),
            ("dcba", "lower", false),
            ("jihg", "lower", false),
            ("wxyz", "lower", true),
            ("zxvt", "lower", false),
            ("0369", "digits", true),
            ("97531", "digits", false),
        ];
        for &(pattern, name, is_ascending) in &test_data {
            let matches = (matching::SequenceMatch {}).get_matches(pattern, &HashMap::new());
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            assert_eq!(m.i, 0);
            assert_eq!(m.j, pattern.len() - 1);
            let p = if let MatchPattern::Sequence(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.sequence_name, name);
            assert_eq!(p.ascending, is_ascending);
        }
    }

    #[test]
    fn test_doesnt_match_len_1_repeat_patterns() {
        for &password in &["", "#"] {
            assert_eq!(
                (matching::RepeatMatch {}).get_matches(password, &HashMap::new()),
                Vec::new()
            );
        }
    }

    #[test]
    fn test_matches_embedded_repeat_patterns() {
        let password = "y4@&&&&&u%7";
        let (i, j) = (3, 7);
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| &m.token == "&&&&&").unwrap();
        assert_eq!(m.i, i);
        assert_eq!(m.j, j);
        let p = if let MatchPattern::Repeat(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.base_token, "&".to_string());
    }

    #[test]
    fn test_repeats_with_base_character() {
        for len in 3..13 {
            for &chr in &['a', 'Z', '4', '&'] {
                let password = (0..len).map(|_| chr).collect::<String>();
                let matches = (matching::RepeatMatch {}).get_matches(&password, &HashMap::new());
                let m = matches
                    .iter()
                    .find(|m| {
                        if let MatchPattern::Repeat(ref p) = m.pattern {
                            if p.base_token == format!("{}", chr) {
                                return true;
                            }
                        };
                        false
                    })
                    .unwrap();
                assert_eq!(m.i, 0);
                assert_eq!(m.j, len - 1);
            }
        }
    }

    #[test]
    fn test_multiple_adjacent_repeats() {
        let password = "BBB1111aaaaa@@@@@@";
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let test_data = [
            ("BBB", 0, 2),
            ("1111", 3, 6),
            ("aaaaa", 7, 11),
            ("@@@@@@", 12, 17),
        ];
        for &(pattern, i, j) in &test_data {
            let m = matches.iter().find(|m| m.token == pattern).unwrap();
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Repeat(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.base_token, pattern[0..1].to_string());
        }
    }

    #[test]
    fn test_multiple_non_adjacent_repeats() {
        let password = "2818BBBbzsdf1111@*&@!aaaaaEUDA@@@@@@1729";
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let test_data = [
            ("BBB", 4, 6),
            ("1111", 12, 15),
            ("aaaaa", 21, 25),
            ("@@@@@@", 30, 35),
        ];
        for &(pattern, i, j) in &test_data {
            let m = matches.iter().find(|m| m.token == pattern).unwrap();
            assert_eq!(m.i, i);
            assert_eq!(m.j, j);
            let p = if let MatchPattern::Repeat(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.base_token, pattern[0..1].to_string());
        }
    }

    #[test]
    fn test_multiple_character_repeats() {
        let password = "abab";
        let (i, j) = (0, 3);
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| m.token == *password).unwrap();
        assert_eq!(m.i, i);
        assert_eq!(m.j, j);
        let p = if let MatchPattern::Repeat(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.base_token, "ab".to_string());
    }

    #[test]
    fn test_matches_longest_repeat() {
        let password = "aabaab";
        let (i, j) = (0, 5);
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| m.token == *password).unwrap();
        assert_eq!(m.i, i);
        assert_eq!(m.j, j);
        let p = if let MatchPattern::Repeat(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.base_token, "aab".to_string());
    }

    #[test]
    fn test_identifies_simplest_repeat() {
        let password = "abababab";
        let (i, j) = (0, 7);
        let matches = (matching::RepeatMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| m.token == *password).unwrap();
        assert_eq!(m.i, i);
        assert_eq!(m.j, j);
        let p = if let MatchPattern::Repeat(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.base_token, "ab".to_string());
    }

    #[test]
    fn test_regex_matching() {
        let test_data = [("1922", "recent_year"), ("2017", "recent_year")];
        for &(pattern, name) in &test_data {
            let matches = (matching::RegexMatch {}).get_matches(pattern, &HashMap::new());
            let m = matches.iter().find(|m| m.token == *pattern).unwrap();
            assert_eq!(m.i, 0);
            assert_eq!(m.j, pattern.len() - 1);
            let p = if let MatchPattern::Regex(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.regex_name, name);
        }
    }

    #[test]
    fn test_date_matching_with_various_separators() {
        let separators = ["", " ", "-", "/", "\\", "_", "."];
        for sep in &separators {
            let password = format!("13{}2{}1921", sep, sep);
            let matches = (matching::DateMatch {}).get_matches(&password, &HashMap::new());
            let m = matches.iter().find(|m| m.token == password).unwrap();
            assert_eq!(m.i, 0);
            assert_eq!(m.j, password.len() - 1);
            let p = if let MatchPattern::Date(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.year, 1921);
            assert_eq!(p.month, 2);
            assert_eq!(p.day, 13);
            assert_eq!(p.separator, sep.to_string());
        }
    }

    #[test]
    fn test_date_matches_year_closest_to_reference_year() {
        use chrono::{Datelike, Local};
        let password = format!("1115{}", Local::today().year() % 100);
        let matches = (matching::DateMatch {}).get_matches(&password, &HashMap::new());
        let m = matches.iter().find(|m| m.token == password).unwrap();
        assert_eq!(m.i, 0);
        assert_eq!(m.j, password.len() - 1);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, Local::today().year());
        assert_eq!(p.month, 11);
        assert_eq!(p.day, 15);
        assert_eq!(p.separator, "".to_string());
    }

    #[test]
    fn test_date_matches() {
        let test_data = [(1, 1, 1999), (11, 8, 2000), (9, 12, 2005), (22, 11, 1551)];
        for &(day, month, year) in &test_data {
            let password = format!("{}{}{}", year, month, day);
            let matches = (matching::DateMatch {}).get_matches(&password, &HashMap::new());
            let m = matches.iter().find(|m| m.token == password).unwrap();
            assert_eq!(m.i, 0);
            assert_eq!(m.j, password.len() - 1);
            let p = if let MatchPattern::Date(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.year, year);
            assert_eq!(p.separator, "".to_string());
        }
        for &(day, month, year) in &test_data {
            let password = format!("{}.{}.{}", year, month, day);
            let matches = (matching::DateMatch {}).get_matches(&password, &HashMap::new());
            let m = matches.iter().find(|m| m.token == password).unwrap();
            assert_eq!(m.i, 0);
            assert_eq!(m.j, password.len() - 1);
            let p = if let MatchPattern::Date(ref p) = m.pattern {
                p
            } else {
                panic!("Wrong match pattern")
            };
            assert_eq!(p.year, year);
            assert_eq!(p.separator, ".".to_string());
        }
    }

    #[test]
    fn test_matching_zero_padded_dates() {
        let password = "02/02/02";
        let matches = (matching::DateMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| m.token == password).unwrap();
        assert_eq!(m.i, 0);
        assert_eq!(m.j, password.len() - 1);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, 2002);
        assert_eq!(p.month, 2);
        assert_eq!(p.day, 2);
        assert_eq!(p.separator, "/".to_string());
    }

    #[test]
    fn test_matching_embedded_dates() {
        let password = "a1/1/91!";
        let matches = (matching::DateMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| &m.token == "1/1/91").unwrap();
        assert_eq!(m.i, 1);
        assert_eq!(m.j, password.len() - 2);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, 1991);
        assert_eq!(p.month, 1);
        assert_eq!(p.day, 1);
        assert_eq!(p.separator, "/".to_string());
    }

    #[test]
    fn test_matching_overlapping_dates() {
        let password = "12/20/1991.12.20";
        let matches = (matching::DateMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| &m.token == "12/20/1991").unwrap();
        assert_eq!(m.i, 0);
        assert_eq!(m.j, 9);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, 1991);
        assert_eq!(p.month, 12);
        assert_eq!(p.day, 20);
        assert_eq!(p.separator, "/".to_string());
        let m = matches.iter().find(|m| &m.token == "1991.12.20").unwrap();
        assert_eq!(m.i, 6);
        assert_eq!(m.j, password.len() - 1);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, 1991);
        assert_eq!(p.month, 12);
        assert_eq!(p.day, 20);
        assert_eq!(p.separator, ".".to_string());
    }

    #[test]
    fn test_matches_dates_padded_by_non_ambiguous_digits() {
        let password = "912/20/919";
        let matches = (matching::DateMatch {}).get_matches(password, &HashMap::new());
        let m = matches.iter().find(|m| &m.token == "12/20/91").unwrap();
        assert_eq!(m.i, 1);
        assert_eq!(m.j, password.len() - 2);
        let p = if let MatchPattern::Date(ref p) = m.pattern {
            p
        } else {
            panic!("Wrong match pattern")
        };
        assert_eq!(p.year, 1991);
        assert_eq!(p.month, 12);
        assert_eq!(p.day, 20);
        assert_eq!(p.separator, "/".to_string());
    }

    #[test]
    fn test_omnimatch() {
        assert_eq!(matching::omnimatch("", &HashMap::new()), Vec::new());
        let password = "r0sebudmaelstrom11/20/91aaaa";
        let expected = [
            ("dictionary", 0, 6),
            ("dictionary", 7, 15),
            ("date", 16, 23),
            ("repeat", 24, 27),
        ];
        let matches = matching::omnimatch(password, &HashMap::new());
        for &(pattern_name, i, j) in &expected {
            assert!(matches
                .iter()
                .any(|m| m.pattern.variant() == pattern_name && m.i == i && m.j == j));
        }
    }
}
