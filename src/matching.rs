use itertools::Itertools;
use regex::Regex;
use std::collections::HashMap;

macro_attr! {
    #[derive(Debug, Clone, Default, PartialEq, Builder!)]
    pub struct Match {
        pub pattern: &'static str,
        pub i: usize,
        pub j: usize,
        pub token: String,
        pub matched_word: Option<String>,
        pub rank: Option<usize>,
        pub dictionary_name: Option<&'static str>,
        pub graph: Option<String>,
        pub reversed: bool,
        pub l33t: bool,
        pub sub: Option<HashMap<char, char>>,
        pub sub_display: Option<String>,
        pub turns: Option<usize>,
        pub shifted_count: Option<usize>,
        pub base_token: Option<String>,
        pub base_matches: Option<Vec<String>>,
        pub base_guesses: Option<u64>,
        pub repeat_count: Option<usize>,
        pub sequence_name: Option<&'static str>,
        pub sequence_space: Option<u8>,
        pub ascending: Option<bool>,
        pub regex_name: Option<&'static str>,
        pub separator: Option<String>,
        pub year: Option<i16>,
        pub month: Option<i8>,
        pub day: Option<i8>,
    }
}

impl Match {
    pub fn build(&mut self) -> Match {
        self.clone()
    }
}

#[doc(hidden)]
pub fn omnimatch(password: &str, user_inputs: &Option<HashMap<String, usize>>) -> Vec<Match> {
    MATCHERS.iter()
        .flat_map(|x| x.get_matches(password, user_inputs))
        .sorted_by(|a, b| Ord::cmp(&a.i, &b.i))
        .into_iter()
        .sorted_by(|a, b| Ord::cmp(&a.j, &b.j))
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
    static ref GRAPHS: HashMap<&'static str, HashMap<char, Vec<Option<&'static str>>>> = {
        let mut table = HashMap::with_capacity(4);
        table.insert("qwerty", super::adjacency_graphs::QWERTY.clone());
        table.insert("dvorak", super::adjacency_graphs::DVORAK.clone());
        table.insert("keypad", super::adjacency_graphs::KEYPAD.clone());
        table.insert("mac_keypad", super::adjacency_graphs::MAC_KEYPAD.clone());
        table
    };
}

trait Matcher: Sync {
    fn get_matches(&self,
                   password: &str,
                   user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match>;
}

lazy_static! {
    static ref MATCHERS: [Box<Matcher>; 8] = [
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
    fn get_matches(&self,
                   password: &str,
                   user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        fn do_trials(matches: &mut Vec<Match>,
                     password: &str,
                     dictionary_name: &'static str,
                     ranked_dict: &HashMap<&str, usize>) {
            let len = password.len();
            let password_lower = password.to_lowercase();
            for i in 0..(len + 1) {
                for j in 0..(len + 1) {
                    let word = &password_lower[i..j];
                    if let Some(rank) = ranked_dict.get(word) {
                        matches.push(Match::default()
                            .pattern("dictionary")
                            .i(i)
                            .j(j)
                            .token(password[i..j].to_string())
                            .matched_word(Some(word.to_string()))
                            .rank(Some(*rank))
                            .dictionary_name(Some(dictionary_name))
                            .build());
                    }
                }
            }
        }

        let mut matches = Vec::new();

        for (dictionary_name, ranked_dict) in super::frequency_lists::RANKED_DICTIONARIES.iter() {
            do_trials(&mut matches, password, dictionary_name, ranked_dict);
        }
        if let Some(ref inputs) = *user_inputs {
            do_trials(&mut matches,
                      password,
                      "user_inputs",
                      &inputs.iter().map(|(x, &i)| (x.as_str(), i)).collect());
        }

        matches
    }
}

struct ReverseDictionaryMatch {}

impl Matcher for ReverseDictionaryMatch {
    fn get_matches(&self,
                   password: &str,
                   user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        let reversed_password = password.chars().rev().collect::<String>();
        (DictionaryMatch {})
            .get_matches(&reversed_password, user_inputs)
            .into_iter()
            .map(|mut x| {
                // Reverse token back
                x.token = x.token.chars().rev().collect();
                x.reversed = true;
                x.i = password.len() - 1 - x.j;
                x.j = password.len() - 1 - x.i;
                x
            })
            .collect()
    }
}

struct L33tMatch {}

impl Matcher for L33tMatch {
    fn get_matches(&self,
                   password: &str,
                   user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        let mut matches = Vec::new();
        for sub in enumerate_l33t_replacements(&relevant_l33t_subtable(password)) {
            if sub.is_empty() {
                break;
            }
            let subbed_password = translate(password, &sub);
            for mut m4tch in (DictionaryMatch {}).get_matches(&subbed_password, user_inputs) {
                let token = &password[m4tch.i..m4tch.j];
                if Some(token.to_lowercase()) == m4tch.matched_word {
                    // Only return the matches that contain an actual substitution
                    continue;
                }
                let match_sub: HashMap<char, char> = sub.clone()
                    .into_iter()
                    .filter(|&(subbed_chr, _)| token.contains(subbed_chr))
                    .collect();
                m4tch.l33t = true;
                m4tch.token = token.to_string();
                m4tch.sub_display =
                    Some(match_sub.iter().map(|(k, v)| format!("{} -> {}", k, v)).collect());
                m4tch.sub = Some(match_sub);
                matches.push(m4tch);
            }
        }
        matches.into_iter().filter(|x| !x.token.is_empty()).collect()
    }
}

fn translate(string: &str, chr_map: &HashMap<char, char>) -> String {
    string.chars().map(|c| *chr_map.get(&c).unwrap_or(&c)).collect()
}

fn relevant_l33t_subtable(password: &str) -> HashMap<char, Vec<char>> {
    let password_chars: Vec<char> = password.chars().collect();
    let mut subtable: HashMap<char, Vec<char>> = HashMap::new();
    for (letter, subs) in L33T_TABLE.iter() {
        let relevant_subs: Vec<char> =
            subs.iter().filter(|&x| password_chars.contains(x)).cloned().collect();
        if !relevant_subs.is_empty() {
            subtable.insert(*letter, relevant_subs);
        }
    }
    subtable
}

fn enumerate_l33t_replacements(table: &HashMap<char, Vec<char>>) -> Vec<HashMap<char, char>> {
    /// Recursive function that does the work
    fn helper(table: &HashMap<char, Vec<char>>,
              subs: Vec<Vec<(char, char)>>,
              remaining_keys: &[char])
              -> Vec<Vec<(char, char)>> {
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
        helper(table,
               next_subs.into_iter().map(|x| x.iter().unique().cloned().collect()).collect(),
               rest_keys)
    }

    helper(table,
           vec![vec![]],
           table.keys().cloned().collect::<Vec<char>>().as_slice())
        .into_iter()
        .map(|sub| sub.into_iter().collect::<HashMap<char, char>>())
        .collect()
}

struct SpatialMatch {}

impl Matcher for SpatialMatch {
    fn get_matches(&self,
                   password: &str,
                   _user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        GRAPHS.iter()
            .flat_map(|(graph_name, graph)| spatial_match_helper(password, graph, graph_name))
            .collect()
    }
}

lazy_static! {
    static ref SHIFTED_REGEX: Regex = Regex::new("[~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?]").unwrap();
}

fn spatial_match_helper(password: &str,
                        graph: &HashMap<char, Vec<Option<&str>>>,
                        graph_name: &str)
                        -> Vec<Match> {
    let mut matches = Vec::new();
    let mut i = 0;
    while i < password.len() - 1 {
        let mut j = i + 1;
        let mut last_direction = None;
        let mut turns = 0;
        let mut shifted_count = if ["qwerty", "dvorak"].contains(&graph_name) &&
                                   SHIFTED_REGEX.is_match(&password[i..(i + 1)]) {
            1
        } else {
            0
        };
        loop {
            let prev_char = password[j - 1..j].chars().next().unwrap();
            let mut found = false;
            let found_direction;
            let mut cur_direction = -1;
            let adjacents = graph.get(&prev_char).cloned().unwrap_or_else(|| vec![]);
            // consider growing pattern by one character if j hasn't gone over the edge.
            if j < password.len() {
                let cur_char = password[j..(j + 1)].chars().next().unwrap();
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
                if j - 1 > 2 {
                    // Don't consider length 1 or 2 chains
                    matches.push(Match::default()
                        .pattern("spatial")
                        .i(i)
                        .j(j - 1)
                        .token(password[i..(j + 1)].to_string())
                        .graph(Some(graph_name.to_string()))
                        .turns(Some(turns))
                        .shifted_count(Some(shifted_count))
                        .build());
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
    fn get_matches(&self,
                   password: &str,
                   user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        let mut matches = Vec::new();
        let mut last_index = 0;
        while last_index < password.len() {
            let greedy_matches = GREEDY_REGEX.captures(&password[last_index..]);
            let lazy_matches = LAZY_REGEX.captures(&password[last_index..]);
            if greedy_matches.is_none() {
                break;
            }
            let greedy_matches = greedy_matches.unwrap();
            let lazy_matches = lazy_matches.unwrap();
            let m4tch;
            let base_token = if greedy_matches.len() > lazy_matches.len() {
                // greedy beats lazy for 'aabaab'
                //   greedy: [aabaab, aab]
                //   lazy:   [aa,     a]
                m4tch = greedy_matches;
                // greedy's repeated string might itself be repeated, eg.
                // aabaab in aabaabaabaab.
                // run an anchored lazy match on greedy's repeated string
                // to find the shortest repeated string
                LAZY_ANCHORED_REGEX.captures(&m4tch[1]).unwrap()[1].to_string()
            } else {
                // lazy beats greedy for 'aaaaa'
                //   greedy: [aaaa,  aa]
                //   lazy:   [aaaaa, a]
                m4tch = lazy_matches;
                m4tch[1].to_string()
            };
            let (i, j) = (m4tch.pos(0).unwrap().0, m4tch.pos(0).unwrap().0 + m4tch[0].len() - 1);
            // recursively match and score the base string
            let base_analysis =
                super::scoring::most_guessable_match_sequence(&base_token,
                                                              &omnimatch(&base_token, user_inputs));
            let base_matches = base_analysis.sequence;
            let base_guesses = base_analysis.guesses;
            matches.push(Match::default()
                .pattern("repeat")
                .i(i)
                .j(j)
                .token(m4tch[0].to_string())
                .repeat_count(m4tch[0].len() / base_token.len())
                .base_token(base_token)
                .base_guesses(base_guesses)
                .base_matches(base_matches)
                .build());
            last_index = j + 1;
        }
        matches
    }
}

lazy_static! {
    static ref GREEDY_REGEX: Regex = Regex::new(r"(.+)\1+").unwrap();
    static ref LAZY_REGEX: Regex = Regex::new(r"(.+?)\1+").unwrap();
    static ref LAZY_ANCHORED_REGEX: Regex = Regex::new(r"^(.+?)\1+$").unwrap();
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
    fn get_matches(&self,
                   password: &str,
                   _user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        fn update(i: usize, j: usize, delta: i32, password: &str, matches: &mut Vec<Match>) {
            let delta_abs = delta.abs();
            if (j - i > 1 || delta_abs == 1) && (0 < delta_abs && delta_abs <= MAX_DELTA) {
                let token = &password[i..j];
                let sequence_name;
                let sequence_space;
                if token.chars().any(char::is_lowercase) {
                    sequence_name = "lower";
                    sequence_space = 26;
                } else if token.chars().any(char::is_uppercase) {
                    sequence_name = "upper";
                    sequence_space = 26;
                } else if token.chars().any(|c| c.is_digit(10)) {
                    sequence_name = "digits";
                    sequence_space = 10;
                } else {
                    // conservatively stick with roman alphabet size.
                    // (this could be improved)
                    sequence_name = "unicode";
                    sequence_space = 26;
                }
                matches.push(Match::default()
                    .pattern("sequence")
                    .i(i)
                    .j(j)
                    .token(token.to_string())
                    .sequence_name(sequence_name)
                    .sequence_space(sequence_space)
                    .ascending(Some(delta > 0))
                    .build());
            }
        }

        let mut matches = Vec::new();

        if password.len() <= 1 {
            return matches;
        }

        let mut i = 0;
        let mut j;
        let mut last_delta = 0;

        for k in 1..(password.len() + 1) {
            let delta = password[k..(k + 1)].chars().next().unwrap() as i32 -
                        password[(k - 1)..k].chars().next().unwrap() as i32;
            if last_delta == 0 {
                last_delta = delta;
                continue;
            }
            j = k - 1;
            update(i, j, last_delta, password, &mut matches);
            i = j;
            last_delta = delta;
        }
        update(i, password.len() - 1, last_delta, password, &mut matches);
        matches
    }
}

struct RegexMatch {}

impl Matcher for RegexMatch {
    fn get_matches(&self,
                   password: &str,
                   _user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        let mut matches = Vec::new();
        for (&name, regex) in REGEXES.iter() {
            for capture in regex.captures_iter(password) {
                let token = &capture[0];
                matches.push(Match::default()
                    .pattern("regex")
                    .token(token.to_string())
                    .i(capture.pos(0).unwrap().0)
                    .j(capture.pos(0).unwrap().1)
                    .regex_name(Some(name))
                    .build());
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
    fn get_matches(&self,
                   password: &str,
                   _user_inputs: &Option<HashMap<String, usize>>)
                   -> Vec<Match> {
        let mut matches = Vec::new();

        // dates without separators are between length 4 '1191' and 8 '11111991'
        for i in 0..(password.len() - 4) {
            for j in (i + 3)..(i + 7) {
                if j >= password.len() {
                    break;
                }
                let token = &password[i..j];
                if !MAYBE_DATE_NO_SEPARATOR_REGEX.is_match(token) {
                    continue;
                }
                let mut candidates = Vec::new();
                for &(k, l) in &DATE_SPLITS[&token.len()] {
                    let ymd = map_ints_to_ymd(token[0..(k + 1)].parse().unwrap(),
                                              token[k..(l + 1)].parse().unwrap(),
                                              token[l..].parse().unwrap());
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
                let metric =
                    |candidate: &(i16, i8, i8)| candidate.0 - super::scoring::REFERENCE_YEAR;
                let best_candidate = candidates.iter().min_by_key(|&c| metric(c)).unwrap();
                matches.push(Match::default()
                    .pattern("date")
                    .token(token.to_string())
                    .i(i)
                    .j(j)
                    .separator("".to_string())
                    .year(best_candidate.0)
                    .month(best_candidate.1)
                    .day(best_candidate.2)
                    .build());
            }
        }

        // dates with separators are between length 6 '1/1/91' and 10 '11/11/1991'
        for i in 0..(password.len() - 6) {
            for j in (i + 5)..(i + 9) {
                if j >= password.len() {
                    break;
                }
                let token = &password[i..j];
                let captures = MAYBE_DATE_WITH_SEPARATOR_REGEX.captures(token);
                if captures.is_none() {
                    continue;
                }
                let captures = captures.unwrap();
                if captures[2] != captures[4] {
                    // Original code uses regex backreferences, Rust doesn't support these.
                    // Need to manually test that group 2 and 4 are the same
                    continue;
                }
                let ymd = map_ints_to_ymd(captures[1].parse().unwrap(),
                                          captures[3].parse().unwrap(),
                                          captures[5].parse().unwrap());
                if let Some(ymd) = ymd {
                    matches.push(Match::default()
                        .pattern("date")
                        .token(token.to_string())
                        .i(i)
                        .j(j)
                        .separator(captures[2].to_string())
                        .year(ymd.0)
                        .month(ymd.1)
                        .day(ymd.2)
                        .build());
                }
            }
        }

        matches.iter()
            .filter(|&x| !matches.iter().any(|y| *x != *y && y.i <= x.i && y.j >= x.j))
            .cloned()
            .collect()
    }
}

/// Takes three ints and returns them in a (y, m, d) tuple
fn map_ints_to_ymd(first: u16, second: u16, third: u16) -> Option<(i16, i8, i8)> {
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
                return Some((year as i16, dm.0, dm.1));
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
            return Some((year as i16, dm.0, dm.1));
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
