use crate::matching::patterns::*;
use crate::matching::Match;
use std::cmp;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct GuessCalculation {
    /// Estimated guesses needed to crack the password
    pub guesses: u64,
    /// Order of magnitude of `guesses`
    pub guesses_log10: f64,
    /// The list of patterns the guess calculation was based on
    pub sequence: Vec<Match>,
}

#[derive(Debug, Clone)]
struct Optimal {
    /// optimal.m[k][l] holds final match in the best length-l match sequence covering the
    /// password prefix up to k, inclusive.
    /// if there is no length-l sequence that scores better (fewer guesses) than
    /// a shorter match sequence spanning the same prefix, optimal.m[k][l] is undefined.
    m: Vec<HashMap<usize, Match>>,
    /// same structure as optimal.m -- holds the product term Prod(m.guesses for m in sequence).
    /// optimal.pi allows for fast (non-looping) updates to the minimization function.
    pi: Vec<HashMap<usize, u64>>,
    /// same structure as optimal.m -- holds the overall metric.
    g: Vec<HashMap<usize, u64>>,
}

#[cfg(target_arch = "wasm32")]
fn current_year() -> i32 {
    js_sys::Date::new_0().get_full_year().try_into().unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
fn current_year() -> i32 {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc().year()
}

lazy_static! {
    pub(crate) static ref REFERENCE_YEAR: i32 = current_year();
}
const MIN_YEAR_SPACE: i32 = 20;
const BRUTEFORCE_CARDINALITY: u64 = 10;
const MIN_GUESSES_BEFORE_GROWING_SEQUENCE: u64 = 10_000;
const MIN_SUBMATCH_GUESSES_SINGLE_CHAR: u64 = 10;
const MIN_SUBMATCH_GUESSES_MULTI_CHAR: u64 = 50;

pub fn most_guessable_match_sequence(
    password: &str,
    matches: &[crate::matching::Match],
    exclude_additive: bool,
) -> GuessCalculation {
    let n = password.chars().count();

    // partition matches into sublists according to ending index j
    let mut matches_by_j: Vec<Vec<Match>> = vec![Vec::new(); n];
    for m in matches {
        matches_by_j[m.j].push(m.clone());
    }
    // small detail: for deterministic output, sort each sublist by i.
    for lst in &mut matches_by_j {
        lst.sort_by_key(|m| m.i);
    }

    let mut optimal = Optimal {
        m: vec![HashMap::new(); n],
        pi: vec![HashMap::new(); n],
        g: vec![HashMap::new(); n],
    };

    /// helper: considers whether a length-l sequence ending at match m is better (fewer guesses)
    /// than previously encountered sequences, updating state if so.
    fn update(
        mut m: Match,
        len: usize,
        password: &str,
        optimal: &mut Optimal,
        exclude_additive: bool,
    ) {
        let k = m.j;
        let mut pi = estimate_guesses(&mut m, password);
        if len > 1 {
            // we're considering a length-l sequence ending with match m:
            // obtain the product term in the minimization function by multiplying m's guesses
            // by the product of the length-(l-1) sequence ending just before m, at m.i - 1.
            pi = pi.saturating_mul(optimal.pi[m.i - 1][&(len - 1)]);
        }
        // calculate the minimization func
        let mut guesses = (factorial(len) as u64).saturating_mul(pi);
        if !exclude_additive {
            let additive = if len == 1 {
                1
            } else {
                (2..len).fold(MIN_GUESSES_BEFORE_GROWING_SEQUENCE, |acc, _| {
                    acc.saturating_mul(MIN_GUESSES_BEFORE_GROWING_SEQUENCE)
                })
            };
            guesses = guesses.saturating_add(additive);
        }
        // update state if new best.
        // first see if any competing sequences covering this prefix, with l or fewer matches,
        // fare better than this sequence. if so, skip it and return.
        for (&competing_l, &competing_guesses) in &optimal.g[k] {
            if competing_l > len {
                continue;
            }
            if competing_guesses <= guesses as u64 {
                return;
            }
        }
        // this sequence might be part of the final optimal sequence.
        optimal.g[k].insert(len, guesses);
        optimal.m[k].insert(len, m);
        optimal.pi[k].insert(len, pi);
    }

    /// helper: evaluate bruteforce matches ending at k.
    fn bruteforce_update(k: usize, password: &str, optimal: &mut Optimal, exclude_additive: bool) {
        // see if a single bruteforce match spanning the k-prefix is optimal.
        let m = make_bruteforce_match(0, k, password);
        update(m, 1, password, optimal, exclude_additive);
        for i in 1..=k {
            // generate k bruteforce matches, spanning from (i=1, j=k) up to (i=k, j=k).
            // see if adding these new matches to any of the sequences in optimal[i-1]
            // leads to new bests.
            let m = make_bruteforce_match(i, k, password);
            for (l, last_m) in optimal.m[i - 1].clone() {
                // corner: an optimal sequence will never have two adjacent bruteforce matches.
                // it is strictly better to have a single bruteforce match spanning the same region:
                // same contribution to the guess product with a lower length.
                // --> safe to skip those cases.
                if last_m.pattern == MatchPattern::BruteForce {
                    continue;
                }
                // try adding m to this length-l sequence.
                update(m.clone(), l + 1, password, optimal, exclude_additive);
            }
        }
    }

    /// helper: make bruteforce match objects spanning i to j, inclusive.
    fn make_bruteforce_match(i: usize, j: usize, password: &str) -> Match {
        Match {
            pattern: MatchPattern::BruteForce,
            token: password.chars().take(j + 1).skip(i).collect(),
            i,
            j,
            ..Match::default()
        }
    }

    /// helper: step backwards through optimal.m starting at the end,
    /// constructing the final optimal match sequence.
    #[allow(clippy::many_single_char_names)]
    fn unwind(n: usize, optimal: &mut Optimal) -> Vec<Match> {
        let mut optimal_match_sequence = Vec::new();
        let mut k = n - 1;
        // find the final best sequence length and score
        let mut l = None;
        let mut g = None;
        for (candidate_l, candidate_g) in &optimal.g[k] {
            if g.is_none() || *candidate_g < *g.as_ref().unwrap() {
                l = Some(*candidate_l);
                g = Some(*candidate_g);
            }
        }

        loop {
            let m = &optimal.m[k][&l.unwrap()];
            optimal_match_sequence.insert(0, m.clone());
            if m.i == 0 {
                return optimal_match_sequence;
            }
            k = m.i - 1;
            l = l.map(|x| x - 1);
        }
    }

    for (k, match_by_j) in matches_by_j.iter().enumerate() {
        for m in match_by_j {
            if m.i > 0 {
                let keys: Vec<usize> = optimal.m[m.i - 1].keys().cloned().collect();
                for l in keys {
                    update(m.clone(), l + 1, password, &mut optimal, exclude_additive);
                }
            } else {
                update(m.clone(), 1, password, &mut optimal, exclude_additive);
            }
        }
        bruteforce_update(k, password, &mut optimal, exclude_additive);
    }
    let optimal_match_sequence = unwind(n, &mut optimal);
    let optimal_l = optimal_match_sequence.len();

    // corner: empty password
    let guesses = if password.is_empty() {
        1
    } else {
        optimal.g[n - 1][&optimal_l]
    };

    GuessCalculation {
        guesses: guesses as u64,
        guesses_log10: (guesses as f64).log10(),
        sequence: optimal_match_sequence,
    }
}

fn factorial(n: usize) -> usize {
    (1..=n).product()
}

fn estimate_guesses(m: &mut Match, password: &str) -> u64 {
    if let Some(guesses) = m.guesses {
        // a match's guess estimate doesn't change. cache it.
        return guesses;
    }
    let min_guesses = if m.token.chars().count() < password.chars().count() {
        if m.token.chars().count() == 1 {
            MIN_SUBMATCH_GUESSES_SINGLE_CHAR
        } else {
            MIN_SUBMATCH_GUESSES_MULTI_CHAR
        }
    } else {
        1
    };
    let guesses = m.pattern.estimate(&m.token);
    m.guesses = Some(cmp::max(guesses, min_guesses));
    m.guesses.unwrap()
}

trait Estimator {
    fn estimate(&mut self, token: &str) -> u64;
}

impl Estimator for MatchPattern {
    fn estimate(&mut self, token: &str) -> u64 {
        match *self {
            MatchPattern::Dictionary(ref mut p) => p.estimate(token),
            MatchPattern::Spatial(ref mut p) => p.estimate(token),
            MatchPattern::Repeat(ref mut p) => p.estimate(token),
            MatchPattern::Sequence(ref mut p) => p.estimate(token),
            MatchPattern::Regex(ref mut p) => p.estimate(token),
            MatchPattern::Date(ref mut p) => p.estimate(token),
            MatchPattern::BruteForce => {
                let mut guesses = BRUTEFORCE_CARDINALITY;
                let token_len = token.chars().count();
                if token_len >= 2 {
                    for _ in 2..=token_len {
                        guesses = guesses.saturating_mul(BRUTEFORCE_CARDINALITY);
                    }
                }
                // small detail: make bruteforce matches at minimum one guess bigger than smallest allowed
                // submatch guesses, such that non-bruteforce submatches over the same [i..j] take precedence.
                let min_guesses = if token_len == 1 {
                    MIN_SUBMATCH_GUESSES_SINGLE_CHAR + 1
                } else {
                    MIN_SUBMATCH_GUESSES_MULTI_CHAR + 1
                };
                cmp::max(guesses, min_guesses)
            }
        }
    }
}

impl Estimator for DictionaryPattern {
    fn estimate(&mut self, token: &str) -> u64 {
        let uppercase_variations = uppercase_variations(token);
        let l33t_variations = l33t_variations(self, token);
        self.base_guesses = self.rank as u64;
        self.uppercase_variations = uppercase_variations;
        self.l33t_variations = l33t_variations;
        self.base_guesses
            * self.uppercase_variations
            * self.l33t_variations
            * if self.reversed { 2 } else { 1 }
    }
}

fn uppercase_variations(token: &str) -> u64 {
    if token.chars().all(char::is_lowercase) || token.to_lowercase().as_str() == token {
        return 1;
    }
    // a capitalized token is the most common capitalization scheme,
    // so it only doubles the search space (uncapitalized + capitalized).
    // allcaps and end-capitalized are common enough too, underestimate as 2x factor to be safe.
    if ((token.chars().next().unwrap().is_uppercase()
        || token.chars().last().unwrap().is_uppercase())
        && token.chars().filter(|&c| c.is_uppercase()).count() == 1)
        || token.chars().all(char::is_uppercase)
    {
        return 2;
    }
    // otherwise calculate the number of ways to capitalize U+L uppercase+lowercase letters
    // with U uppercase letters or less. or, if there's more uppercase than lower (for eg. PASSwORD),
    // the number of ways to lowercase U+L letters with L lowercase letters or less.
    let upper = token.chars().filter(|c| c.is_uppercase()).count();
    let lower = token.chars().filter(|c| c.is_lowercase()).count();
    (1..=cmp::min(upper, lower))
        .map(|i| n_ck(upper + lower, i))
        .sum()
}

fn l33t_variations(pattern: &DictionaryPattern, token: &str) -> u64 {
    if !pattern.l33t {
        return 1;
    }
    let mut variations = 1;
    for (subbed, unsubbed) in pattern.sub.as_ref().unwrap() {
        // lower-case match.token before calculating: capitalization shouldn't affect l33t calc.
        let token = token.to_lowercase();
        let subbed = token.chars().filter(|c| c == subbed).count();
        let unsubbed = token.chars().filter(|c| c == unsubbed).count();
        if subbed == 0 || unsubbed == 0 {
            // for this sub, password is either fully subbed (444) or fully unsubbed (aaa)
            // treat that as doubling the space (attacker needs to try fully subbed chars in addition to
            // unsubbed.)
            variations *= 2;
        } else {
            // this case is similar to capitalization:
            // with aa44a, U = 3, S = 2, attacker needs to try unsubbed + one sub + two subs
            let p = cmp::min(unsubbed, subbed);
            let possibilities: u64 = (1..=p).map(|i| n_ck(unsubbed + subbed, i)).sum();
            variations *= possibilities;
        }
    }
    variations as u64
}

fn n_ck(n: usize, k: usize) -> u64 {
    // http://blog.plover.com/math/choose.html
    (if k > n {
        0
    } else if k == 0 {
        1
    } else {
        let mut r: usize = 1;
        let mut n = n;
        for d in 1..=k {
            r = r.saturating_mul(n);
            r /= d;
            n -= 1;
        }
        r
    }) as u64
}

impl Estimator for SpatialPattern {
    fn estimate(&mut self, token: &str) -> u64 {
        let (starts, degree) = if ["qwerty", "dvorak"].contains(&self.graph.as_str()) {
            (*KEYBOARD_STARTING_POSITIONS, *KEYBOARD_AVERAGE_DEGREE)
        } else {
            (*KEYPAD_STARTING_POSITIONS, *KEYPAD_AVERAGE_DEGREE)
        };
        let mut guesses = 0u64;
        let len = token.chars().count();
        // estimate the number of possible patterns w/ length L or less with t turns or less.
        for i in 2..=len {
            let possible_turns = cmp::min(self.turns, i - 1);
            for j in 1..=possible_turns {
                guesses = guesses.saturating_add(
                    n_ck(i - 1, j - 1) * starts as u64 * degree.pow(j as u32) as u64,
                );
            }
        }
        // add extra guesses for shifted keys. (% instead of 5, A instead of a.)
        // math is similar to extra guesses of l33t substitutions in dictionary matches.
        let shifted_count = self.shifted_count;
        if shifted_count > 0 {
            let unshifted_count = len - shifted_count;
            if unshifted_count == 0 {
                guesses = guesses.saturating_mul(2);
            } else {
                let shifted_variations: u64 = (1..=cmp::min(shifted_count, unshifted_count))
                    .map(|i| n_ck(shifted_count + unshifted_count, i))
                    .sum();
                guesses = guesses.saturating_mul(shifted_variations);
            }
        }
        guesses
    }
}

lazy_static! {
    static ref KEYBOARD_AVERAGE_DEGREE: u64 = calc_average_degree(&crate::adjacency_graphs::QWERTY);
    // slightly different for keypad/mac keypad, but close enough
    static ref KEYPAD_AVERAGE_DEGREE: u64 = calc_average_degree(&crate::adjacency_graphs::KEYPAD);
    static ref KEYBOARD_STARTING_POSITIONS: u64 = crate::adjacency_graphs::QWERTY.len() as u64;
    static ref KEYPAD_STARTING_POSITIONS: u64 = crate::adjacency_graphs::KEYPAD.len() as u64;
}

fn calc_average_degree(graph: &HashMap<char, Vec<Option<&'static str>>>) -> u64 {
    let sum: u64 = graph
        .values()
        .map(|neighbors| neighbors.iter().filter(|n| n.is_some()).count() as u64)
        .sum();
    sum / graph.len() as u64
}

impl Estimator for RepeatPattern {
    fn estimate(&mut self, _: &str) -> u64 {
        self.base_guesses.saturating_mul(self.repeat_count as u64)
    }
}

impl Estimator for SequencePattern {
    fn estimate(&mut self, token: &str) -> u64 {
        let first_chr = token.chars().next().unwrap();
        // lower guesses for obvious starting points
        let mut base_guesses = if ['a', 'A', 'z', 'Z', '0', '1', '9'].contains(&first_chr) {
            4
        } else if first_chr.is_digit(10) {
            10
        } else {
            // could give a higher base for uppercase,
            // assigning 26 to both upper and lower sequences is more conservative.
            26
        };
        if !self.ascending {
            // need to try a descending sequence in addition to every ascending sequence ->
            // 2x guesses
            base_guesses *= 2;
        }
        base_guesses * token.chars().count() as u64
    }
}

impl Estimator for RegexPattern {
    fn estimate(&mut self, token: &str) -> u64 {
        if CHAR_CLASS_BASES.keys().any(|x| *x == self.regex_name) {
            CHAR_CLASS_BASES[self.regex_name].pow(token.chars().count() as u32)
        } else {
            match self.regex_name {
                "recent_year" => {
                    let year_space =
                        (self.regex_match[0].parse::<i32>().unwrap() - *REFERENCE_YEAR).abs();
                    cmp::max(year_space, MIN_YEAR_SPACE) as u64
                }
                _ => unreachable!(),
            }
        }
    }
}

lazy_static! {
    static ref CHAR_CLASS_BASES: HashMap<&'static str, u64> = {
        let mut table = HashMap::with_capacity(6);
        table.insert("alpha_lower", 26);
        table.insert("alpha_upper", 26);
        table.insert("alpha", 52);
        table.insert("alphanumeric", 62);
        table.insert("digits", 10);
        table.insert("symbols", 33);
        table
    };
}

impl Estimator for DatePattern {
    fn estimate(&mut self, _: &str) -> u64 {
        // base guesses: (year distance from REFERENCE_YEAR) * num_days * num_years
        let year_space = cmp::max((self.year - *REFERENCE_YEAR).abs(), MIN_YEAR_SPACE);
        let mut guesses = year_space as u64 * 365;
        // add factor of 4 for separator selection (one of ~4 choices)
        if !self.separator.is_empty() {
            guesses *= 4;
        }
        guesses as u64
    }
}

#[cfg(test)]
mod tests {
    use crate::matching::patterns::*;
    use crate::matching::Match;
    use crate::scoring;
    use crate::scoring::Estimator;
    use quickcheck::TestResult;
    use std::collections::HashMap;

    #[test]
    fn test_n_ck() {
        let test_data = [
            (0, 0, 1),
            (1, 0, 1),
            (5, 0, 1),
            (0, 1, 0),
            (0, 5, 0),
            (2, 1, 2),
            (4, 2, 6),
            (33, 7, 4_272_048),
        ];
        for &(n, k, result) in &test_data {
            assert_eq!(scoring::n_ck(n, k), result);
        }
    }

    quickcheck! {
        fn test_n_ck_mul_overflow(n: usize, k: usize) -> TestResult {
            if n >= 63 {
                scoring::n_ck(n, k); // Must not panic
                TestResult::from_bool(true)
            } else {
                TestResult::discard()
            }
        }

        fn test_n_ck_mirror_identity(n: usize, k: usize) -> TestResult {
            if k > n || n >= 63 {
                return TestResult::discard();
            }
            TestResult::from_bool(scoring::n_ck(n, k) == scoring::n_ck(n, n-k))
        }

        fn test_n_ck_pascals_triangle(n: usize, k: usize) -> TestResult {
            if n == 0 || k == 0 || n >= 63 {
                return TestResult::discard();
            }
            TestResult::from_bool(scoring::n_ck(n, k) == scoring::n_ck(n-1, k-1) + scoring::n_ck(n-1, k))
        }
    }

    #[test]
    fn test_search_returns_one_bruteforce_match_given_empty_match_sequence() {
        let password = "0123456789";
        let result = scoring::most_guessable_match_sequence(password, &[], true);
        assert_eq!(result.sequence.len(), 1);
        let m0 = &result.sequence[0];
        assert_eq!(m0.pattern.variant(), "bruteforce");
        assert_eq!(m0.token, password);
        assert_eq!(m0.i, 0);
        assert_eq!(m0.j, 9);
    }

    #[test]
    fn test_search_returns_match_and_bruteforce_when_match_covers_prefix_of_password() {
        let password = "0123456789";
        let m = Match {
            i: 0,
            j: 5,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result = scoring::most_guessable_match_sequence(password, &[m.clone()], true);
        assert_eq!(result.sequence.len(), 2);
        assert_eq!(result.sequence[0], m);
        let m1 = &result.sequence[1];
        assert_eq!(m1.pattern.variant(), "bruteforce");
        assert_eq!(m1.i, 6);
        assert_eq!(m1.j, 9);
    }

    #[test]
    fn test_search_returns_bruteforce_and_match_when_match_covers_a_suffix() {
        let password = "0123456789";
        let m = Match {
            i: 3,
            j: 9,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result = scoring::most_guessable_match_sequence(password, &[m.clone()], true);
        assert_eq!(result.sequence.len(), 2);
        let m0 = &result.sequence[0];
        assert_eq!(m0.pattern.variant(), "bruteforce");
        assert_eq!(m0.i, 0);
        assert_eq!(m0.j, 2);
        assert_eq!(result.sequence[1], m);
    }

    #[test]
    fn test_search_returns_bruteforce_and_match_when_match_covers_an_infix() {
        let password = "0123456789";
        let m = Match {
            i: 1,
            j: 8,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result = scoring::most_guessable_match_sequence(password, &[m.clone()], true);
        assert_eq!(result.sequence.len(), 3);
        assert_eq!(result.sequence[1], m);
        let m0 = &result.sequence[0];
        let m2 = &result.sequence[2];
        assert_eq!(m0.pattern.variant(), "bruteforce");
        assert_eq!(m0.i, 0);
        assert_eq!(m0.j, 0);
        assert_eq!(m2.pattern.variant(), "bruteforce");
        assert_eq!(m2.i, 9);
        assert_eq!(m2.j, 9);
    }

    #[test]
    fn test_search_chooses_lower_guesses_match_given_two_matches_of_same_span() {
        let password = "0123456789";
        let mut m0 = Match {
            i: 0,
            j: 9,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };
        let m1 = Match {
            i: 0,
            j: 9,
            guesses: Some(2),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result =
            scoring::most_guessable_match_sequence(password, &[m0.clone(), m1.clone()], true);
        assert_eq!(result.sequence.len(), 1);
        assert_eq!(result.sequence[0], m0);
        // make sure ordering doesn't matter
        m0.guesses = Some(3);
        let result = scoring::most_guessable_match_sequence(password, &[m0, m1.clone()], true);
        assert_eq!(result.sequence.len(), 1);
        assert_eq!(result.sequence[0], m1);
    }

    #[test]
    fn test_search_when_m0_covers_m1_and_m2_choose_m0_when_m0_lt_m1_t_m2_t_fact_2() {
        let password = "0123456789";
        let m0 = Match {
            i: 0,
            j: 9,
            guesses: Some(3),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };
        let m1 = Match {
            i: 0,
            j: 3,
            guesses: Some(2),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };
        let m2 = Match {
            i: 4,
            j: 9,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result = scoring::most_guessable_match_sequence(password, &[m0.clone(), m1, m2], true);
        assert_eq!(result.guesses, 3);
        assert_eq!(result.sequence, vec![m0]);
    }

    #[test]
    fn test_search_when_m0_covers_m1_and_m2_choose_m1_m2_when_m0_gt_m1_t_m2_t_fact_2() {
        let password = "0123456789";
        let m0 = Match {
            i: 0,
            j: 9,
            guesses: Some(5),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };
        let m1 = Match {
            i: 0,
            j: 3,
            guesses: Some(2),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };
        let m2 = Match {
            i: 4,
            j: 9,
            guesses: Some(1),
            pattern: MatchPattern::Dictionary(DictionaryPattern::default()),
            ..Match::default()
        };

        let result =
            scoring::most_guessable_match_sequence(password, &[m0, m1.clone(), m2.clone()], true);
        assert_eq!(result.guesses, 4);
        assert_eq!(result.sequence, vec![m1, m2]);
    }

    #[test]
    fn test_calc_guesses_returns_guesses_when_cached() {
        let mut m = Match {
            guesses: Some(1),
            ..Match::default()
        };
        assert_eq!(scoring::estimate_guesses(&mut m, ""), 1);
    }

    #[test]
    fn test_calc_guesses_delegates_based_on_pattern() {
        let mut p = DatePattern {
            year: 1977,
            month: 7,
            day: 14,
            ..DatePattern::default()
        };
        let token = "1977";
        let mut m = Match {
            pattern: MatchPattern::Date(p.clone()),
            token: token.to_string(),
            ..Match::default()
        };
        assert_eq!(scoring::estimate_guesses(&mut m, token), p.estimate(token));
    }

    #[test]
    fn test_repeat_guesses() {
        let test_data = [
            ("aa", "a", 2),
            ("999", "9", 3),
            ("$$$$", "$", 4),
            ("abab", "ab", 2),
            (
                "batterystaplebatterystaplebatterystaple",
                "batterystaple",
                3,
            ),
        ];
        for &(token, base_token, repeat_count) in &test_data {
            let base_guesses = scoring::most_guessable_match_sequence(
                base_token,
                &crate::matching::omnimatch(base_token, &HashMap::new()),
                false,
            )
            .guesses;
            let mut p = RepeatPattern {
                base_token: base_token.to_string(),
                base_guesses,
                repeat_count,
                ..RepeatPattern::default()
            };
            let expected_guesses = base_guesses * repeat_count as u64;
            assert_eq!(p.estimate(token), expected_guesses);
        }
    }

    #[test]
    fn test_sequence_guesses() {
        let test_data = [
            ("ab", true, 4 * 2),         // obvious start * len-2
            ("XYZ", true, 26 * 3),       // base26 * len-3
            ("4567", true, 10 * 4),      // base10 * len-4
            ("7654", false, 10 * 4 * 2), // base10 * len 4 * descending
            ("ZYX", false, 4 * 3 * 2),   /* obvious start * len-3 * descending */
        ];
        for &(token, ascending, guesses) in &test_data {
            let mut p = SequencePattern {
                ascending,
                ..SequencePattern::default()
            };
            assert_eq!(p.estimate(token), guesses);
        }
    }

    #[test]
    fn test_regex_guesses_lowercase() {
        let token = "aizocdk";
        let mut p = RegexPattern {
            regex_name: "alpha_lower",
            regex_match: vec![token.to_string()],
        };
        assert_eq!(p.estimate(token), 26u64.pow(7));
    }

    #[test]
    fn test_regex_guesses_alphanumeric() {
        let token = "ag7C8";
        let mut p = RegexPattern {
            regex_name: "alphanumeric",
            regex_match: vec![token.to_string()],
        };
        assert_eq!(p.estimate(token), 62u64.pow(5));
    }

    #[test]
    fn test_regex_guesses_distant_year() {
        let token = "1972";
        let mut p = RegexPattern {
            regex_name: "recent_year",
            regex_match: vec![token.to_string()],
        };
        assert_eq!(
            p.estimate(token),
            (*scoring::REFERENCE_YEAR - 1972).abs() as u64
        );
    }

    #[test]
    fn test_regex_guesses_recent_year() {
        let token = "2005";
        let mut p = RegexPattern {
            regex_name: "recent_year",
            regex_match: vec![token.to_string()],
        };
        assert_eq!(p.estimate(token), scoring::MIN_YEAR_SPACE as u64);
    }

    #[test]
    fn test_date_guesses() {
        let mut p = DatePattern {
            separator: "".to_string(),
            year: 1923,
            month: 1,
            day: 1,
        };
        let token = "1123";
        assert_eq!(
            p.estimate(token),
            365 * (*scoring::REFERENCE_YEAR - p.year).abs() as u64
        );
    }

    #[test]
    fn test_date_guesses_recent_years_assume_min_year_space() {
        let mut p = DatePattern {
            separator: "/".to_string(),
            year: 2010,
            month: 1,
            day: 1,
        };
        let token = "1/1/2010";
        assert_eq!(p.estimate(token), 365 * scoring::MIN_YEAR_SPACE as u64 * 4);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_spatial_guesses_no_turns_or_shifts() {
        let mut p = SpatialPattern {
            graph: "qwerty".to_string(),
            turns: 1,
            shifted_count: 0,
        };
        let token = "zxcvbn";
        let base_guesses = *scoring::KEYBOARD_STARTING_POSITIONS
            * *scoring::KEYBOARD_AVERAGE_DEGREE
            * (token.len() - 1) as u64;
        assert_eq!(p.estimate(token), base_guesses as u64);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_spatial_guesses_adds_for_shifted_keys() {
        let mut p = SpatialPattern {
            graph: "qwerty".to_string(),
            turns: 1,
            shifted_count: 2,
        };
        let token = "ZxCvbn";
        let base_guesses = *scoring::KEYBOARD_STARTING_POSITIONS
            * *scoring::KEYBOARD_AVERAGE_DEGREE
            * (token.len() - 1) as u64
            * (scoring::n_ck(6, 2) + scoring::n_ck(6, 1));
        assert_eq!(p.estimate(token), base_guesses);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_spatial_guesses_doubles_when_all_shifted() {
        let mut p = SpatialPattern {
            graph: "qwerty".to_string(),
            turns: 1,
            shifted_count: 6,
        };
        let token = "ZXCVBN";
        let base_guesses = *scoring::KEYBOARD_STARTING_POSITIONS
            * *scoring::KEYBOARD_AVERAGE_DEGREE
            * (token.len() - 1) as u64
            * 2;
        assert_eq!(p.estimate(token), base_guesses as u64);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_spatial_guesses_accounts_for_turn_positions_directions_and_start_keys() {
        let mut p = SpatialPattern {
            graph: "qwerty".to_string(),
            turns: 3,
            shifted_count: 0,
        };
        let token = "zxcft6yh";
        let guesses: u64 = (2..(token.len() + 1))
            .map(|i| {
                (1..::std::cmp::min(p.turns + 1, i))
                    .map(|j| {
                        scoring::n_ck(i - 1, j - 1)
                            * (*scoring::KEYBOARD_STARTING_POSITIONS
                                * scoring::KEYBOARD_AVERAGE_DEGREE.pow(j as u32))
                                as u64
                    })
                    .sum::<u64>()
            })
            .sum::<u64>();
        assert_eq!(p.estimate(token), guesses);
    }

    #[test]
    fn test_dictionary_base_guesses_equals_rank() {
        let mut p = DictionaryPattern {
            rank: 32,
            ..DictionaryPattern::default()
        };
        let token = "aaaaa";
        assert_eq!(p.estimate(token), 32);
    }

    #[test]
    fn test_dictionary_extra_guesses_added_for_caps() {
        let mut p = DictionaryPattern {
            rank: 32,
            ..DictionaryPattern::default()
        };
        let token = "AAAaaa";
        assert_eq!(p.estimate(token), 32 * scoring::uppercase_variations(token));
    }

    #[test]
    fn test_dictionary_guesses_doubled_if_reversed() {
        let mut p = DictionaryPattern {
            rank: 32,
            reversed: true,
            ..DictionaryPattern::default()
        };
        let token = "aaa";
        assert_eq!(p.estimate(token), 32 * 2);
    }

    #[test]
    fn test_dictionary_guesses_added_for_l33t() {
        let mut subs = HashMap::with_capacity(1);
        subs.insert('@', 'a');
        let mut p = DictionaryPattern {
            rank: 32,
            l33t: true,
            sub: Some(subs),
            ..DictionaryPattern::default()
        };
        let token = "aaa@@@";
        let expected = 32 * scoring::l33t_variations(&p, token);
        assert_eq!(p.estimate(token), expected);
    }

    #[test]
    fn test_dictionary_guesses_added_for_caps_and_l33t() {
        let mut subs = HashMap::with_capacity(1);
        subs.insert('@', 'a');
        let mut p = DictionaryPattern {
            rank: 32,
            l33t: true,
            sub: Some(subs),
            ..DictionaryPattern::default()
        };
        let token = "AaA@@@";
        let expected =
            32 * scoring::l33t_variations(&p, token) * scoring::uppercase_variations(token);
        assert_eq!(p.estimate(token), expected);
    }

    #[test]
    fn test_uppercase_variations() {
        let test_data = [
            ("", 1),
            ("a", 1),
            ("A", 2),
            ("abcdef", 1),
            ("Abcdef", 2),
            ("abcdeF", 2),
            ("ABCDEF", 2),
            ("aBcdef", scoring::n_ck(6, 1)),
            ("aBcDef", scoring::n_ck(6, 1) + scoring::n_ck(6, 2)),
            ("ABCDEf", scoring::n_ck(6, 1)),
            ("aBCDEf", scoring::n_ck(6, 1) + scoring::n_ck(6, 2)),
            (
                "ABCdef",
                scoring::n_ck(6, 1) + scoring::n_ck(6, 2) + scoring::n_ck(6, 3),
            ),
        ];
        for &(word, variants) in &test_data {
            assert_eq!(scoring::uppercase_variations(word), variants);
        }
    }

    #[test]
    fn test_l33t_variations_for_non_l33t() {
        let p = DictionaryPattern {
            l33t: false,
            ..DictionaryPattern::default()
        };
        assert_eq!(scoring::l33t_variations(&p, ""), 1);
    }

    #[test]
    fn test_l33t_variations() {
        let test_data = [
            ("", 1, vec![].into_iter().collect::<HashMap<char, char>>()),
            ("a", 1, vec![].into_iter().collect::<HashMap<char, char>>()),
            (
                "4",
                2,
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "4pple",
                2,
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "abcet",
                1,
                vec![].into_iter().collect::<HashMap<char, char>>(),
            ),
            (
                "4bcet",
                2,
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "a8cet",
                2,
                vec![('8', 'b')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "abce+",
                2,
                vec![('+', 't')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "48cet",
                4,
                vec![('4', 'a'), ('8', 'b')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "a4a4aa",
                scoring::n_ck(6, 2) + scoring::n_ck(6, 1),
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "4a4a44",
                scoring::n_ck(6, 2) + scoring::n_ck(6, 1),
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "Aa44aA",
                scoring::n_ck(6, 2) + scoring::n_ck(6, 1),
                vec![('4', 'a')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
            (
                "a44att+",
                (scoring::n_ck(4, 2) + scoring::n_ck(4, 1)) * scoring::n_ck(3, 1),
                vec![('4', 'a'), ('+', 't')]
                    .into_iter()
                    .collect::<HashMap<char, char>>(),
            ),
        ];
        for &(word, variants, ref sub) in &test_data {
            let p = DictionaryPattern {
                sub: Some(sub.clone()),
                l33t: !sub.is_empty(),
                ..DictionaryPattern::default()
            };
            assert_eq!(scoring::l33t_variations(&p, word), variants);
        }
    }
}
