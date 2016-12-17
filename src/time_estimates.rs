//! Contains structs and methods for calculating estimated time
//! needed to crack a given password.

/// Back-of-the-envelope crack time estimations, in seconds, based on a few scenarios
#[derive(Debug, Clone, Copy)]
pub struct CrackTimes {
    /// Online attack on a service that rate-limits password attempts
    pub online_throttling_100_per_hour: u64,
    /// Online attack on a service that doesn't rate-limit,
    /// or where an attacker has outsmarted rate-limiting.
    pub online_no_throttling_10_per_second: u64,
    /// Offline attack, assumes multiple attackers.
    /// Proper user-unique salting, and a slow hash function
    /// such as bcrypt, scrypt, PBKDF2.
    pub offline_slow_hashing_1e4_per_second: u64,
    /// Offline attack with user-unique salting but a fast hash function
    /// such as SHA-1, SHA-256, or MD5. A wide range of reasonable numbers
    /// anywhere from one billion to one trillion guesses per second,
    /// depending on number of cores and machines, ballparking at 10 billion per second.
    pub offline_fast_hashing_1e10_per_second: u64,
}

/// Back-of-the-envelope crack time estimations, in a human-readable format,
/// based on a few scenarios
#[derive(Debug, Clone)]
pub struct CrackTimesDisplay {
    /// Online attack on a service that rate-limits password attempts
    pub online_throttling_100_per_hour: String,
    /// Online attack on a service that doesn't rate-limit,
    /// or where an attacker has outsmarted rate-limiting.
    pub online_no_throttling_10_per_second: String,
    /// Offline attack, assumes multiple attackers.
    /// Proper user-unique salting, and a slow hash function
    /// such as bcrypt, scrypt, PBKDF2.
    pub offline_slow_hashing_1e4_per_second: String,
    /// Offline attack with user-unique salting but a fast hash function
    /// such as SHA-1, SHA-256, or MD5. A wide range of reasonable numbers
    /// anywhere from one billion to one trillion guesses per second,
    /// depending on number of cores and machines, ballparking at 10 billion per second.
    pub offline_fast_hashing_1e10_per_second: String,
}

#[doc(hidden)]
pub fn estimate_attack_times(guesses: u64) -> (CrackTimes, CrackTimesDisplay, u8) {
    let crack_times_seconds = CrackTimes {
        online_throttling_100_per_hour: guesses * 36,
        online_no_throttling_10_per_second: guesses / 10,
        offline_slow_hashing_1e4_per_second: guesses / 10_000,
        offline_fast_hashing_1e10_per_second: guesses / 10_000_000_000,
    };
    let crack_times_display = CrackTimesDisplay {
        online_throttling_100_per_hour:
            display_time(crack_times_seconds.online_throttling_100_per_hour),
        online_no_throttling_10_per_second:
            display_time(crack_times_seconds.online_no_throttling_10_per_second),
        offline_slow_hashing_1e4_per_second:
            display_time(crack_times_seconds.offline_slow_hashing_1e4_per_second),
        offline_fast_hashing_1e10_per_second:
            display_time(crack_times_seconds.offline_fast_hashing_1e10_per_second),
    };
    (crack_times_seconds, crack_times_display, calculate_score(guesses))
}

fn display_time(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = MINUTE * 60;
    const DAY: u64 = HOUR * 24;
    const MONTH:u64  = DAY * 31;
    const YEAR:u64 = MONTH * 12;
    const CENTURY:u64 = YEAR * 100;
    if seconds < 1 {
        "less than a second".to_string()
    } else if seconds < MINUTE {
        let base = seconds;
        format!("{} second{}", base, if base > 1 { "s" } else { "" })
    } else if seconds < HOUR {
        let base = seconds / MINUTE;
        format!("{} minute{}", base, if base > 1 { "s" } else { "" })
    } else if seconds < DAY {
        let base = seconds / HOUR;
        format!("{} hour{}", base, if base > 1 { "s" } else { "" })
    } else if seconds < MONTH {
        let base = seconds / DAY;
        format!("{} day{}", base, if base > 1 { "s" } else { "" })
    } else if seconds < YEAR {
        let base = seconds / MONTH;
        format!("{} month{}", base, if base > 1 { "s" } else { "" })
    } else if seconds < CENTURY {
        let base = seconds / YEAR;
        format!("{} year{}", base, if base > 1 { "s" } else { "" })
    } else {
        "centuries".to_string()
    }
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
