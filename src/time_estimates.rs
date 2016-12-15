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
pub fn estimate_attack_times(guesses: u64) -> (CrackTimes, CrackTimesDisplay) {
    unimplemented!()
}
