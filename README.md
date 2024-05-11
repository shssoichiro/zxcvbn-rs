# zxcvbn

[![Version](https://img.shields.io/crates/v/zxcvbn.svg)](https://crates.io/crates/zxcvbn)
[![License](https://img.shields.io/crates/l/zxcvbn.svg)](https://github.com/shssoichiro/zxcvbn-rs/blob/master/LICENSE)

## Overview

`zxcvbn` is a password strength estimator based off of Dropbox's zxcvbn library. Through pattern matching and conservative estimation, it recognizes and weighs 30k common passwords, common names and surnames according to US census data, popular English words from Wikipedia and US television and movies, and other common patterns like dates, repeats (`aaa`), sequences (`abcd`), keyboard patterns (`qwertyuiop`), and l33t speak.

Consider using zxcvbn as an algorithmic alternative to password composition policy — it is more secure, flexible, and usable when sites require a minimal complexity score in place of annoying rules like "passwords must contain three of {lower, upper, numbers, symbols}".

- **More secure**: policies often fail both ways, allowing weak passwords (`P@ssword1`) and disallowing strong passwords.
- **More flexible**: zxcvbn allows many password styles to flourish so long as it detects sufficient complexity — passphrases are rated highly given enough uncommon words, keyboard patterns are ranked based on length and number of turns, and capitalization adds more complexity when it's unpredictable.
- **More usable**: zxcvbn is designed to power simple, rule-free interfaces that give instant feedback. In addition to strength estimation, zxcvbn includes minimal, targeted verbal feedback that can help guide users towards less guessable passwords.

## Installing

`zxcvbn` can be added to your project's `Cargo.toml` under the `[dependencies]` section, as such:

```toml
[dependencies]
zxcvbn = "2"
```

zxcvbn has a "ser" feature flag you can enable if you require serialization support via `serde`.
It is disabled by default to reduce bloat.

zxcvbn follows Semantic Versioning.

zxcvbn targets the latest stable Rust compiler.
It may compile on earlier versions of the compiler, but is only guaranteed to work on the latest stable.
It should also work on the latest beta and nightly, assuming there are no compiler bugs.

## Usage

Full API documentation can be found [here](https://docs.rs/zxcvbn/*/zxcvbn/).

`zxcvbn` exposes one function called `zxcvbn` which can be called to calculate a score (0-4) for a password as well as other relevant information.
`zxcvbn` may also take an array of user inputs (e.g. username, email address, city, state) to provide warnings for passwords containing such information.

Usage example:

```rust
extern crate zxcvbn;

use zxcvbn::zxcvbn;

fn main() {
    let estimate = zxcvbn("correcthorsebatterystaple", &[]);
    println!("{:?}", estimate.score()); // Medium
}
```

Other fields available on the returned `Entropy` struct may be viewed in the [full documentation](https://docs.rs/zxcvbn/*/zxcvbn/).

## Contributing

Any contributions are welcome and will be accepted via pull request on GitHub. Bug reports can be
filed via GitHub issues. Please include as many details as possible. If you have the capability
to submit a fix with the bug report, it is preferred that you do so via pull request,
however you do not need to be a Rust developer to contribute.
Other contributions (such as improving documentation or translations) are also welcome via GitHub.

## License

zxcvbn is open-source software, distributed under the MIT license.
