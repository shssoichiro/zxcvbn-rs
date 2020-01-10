**Version 2.0.1**
 - Fix overflow bugs that may cause wrong results on very complex passwords
 - Fix a panic that could occur on passwords with multibyte unicode characters

**Version 2.0.0**
 - [Breaking] Update CrackTimes interface to be more idiomatic to Rust (https://github.com/shssoichiro/zxcvbn-rs/pull/24)
 - Upgrade `derive_builder` to 0.8
 - Upgrade `fancy_regex` to 0.2
 - Move to 2018 edition
 - Various internal improvements

**Version 1.0.2**
 - Fix building on Rust 1.36.0 (https://github.com/shssoichiro/zxcvbn-rs/pull/21)
 - Cleanup development profiles which are no longer needed
 - Remove built-in clippy and prefer using clippy from rustup
 - Upgrade `itertools` to 0.8
 - Upgrade `derive_builder` to 0.7

**Version 1.0.1**
 - Upgrade `regex` to 1.0

**Version 1.0.0**
 - [SEMVER_MINOR] Add support for UTF-8 strings (https://github.com/shssoichiro/zxcvbn-rs/issues/4)
 - [SEMVER_MAJOR] Remove the `ZxcvbnError::NonAsciiPassword` variant, since this error can no longer occur

**Version 0.7.0**
 - [SEMVER_MAJOR] Refactor `Match` to use an enum internally, to avoid cluttering the struct with several `Option` types (https://github.com/shssoichiro/zxcvbn-rs/issues/19)
 - Make `Match` public (https://github.com/shssoichiro/zxcvbn-rs/issues/17)

**Version 0.6.3**
 - Refactor handling of strings to use streaming of characters. This brings zxcvbn closer to working on UTF-8 inputs.
 - Fix an issue that would cause bruteforce scores to be too low (https://github.com/shssoichiro/zxcvbn-rs/issues/15)

**Version 0.6.2**
 - Upgrade dependencies and fix linter warnings

**Version 0.6.1**
 - Upgrade `derive_builder` to 0.5.0
 - Fix a bug that was causing incorrect scoring for some passwords (https://github.com/shssoichiro/zxcvbn-rs/issues/13)

**Version 0.6.0**
 - [SEMVER_MAJOR] Change the signature for `zxcvbn` to take `&[]` instead of `Option<&[]>` for `user_inputs` (https://github.com/shssoichiro/zxcvbn-rs/issues/9)
 - [SEMVER_MAJOR] Change the signature for `zxcvbn` to return `Result<Entropy, ZxcvbnError>` instead of `Option<Entropy>` (https://github.com/shssoichiro/zxcvbn-rs/issues/11)

**Version 0.5.0**
 - Fix for a BC-breaking change in nightly Rust (https://github.com/shssoichiro/zxcvbn-rs/pull/8)
 - Upgrade `serde` to 1.0
 - Silence a warning from `derive_builder`

**Version 0.4.4**
 - Upgrade `itertools` to 0.6

**Version 0.4.3**
 - Upgrade to derive_builder 0.4

**Version 0.4.2**
 - Remove FFI dependency on oniguruma

**Version 0.4.1**
 - Fix more overflow bugs
 - Simplify code for handling overflows

**Version 0.4.0**
 - Fix bug which caused multiplication overflows on some very strong passwords
 - Remove rustc-serialize support (https://github.com/shssoichiro/zxcvbn-rs/issues/5)

**Version 0.3.0**
 - Make reference year dynamic
 - Performance optimizations
 - [SEMVER_MAJOR] Rename "serde" feature to "ser" (required by cargo)
 - [SEMVER_MAJOR] Bump required serde and serde_derive version to 0.9.x

**Version 0.2.1**
 - Update regex dependency to 0.2.0

**Version 0.2.0**
 - [SEMVER_MINOR] Add optional features "rustc-serialize" and "serde" for serialization support.
