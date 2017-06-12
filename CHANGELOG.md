**Version 0.6.0**
 - [SEMVER_MAJOR] Change the signature for `zxcvbn` to take `&[]` instead of `Option<&[]>` for `user_inputs` (https://github.com/shssoichiro/zxcvbn-rs/issues/9)
 - [SEMVER_MAJOR] Change the signature for `zxcvbn` to return `Result<Entropy, ZxcvbnError>` instead of `Option<Entropy>`

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
