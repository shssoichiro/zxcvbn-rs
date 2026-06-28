# zxcvbn-rs Python bindings

This package provides opt-in Python bindings for `zxcvbn-rs`.
The `zxcvbn` function returns a dictionary-style payload compatible with the
commonly used fields from `zxcvbn-python`, using JSON-native values throughout.
The Python package version tracks the Rust crate version.

```python
from zxcvbn_rs import zxcvbn

result = zxcvbn("correct horse battery staple", user_inputs=["alex"])
```

`max_length` may be supplied as a keyword argument to reject longer passwords.
When it is omitted, the Rust library's built-in 100-character evaluation limit
applies. Lengths are measured in Unicode characters.

## Compatibility notes

- `guesses` is an integer capped at `2**64 - 1`; `guesses_log10` retains the
  estimated magnitude after saturation.
- `calc_time` is a JSON-serializable number of milliseconds rather than a
  `datetime.timedelta`.
- Crack-time values are floats rather than `decimal.Decimal` objects.
- An empty password has `guesses_log10 == 0.0`, avoiding a non-finite JSON value.
- The returned `password`, feedback, and sequence dictionary names follow the
  `zxcvbn-python` field conventions where the Rust API exposes equivalent data.
- The Rust core evaluates at most the first 100 characters. Supplying a larger
  `max_length` does not change that core safety limit.

## Local development

```bash
cd bindings/python
python3 -m pip install -U maturin
maturin develop
python3 -c "from zxcvbn_rs import zxcvbn; print(zxcvbn('correcthorsebatterystaple'))"
```

## Build wheels

```bash
cd bindings/python
maturin build --release
```

## Run Python tests

After installing the built wheel (or running `maturin develop`):

```bash
cd bindings/python
python3 -m unittest discover -s tests -p "test_*.py"
```
