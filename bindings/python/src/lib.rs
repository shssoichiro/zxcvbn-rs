use ::zxcvbn::time_estimates::CrackTimeSeconds;
use ::zxcvbn::{zxcvbn as zxcvbn_core, Match, feedback::Warning};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pythonize::pythonize;
use serde::Serialize;

#[derive(Serialize)]
struct CrackTimesSecondsOut {
    online_throttling_100_per_hour: f64,
    online_no_throttling_10_per_second: f64,
    offline_slow_hashing_1e4_per_second: f64,
    offline_fast_hashing_1e10_per_second: f64,
}

#[derive(Serialize)]
struct CrackTimesDisplayOut {
    online_throttling_100_per_hour: String,
    online_no_throttling_10_per_second: String,
    offline_slow_hashing_1e4_per_second: String,
    offline_fast_hashing_1e10_per_second: String,
}

#[derive(Serialize)]
struct FeedbackOut {
    warning: String,
    suggestions: Vec<String>,
}

#[derive(Serialize)]
struct ZxcvbnResultOut {
    password: String,
    guesses: u64,
    guesses_log10: f64,
    score: u8,
    feedback: FeedbackOut,
    sequence: Vec<Match>,
    calc_time: f64,
    crack_times_seconds: CrackTimesSecondsOut,
    crack_times_display: CrackTimesDisplayOut,
}

fn crack_time_to_f64(value: CrackTimeSeconds) -> f64 {
    match value {
        CrackTimeSeconds::Integer(v) => v as f64,
        CrackTimeSeconds::Float(v) => v,
    }
}

fn dictionary_name(name: &str) -> &str {
    match name {
        "Passwords" => "passwords",
        "English" => "english_wikipedia",
        "FemaleNames" => "female_names",
        "MaleNames" => "male_names",
        "Surnames" => "surnames",
        "UsTvAndFilm" => "us_tv_and_film",
        "UserInputs" => "user_inputs",
        _ => name,
    }
}

fn normalize_sequence(result: &Bound<'_, PyAny>) -> PyResult<()> {
    let result = result.downcast::<PyDict>()?;
    let sequence = result
        .get_item("sequence")?
        .ok_or_else(|| PyValueError::new_err("serialized result has no sequence"))?;
    for item in sequence.downcast::<PyList>()? {
        let item = item.downcast::<PyDict>()?;
        if let Some(name) = item.get_item("dictionary_name")? {
            let name = name.extract::<String>()?;
            item.set_item("dictionary_name", dictionary_name(&name))?;
        }
        for key in ["sub", "sub_display"] {
            if item.get_item(key)?.map_or(false, |value| value.is_none()) {
                item.del_item(key)?;
            }
        }
    }
    Ok(())
}

#[pyfunction(name = "zxcvbn", signature = (password, user_inputs=None, max_length=None))]
fn zxcvbn_py(
    py: Python<'_>,
    password: &str,
    user_inputs: Option<Vec<String>>,
    max_length: Option<usize>,
) -> PyResult<Py<PyAny>> {
    let password = password.to_owned();
    if let Some(limit) = max_length {
        if password.chars().count() > limit {
            return Err(PyValueError::new_err(format!(
                "Password exceeds max length of {limit} characters."
            )));
        }
    }

    let inputs = user_inputs.unwrap_or_default();
    let input_refs = inputs.iter().map(String::as_str).collect::<Vec<_>>();
    let entropy = py.allow_threads(|| zxcvbn_core(&password, &input_refs));
    let crack_times = entropy.crack_times();
    let t_online_throttling = crack_times.online_throttling_100_per_hour();
    let t_online_no_throttling = crack_times.online_no_throttling_10_per_second();
    let t_offline_slow = crack_times.offline_slow_hashing_1e4_per_second();
    let t_offline_fast = crack_times.offline_fast_hashing_1e10_per_second();

    let feedback = if let Some(feedback) = entropy.feedback() {
        FeedbackOut {
            warning: feedback
                .warning()
                .map(|value: Warning| value.to_string())
                .unwrap_or_default(),
            suggestions: feedback
                .suggestions()
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    } else {
        FeedbackOut {
            warning: String::new(),
            suggestions: Vec::new(),
        }
    };

    let response = ZxcvbnResultOut {
        password,
        guesses: entropy.guesses(),
        guesses_log10: if entropy.guesses_log10().is_finite() {
            entropy.guesses_log10()
        } else {
            0.0
        },
        score: u8::from(entropy.score()),
        feedback,
        sequence: entropy.sequence().to_vec(),
        calc_time: entropy.calculation_time().as_secs_f64() * 1000.0,
        crack_times_seconds: CrackTimesSecondsOut {
            online_throttling_100_per_hour: crack_time_to_f64(t_online_throttling),
            online_no_throttling_10_per_second: crack_time_to_f64(t_online_no_throttling),
            offline_slow_hashing_1e4_per_second: crack_time_to_f64(t_offline_slow),
            offline_fast_hashing_1e10_per_second: crack_time_to_f64(t_offline_fast),
        },
        crack_times_display: CrackTimesDisplayOut {
            online_throttling_100_per_hour: t_online_throttling.to_string(),
            online_no_throttling_10_per_second: t_online_no_throttling.to_string(),
            offline_slow_hashing_1e4_per_second: t_offline_slow.to_string(),
            offline_fast_hashing_1e10_per_second: t_offline_fast.to_string(),
        },
    };

    let py_obj = pythonize(py, &response)?;
    normalize_sequence(py_obj.bind(py))?;

    Ok(py_obj)
}

#[pymodule]
fn _zxcvbn_rs(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(zxcvbn_py, module)?)?;
    Ok(())
}
