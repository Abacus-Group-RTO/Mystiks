use num_cpus;
use pyo3::prelude::*;
use pyo3::PyObject;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::exceptions::{PyIOError, PyValueError, PyRuntimeError};
use pyo3::wrap_pyfunction;
use rayon::prelude::*;
use regex::bytes::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use walkdir::WalkDir;


#[pyclass]
pub struct SearchResult {
    #[pyo3(get, set)]
    uuid: String,
    #[pyo3(get, set)]
    scan_started_at: u64,
    #[pyo3(get, set)]
    scan_completed_at: u64,
    #[pyo3(get, set)]
    total_files_scanned: usize,
    #[pyo3(get, set)]
    total_directories_scanned: usize,
    #[pyo3(get, set)]
    matches: Vec<Py<SearchMatch>>
}


#[pyclass]
#[derive(Clone)]
pub struct SearchMatch {
    #[pyo3(get, set)]
    uuid: String,
    #[pyo3(get, set)]
    file_name: String,
    #[pyo3(get, set)]
    pattern: String,
    #[pyo3(get, set)]
    pattern_tag: String,
    #[pyo3(get, set)]
    groups: Vec<Py<PyBytes>>,
    #[pyo3(get, set)]
    capture: Py<PyBytes>,
    #[pyo3(get, set)]
    capture_start: usize,
    #[pyo3(get, set)]
    capture_end: usize,
    #[pyo3(get, set)]
    context: Py<PyBytes>,
    #[pyo3(get, set)]
    context_start: usize,
    #[pyo3(get, set)]
    context_end: usize,
}


fn compile_patterns(patterns: Vec<(String, String, Option<PyObject>)>) -> Result<Vec<(String, Regex, Option<PyObject>)>, PyErr> {
    // We compile each pattern and its tag into a vector.
    let mut regex_patterns: Vec<(String, Regex, Option<PyObject>)> = Vec::new();

    for (tag, pattern, filter) in patterns {
        // We attempt to convert the byte string into a valid pattern, and if
        // that fails, we raise a value error.
        let byte_pattern = Regex::new(&pattern).map_err(|error| {
            PyErr::new::<PyValueError, _>(format!("Failed to compile pattern: {}", error))
        })?;

        regex_patterns.push((tag, byte_pattern, filter));
    }

    Ok::<Vec<(String, Regex, Option<PyObject>)>, _>(regex_patterns)
}


#[pyfunction]
fn recursive_regex_search(py: Python, path: &str, patterns: Vec<(String, String, Option<PyObject>)>, desired_context: Option<usize>, max_file_size: Option<usize>, max_threads: Option<usize>, skip_symlinks: Option<bool>) -> PyResult<SearchResult> {
    // If any of the function arguments are left blank, we assign defaults here.
    let desired_context: usize = desired_context.unwrap_or(128);
    let max_file_size: usize = max_file_size.unwrap_or(0);
    let max_threads: usize = max_threads.unwrap_or(num_cpus::get());
    let skip_symlinks: bool = skip_symlinks.unwrap_or(false);

    let regex_patterns = Arc::new(compile_patterns(patterns)?);

    // We prepare some channels for us to use between threads.
    let (match_sender, match_receiver) = channel();
    let match_sender = Arc::new(Mutex::new(match_sender));

    let (error_sender, error_receiver) = channel();
    let error_sender = Arc::new(Mutex::new(error_sender));

    // We keep some operation statistics.
    let total_files_scanned = Arc::new(Mutex::new(0));
    let total_directories_scanned = Arc::new(Mutex::new(0));
    let scan_started_at = SystemTime::now();

    let pool = rayon::ThreadPoolBuilder::new().num_threads(max_threads).build().unwrap();

    // We begin executing inside the context of our thread pool.
    py.allow_threads(|| {
        pool.install(|| {
            WalkDir::new(path).into_iter().filter_map(|e| e.ok()).par_bridge().for_each(|entry| {
                let file_type = entry.file_type();

                if file_type.is_symlink() && skip_symlinks {
                    return;
                } else if !file_type.is_file() {
                    if file_type.is_dir() {
                        *total_directories_scanned.lock().unwrap() += 1;
                    }

                    return;
                }

                // If we've made it this far, the entry is a file.
                *total_files_scanned.lock().unwrap() += 1;

                // We can move onto reading the file.
                let path = entry.path();

                // We open the file for reading, or error if we can't.
                let file_open_result = File::open(&path);

                if file_open_result.is_err() {
                    let _ = error_sender.lock().unwrap().send(PyErr::new::<PyIOError, _>(format!("Failed to open file: {}", path.display())));
                    return;
                }

                let mut file = file_open_result.unwrap();

                // Next, we try to check for the file's metadata.
                let file_metadata_result = file.metadata();

                if file_metadata_result.is_err() {
                    let _ = error_sender.lock().unwrap().send(PyErr::new::<PyIOError, _>(format!("Failed to get file metadata: {}", path.display())));
                    return;
                }

                let file_metadata = file_metadata_result.unwrap();

                // If the file is too big, we skip it.
                if max_file_size > 0 && file_metadata.len() > max_file_size.try_into().unwrap() {
                    return;
                }

                // We read the file's contents into memory for scanning.
                let mut contents = Vec::new();

                if file.read_to_end(&mut contents).is_err() {
                    let _ = error_sender.lock().unwrap().send(PyErr::new::<PyIOError, _>(format!("Failed to read the file: {}", path.display())));
                    return;
                }

                // Time to iterate through our capture patterns!
                for (pattern_tag, pattern, filter) in regex_patterns.iter() {
                    for capture in pattern.captures_iter(&contents) {
                        let full_match = capture.get(0).unwrap();

                        // We make sure that the correct amount of context is stored.
                        let mut context_start = 0;

                        if full_match.start() > desired_context {
                            context_start = full_match.start() - desired_context;
                        }

                        let mut context_end = contents.len();

                        if context_end > full_match.end() + desired_context {
                            context_end = full_match.end() + desired_context;
                        }

                        // We store each capture group.
                        let mut groups: Vec<Py<PyBytes>> = Vec::new();

                        if capture.len() > 1 {
                            for index in 1..capture.len() {
                                let group = capture.get(index).unwrap();
                                groups.push(Python::with_gil(|py| PyBytes::new(py, &contents[group.start()..group.end()]).into()));
                            }
                        }

                        // We setup our capture and context values.
                        let capture = contents[full_match.start()..full_match.end()].to_vec();
                        let context = contents[context_start..context_end].to_vec();

                        let match_obj = Python::with_gil(|py| {
                            Py::new(py, SearchMatch {
                                uuid: Uuid::new_v4().to_string(),
                                file_name: path.display().to_string(),
                                pattern: pattern.as_str().to_string(),
                                pattern_tag: pattern_tag.to_string(),
                                groups: groups,
                                capture: PyBytes::new(py, &capture).into(),
                                capture_start: full_match.start(),
                                capture_end: full_match.end(),
                                context: PyBytes::new(py, &context).into(),
                                context_start: context_start,
                                context_end: context_end,
                            })
                        }).unwrap();

                        if filter.is_some() {
                            let filter = filter.clone().unwrap();

                            // We try to get a return value from the filter here,
                            // but if the filter fails, we handle that next.
                            let filter_result: Result<bool, PyErr> = Python::with_gil(|py| {
                                let args = PyTuple::new(py, &[match_obj.clone()]);
                                let value: bool = filter.call1(py, args)?.extract(py)?;

                                Ok::<bool, _>(value)
                            });

                            if filter_result.is_err() {
                                let _ = error_sender.lock().unwrap().send(PyErr::new::<PyRuntimeError, _>(format!("Failed to filter the finding: {}", pattern_tag.to_string())));
                                return;
                            }

                            // Technically, this conversion can fail. However, if done
                            // correctly, it will never fail. Only developers can
                            // introduce a crash here.
                            let is_filtered: bool = filter_result.unwrap();

                            if is_filtered {
                                return;
                            }
                        }

                        // We can now acquire the lock and push our results back!
                        match_sender.lock().unwrap().send(match_obj).unwrap();
                    }
                }
            });
        });
    });

    drop(match_sender);
    drop(error_sender);

    // If something exploded mid-search, we raise that error here.
    if let Ok(error) = error_receiver.try_recv() {
        return Err(error);
    }

    let scan_completed_at = SystemTime::now();

    // We iterate through the result queue and push those into an array.
    let search_matches = match_receiver.iter().collect();
    let total_files_scanned = *total_files_scanned.lock().unwrap();
    let total_directories_scanned = *total_directories_scanned.lock().unwrap();

    Ok(SearchResult {
        uuid: Uuid::new_v4().to_string(),
        scan_started_at: scan_started_at.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        scan_completed_at: scan_completed_at.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        total_files_scanned: total_files_scanned,
        total_directories_scanned: total_directories_scanned,
        matches: search_matches,
    })
}


#[pymodule]
fn mystik_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(recursive_regex_search, m)?)?;
    m.add_class::<SearchMatch>()?;

    Ok(())
}
