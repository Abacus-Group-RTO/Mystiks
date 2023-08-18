use base64::{Engine as _, engine::general_purpose};
use num_cpus;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use regex::bytes::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;
use uuid::Uuid;
use walkdir::WalkDir;


#[pyclass]
struct Match {
    #[pyo3(get, set)]
    uuid: String,
    #[pyo3(get, set)]
    file_name: String,
    #[pyo3(get, set)]
    pattern: String,
    #[pyo3(get, set)]
    pattern_name: String,
    #[pyo3(get, set)]
    groups: Vec<String>,
    #[pyo3(get, set)]
    capture: String,
    #[pyo3(get, set)]
    capture_start: usize,
    #[pyo3(get, set)]
    capture_end: usize,
    #[pyo3(get, set)]
    context: String,
    #[pyo3(get, set)]
    context_start: usize,
    #[pyo3(get, set)]
    context_end: usize,
}


#[pymethods]
impl Match {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Match(file_name={}, capture={}, pattern_name={}, capture_start={}, capture_end={}, context={}, context_start={}, context_end={})",
            self.file_name, self.capture, self.pattern_name, self.capture_start, self.capture_end, self.context, self.context_start, self.context_end))
    }
}


#[pyfunction]
fn recursive_regex_search(path: &str, patterns: Vec<(String, &str)>, desired_context: usize, max_file_size: usize) -> PyResult<Vec<Match>> {
    let regex_patterns: Vec<(String, Regex)> = patterns
        .iter()
        .map(|(name, pattern)| (name.clone(), Regex::new(pattern).unwrap()))
        .collect();

    let (tx, rx) = channel::<Match>();
    let tx = Arc::new(Mutex::new(tx));

    let max_threads = num_cpus::get();
    let mut thread_pool = Vec::new();

    // We start walking over all the files in the target path.
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let tx = tx.clone();
        let path = entry.path().to_owned();
        let regex_patterns = regex_patterns.clone();

        let thread_handle = thread::spawn(move || {
            let mut file = File::open(&path).unwrap();

            // If the file is too big, we skip it.
            if file.metadata().unwrap().len() > max_file_size.try_into().unwrap() {
                return;
            }

            // We read the file's contents into memory for scanning.
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();

            // Time to iterate through our capture patterns!
            for (pattern_name, pattern) in regex_patterns {
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
                    let mut groups: Vec<String> = Vec::new();

                    if capture.len() > 1 {
                        for index in 1..capture.len() {
                            let group = capture.get(index).unwrap();
                            groups.push(general_purpose::STANDARD.encode(&contents[group.start()..group.end()]));
                        }
                    }

                    // We can now acquire the lock and push our results back!
                    tx.lock().unwrap().send(Match {
                        uuid: Uuid::new_v4().to_string(),
                        file_name: path.display().to_string(),
                        pattern: pattern.as_str().to_string(),
                        pattern_name: pattern_name.clone(),
                        groups: groups,
                        capture: general_purpose::STANDARD.encode(&contents[full_match.start()..full_match.end()]),
                        capture_start: full_match.start(),
                        capture_end: full_match.end(),
                        context: general_purpose::STANDARD.encode(&contents[context_start..context_end]),
                        context_start: context_start,
                        context_end: context_end,
                    }).unwrap();
                }
            }
        });

        thread_pool.push(thread_handle);

        // If our thread count is too high, we just wait on one to exit.
        while thread_pool.len() >= max_threads {
            let completed_thread = thread_pool.remove(0);
            completed_thread.join().unwrap();
        }
    }

    drop(tx);

    // We iterate through the result queue and push those into an array.
    let mut matching_files = Vec::new();

    for match_obj in rx.iter() {
        matching_files.push(match_obj);
    }

    Ok(matching_files)
}


#[pymodule]
fn mystik_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(recursive_regex_search, m)?)?;
    m.add_class::<Match>()?;

    Ok(())
}
