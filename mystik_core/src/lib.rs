use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use regex::bytes::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use walkdir::WalkDir;
use std::cmp;
use num_cpus;


#[pyclass]
struct Match {
    #[pyo3(get, set)]
    file_name: String,
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
        Ok(format!("Match(file_name={}, capture={}, capture_start={}, capture_end={}, context={}, context_start={}, context_end={})", self.file_name, self.capture, self.capture_start, self.capture_end, self.context, self.context_start, self.context_end))
    }
}

#[pyfunction]
fn recursive_regex_search(path: &str, patterns: Vec<&str>) -> PyResult<Vec<Match>> {
    let mut matching_files = Vec::new();
    let regex_patterns: Vec<Regex> = patterns.iter().map(|pattern| Regex::new(pattern).unwrap()).collect();

    let (tx, rx) = channel::<Match>();
    let tx = Arc::new(Mutex::new(tx));

    let max_threads = num_cpus::get();
    let mut thread_pool = Vec::new();

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let tx = tx.clone();
        let path = entry.path().to_owned();
        let regex_patterns = regex_patterns.clone();

        let thread_handle = thread::spawn(move || {
            let mut file = File::open(&path).unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();

            for pattern in regex_patterns {
                for match_obj in pattern.find_iter(&contents) {
                    let context_start = cmp::max(0, match_obj.start() - 64);
                    let context_end = cmp::min(contents.len(), match_obj.end() + 64);

                    tx.lock().unwrap().send(Match {
                        file_name: path.display().to_string(),
                        capture_start: match_obj.start(),
                        capture_end: match_obj.end(),
                        capture: hex::encode(&contents[match_obj.start()..match_obj.end()]),
                        context: hex::encode(&contents[context_start..context_end]),
                        context_start: context_start,
                        context_end: context_end,
                    }).unwrap();
                }
            }
        });

        thread_pool.push(thread_handle);

        while thread_pool.len() >= max_threads {
            let completed_thread = thread_pool.remove(0);
            completed_thread.join().unwrap();
        }
    }

    drop(tx);

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
