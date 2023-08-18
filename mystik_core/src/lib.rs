use num_cpus;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use regex::bytes::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use walkdir::WalkDir;


#[pyclass]
struct SearchResult {
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
    matches: Vec<SearchMatch>
}


#[pyclass]
#[derive(Clone)]
struct SearchMatch {
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


// We use a temporary
struct TemporaryMatch {
    uuid: String,
    file_name: String,
    pattern: String,
    pattern_tag: String,
    groups: Vec<Vec<u8>>,
    capture: Vec<u8>,
    capture_start: usize,
    capture_end: usize,
    context: Vec<u8>,
    context_start: usize,
    context_end: usize,
}


#[pyfunction]
fn recursive_regex_search(py: Python, path: &str, patterns: Vec<(String, &PyBytes)>, desired_context: Option<usize>, max_file_size: Option<usize>, max_threads: Option<usize>) -> PyResult<SearchResult> {
    // If any of the function arguments are left blank, we assign defaults here.
    let desired_context = desired_context.unwrap_or(128);
    let max_file_size = max_file_size.unwrap_or(0);
    let max_threads = max_threads.unwrap_or(num_cpus::get());

    // We compile each pattern and its tag into a vector.
    let regex_patterns: Vec<(String, Regex)> = patterns
        .iter()
        .map(|(tag, pattern)| (tag.clone(), Regex::new(from_utf8(pattern.as_bytes()).unwrap()).unwrap()))
        .collect();

    // We prepare some queues for us to use between threads.
    let (tx, rx) = channel::<TemporaryMatch>();
    let tx = Arc::new(Mutex::new(tx));

    // We initialize our thread pool.
    let mut thread_pool = Vec::new();

    // We keep some operation statistics.
    let mut total_files_scanned = 0;
    let mut total_directories_scanned = 0;
    let scan_started_at = SystemTime::now();

    // We start walking over all the files in the target path.
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            if entry.file_type().is_dir() {
                total_directories_scanned += 1;
            }

            continue;
        }

        total_files_scanned += 1;

        let tx = tx.clone();
        let path = entry.path().to_owned();
        let regex_patterns = regex_patterns.clone();

        let thread_handle = thread::spawn(move || {
            let mut file = File::open(&path).unwrap();

            // If the file is too big, we skip it.
            if max_file_size > 0 && file.metadata().unwrap().len() > max_file_size.try_into().unwrap() {
                return;
            }

            // We read the file's contents into memory for scanning.
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();

            // Time to iterate through our capture patterns!
            for (pattern_tag, pattern) in regex_patterns {
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
                    let mut groups: Vec<Vec<u8>> = Vec::new();

                    if capture.len() > 1 {
                        for index in 1..capture.len() {
                            let group = capture.get(index).unwrap();
                            groups.push(contents[group.start()..group.end()].to_vec());
                        }
                    }

                    // We can now acquire the lock and push our results back!
                    tx.lock().unwrap().send(TemporaryMatch {
                        uuid: Uuid::new_v4().to_string(),
                        file_name: path.display().to_string(),
                        pattern: pattern.as_str().to_string(),
                        pattern_tag: pattern_tag.clone(),
                        groups: groups,
                        capture: contents[full_match.start()..full_match.end()].to_vec(),
                        capture_start: full_match.start(),
                        capture_end: full_match.end(),
                        context: contents[context_start..context_end].to_vec(),
                        context_start: context_start,
                        context_end: context_end,
                    }).unwrap();
                }
            }
        });

        thread_pool.push(thread_handle);

        // If our thread count is too high, we just wait on one to exit.
        while thread_pool.len() >= max_threads {
            let thread = thread_pool.remove(0);
            thread.join().unwrap();
        }
    }

    // This waits for the queue to be released before dropping it; this is
    // just a fancy way to join the threads together.
    drop(tx);

    let scan_completed_at = SystemTime::now();

    // We iterate through the result queue and push those into an array.
    let mut search_matches = Vec::new();

    for match_obj in rx.iter() {
        let groups_as_bytes: Vec<Py<PyBytes>> = match_obj.groups
            .iter()
            .map(|group| PyBytes::new(py, group).into())
            .collect();

        search_matches.push(SearchMatch {
            uuid: match_obj.uuid,
            file_name: match_obj.file_name,
            pattern: match_obj.pattern,
            pattern_tag: match_obj.pattern_tag,
            groups: groups_as_bytes,
            capture: PyBytes::new(py, &match_obj.capture).into(),
            capture_start: match_obj.capture_start,
            capture_end: match_obj.capture_end,
            context: PyBytes::new(py, &match_obj.context).into(),
            context_start: match_obj.context_start,
            context_end: match_obj.context_end
        })
    }

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
