# Mystiks
This is an experimental attempt to improve the traditional secret searching techniques. **Findings** are primarily a Regular Expression pattern, name, and description which is defined as a subclass of `Finding` in Python. These findings are then captured out of the target directory using an efficient Rust-based core before being passed back to Python, where each match is rated against **indicators**. Indicators are used to calculate **ratings**, which are used to determine how likely or unlikely a match is to be correct.

## Command-Line Interface
```bash
usage: mystiks [-h] [-n NAME] [-o OUTPUT] [-l LIMIT] [-t THREADS] [-c CONTEXT] [-f FORMATS] [-u] path

Searches the given path for findings and outputs a report

positional arguments:
  path                  The path to search for findings in

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  The name of the report (Default: The target path's folder name)
  -o OUTPUT, --output OUTPUT
                        The path to save the report into (Default: Mystiks-<Report UUID>)
  -l LIMIT, --limit LIMIT
                        The maximum size a searchable file can be (Default: 500MB)
  -t THREADS, --threads THREADS
                        The amount of threads to use for searching (Default: Count of CPU cores)
  -c CONTEXT, --context CONTEXT
                        The amount of context to capture (Default: 128 bytes)
  -f FORMATS, --formats FORMATS
                        A comma-seperated list of formats to output (Default: HTML,JSON)
  -u, --utf16           Whether to search for UTF-16 strings (Default: Ignore UTF-16)
```

## Screenshots
![Mystiks Example2](images/Example2.png)
![Mystiks Example1](images/Example1.png)
