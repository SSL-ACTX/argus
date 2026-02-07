#![cfg(feature = "python-ffi")]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use crate::cli::{Cli, OutputPersona};
use crate::output::MatchRecord;
use crate::scan::{build_exclude_matcher, is_excluded_path, run_analysis};

use ignore::WalkBuilder;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use tempfile::NamedTempFile;
use std::time::Duration;

const MAX_MMAP_SIZE: u64 = 200 * 1024 * 1024;

#[pyclass]
#[derive(Clone)]
pub struct PyMatchRecord {
    #[pyo3(get)]
    pub source: String,
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub matched: String,
    #[pyo3(get)]
    pub line: usize,
    #[pyo3(get)]
    pub col: usize,
    #[pyo3(get)]
    pub entropy: Option<f64>,
    #[pyo3(get)]
    pub context: String,
    #[pyo3(get)]
    pub identifier: Option<String>,
}

impl From<MatchRecord> for PyMatchRecord {
    fn from(rec: MatchRecord) -> Self {
        Self {
            source: rec.source,
            kind: rec.kind,
            matched: rec.matched,
            line: rec.line,
            col: rec.col,
            entropy: rec.entropy,
            context: rec.context,
            identifier: rec.identifier,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct ScanOptions {
    #[pyo3(get, set)]
    pub targets: Vec<String>,
    #[pyo3(get, set)]
    pub keywords: Vec<String>,
    #[pyo3(get, set)]
    pub entropy: bool,
    #[pyo3(get, set)]
    pub threshold: f64,
    #[pyo3(get, set)]
    pub context: usize,
    #[pyo3(get, set)]
    pub deep_scan: bool,
    #[pyo3(get, set)]
    pub flow_scan: bool,
    #[pyo3(get, set)]
    pub request_trace: bool,
    #[pyo3(get, set)]
    pub exclude: Vec<String>,
    #[pyo3(get, set)]
    pub confidence_floor: u8,
    #[pyo3(get, set)]
    pub expand: bool,
    #[pyo3(get, set)]
    pub mode: String,
    #[pyo3(get, set)]
    pub threads: usize,
}

#[pymethods]
impl ScanOptions {
    #[new]
    #[pyo3(signature = (
        targets,
        keywords = Vec::new(),
        entropy = false,
        threshold = 4.5,
        context = 80,
        deep_scan = false,
        flow_scan = false,
        request_trace = false,
        exclude = Vec::new(),
        confidence_floor = 0,
        expand = false,
        mode = "scan".to_string(),
        threads = 0
    ))]
    fn new(
        targets: Vec<String>,
        keywords: Vec<String>,
        entropy: bool,
        threshold: f64,
        context: usize,
        deep_scan: bool,
        flow_scan: bool,
        request_trace: bool,
        exclude: Vec<String>,
        confidence_floor: u8,
        expand: bool,
        mode: String,
        threads: usize,
    ) -> Self {
        Self {
            targets,
            keywords,
            entropy,
            threshold,
            context,
            deep_scan,
            flow_scan,
            request_trace,
            exclude,
            confidence_floor,
            expand,
            mode,
            threads,
        }
    }
}

#[pyclass]
pub struct ArgusScanner {
    options: ScanOptions,
}

#[pymethods]
impl ArgusScanner {
    #[new]
    fn new(options: ScanOptions) -> Self {
        Self { options }
    }

    pub fn scan(&self) -> PyResult<Vec<PyMatchRecord>> {
        let cli = build_cli(&self.options)?;
        let recs = scan_targets(&cli)?;
        Ok(recs.into_iter().map(PyMatchRecord::from).collect())
    }

    pub fn scan_json(&self) -> PyResult<String> {
        let cli = build_cli(&self.options)?;
        let recs = scan_targets(&cli)?;
        serde_json::to_string_pretty(&recs)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize results: {}", e)))
    }
}

#[pyfunction]
pub fn scan(options: ScanOptions) -> PyResult<Vec<PyMatchRecord>> {
    let cli = build_cli(&options)?;
    let recs = scan_targets(&cli)?;
    Ok(recs.into_iter().map(PyMatchRecord::from).collect())
}

#[pyfunction]
pub fn scan_json(options: ScanOptions) -> PyResult<String> {
    let cli = build_cli(&options)?;
    let recs = scan_targets(&cli)?;
    serde_json::to_string_pretty(&recs)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize results: {}", e)))
}

#[pymodule]
fn argus_ffi(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ScanOptions>()?;
    m.add_class::<ArgusScanner>()?;
    m.add_class::<PyMatchRecord>()?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(scan_json, m)?)?;
    Ok(())
}

fn build_cli(options: &ScanOptions) -> PyResult<Cli> {
    if options.targets.is_empty() {
        return Err(PyValueError::new_err("targets must not be empty"));
    }
    if options.keywords.is_empty() && !options.entropy {
        return Err(PyValueError::new_err("provide at least one keyword or enable entropy"));
    }
    let mode = match options.mode.to_lowercase().as_str() {
        "debug" | "loud" => OutputPersona::Debug,
        _ => OutputPersona::Scan,
    };

    Ok(Cli {
        target: options.targets.clone(),
        keyword: options.keywords.clone(),
        entropy: options.entropy,
        threshold: options.threshold,
        context: options.context,
        threads: options.threads,
        json: true,
        output: None,
        no_color: true,
        output_format: "single".to_string(),
        exclude: options.exclude.clone(),
        emit_tags: None,
        deep_scan: options.deep_scan,
        flow_scan: options.flow_scan,
        request_trace: options.request_trace,
        suppress: None,
        suppress_out: None,
        suppression_audit: false,
        diff: false,
        diff_base: "HEAD".to_string(),
        mode,
        quiet: matches!(mode, OutputPersona::Scan),
        loud: matches!(mode, OutputPersona::Debug),
        confidence_floor: options.confidence_floor,
        expand: options.expand,
    })
}

fn scan_targets(cli: &Cli) -> PyResult<Vec<MatchRecord>> {
    let mut out: Vec<MatchRecord> = Vec::new();
    let exclude_matcher = build_exclude_matcher(&cli.exclude);

    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(5))
        .build();

    for target in &cli.target {
        if target.starts_with("http") {
            let response = agent
                .get(target)
                .call()
                .map_err(|e| PyValueError::new_err(format!("HTTP error fetching {}: {}", target, e)))?;
            let mut tmp = NamedTempFile::new()
                .map_err(|e| PyValueError::new_err(format!("Temp file error: {}", e)))?;
            std::io::copy(&mut response.into_reader(), &mut tmp)
                .map_err(|e| PyValueError::new_err(format!("Stream error: {}", e)))?;

            let file = tmp.as_file();
            let mmap = unsafe { Mmap::map(file) }
                .map_err(|e| PyValueError::new_err(format!("mmap failed: {}", e)))?;

            let (_out, recs) = run_analysis(
                target,
                &mmap,
                cli,
                None,
                Some(target),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
            out.extend(recs);
            continue;
        }

        let walker = WalkBuilder::new(target)
            .hidden(false)
            .git_ignore(true)
            .build();

        for result in walker {
            let entry = match result {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if is_excluded_path(path, &exclude_matcher) {
                continue;
            }

            let metadata = match path.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() == 0 || metadata.len() > MAX_MMAP_SIZE {
                continue;
            }

            if let Ok(mut file) = File::open(path) {
                let mut peek = [0u8; 1024];
                if let Ok(n) = file.read(&mut peek) {
                    if n > 0 && peek[..n].contains(&0) {
                        continue;
                    }
                }

                let mmap = match unsafe { Mmap::map(&file) } {
                    Ok(mmap) => mmap,
                    Err(_) => continue,
                };

                let source_label = path.to_string_lossy().to_string();
                let (_out, recs) = run_analysis(
                    &source_label,
                    &mmap,
                    cli,
                    Some(path),
                    Some(&source_label),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                out.extend(recs);
            }
        }
    }

    Ok(out)
}