use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use log::{error, info};

use crate::cli::Cli;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MatchRecord {
    pub source: String,
    pub kind: String,
    pub matched: String,
    pub line: usize,
    pub col: usize,
    pub entropy: Option<f64>,
    pub context: String,
    pub identifier: Option<String>,
}

impl MatchRecord {
    pub fn fingerprint(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.source.hash(&mut hasher);
        self.kind.hash(&mut hasher);
        self.matched.hash(&mut hasher);
        self.line.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub ignored_fingerprints: Vec<String>,
}

pub enum OutputMode {
    None,
    Single(Arc<Mutex<Vec<MatchRecord>>>),
    Ndjson(Arc<Mutex<File>>),
    PerFile(PathBuf),
    Story(Arc<Mutex<Vec<MatchRecord>>>, PathBuf),
    Sarif(Arc<Mutex<Vec<MatchRecord>>>, PathBuf),
    Csv(Arc<Mutex<Vec<MatchRecord>>>, PathBuf),
    Junit(Arc<Mutex<Vec<MatchRecord>>>, PathBuf),
}

pub fn build_output_mode(cli: &Cli) -> OutputMode {
    if let Some(path) = &cli.output {
        match cli.output_format.as_str() {
            "ndjson" => match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => OutputMode::Ndjson(Arc::new(Mutex::new(f))),
                Err(e) => {
                    error!("Failed to open NDJSON output {}: {}", path, e);
                    OutputMode::None
                }
            },
            "sarif" => OutputMode::Sarif(Arc::new(Mutex::new(Vec::new())), PathBuf::from(path)),
            "csv" => OutputMode::Csv(Arc::new(Mutex::new(Vec::new())), PathBuf::from(path)),
            "junit" => OutputMode::Junit(Arc::new(Mutex::new(Vec::new())), PathBuf::from(path)),
            "per-file" => {
                let dir = PathBuf::from(path);
                if let Err(e) = fs::create_dir_all(&dir) {
                    error!("Failed to create output directory {}: {}", path, e);
                    OutputMode::None
                } else {
                    OutputMode::PerFile(dir)
                }
            }
            "story" => OutputMode::Story(Arc::new(Mutex::new(Vec::new())), PathBuf::from(path)),
            _ => OutputMode::Single(Arc::new(Mutex::new(Vec::new()))),
        }
    } else {
        OutputMode::None
    }
}

pub fn handle_output(
    output_mode: &OutputMode,
    cli: &Cli,
    out: &str,
    recs: Vec<MatchRecord>,
    source_path: Option<&Path>,
    source_label: &str,
) {
    match output_mode {
        OutputMode::Single(col)
        | OutputMode::Story(col, _)
        | OutputMode::Sarif(col, _)
        | OutputMode::Csv(col, _)
        | OutputMode::Junit(col, _) => {
            if !recs.is_empty() {
                if let Ok(mut guard) = col.lock() {
                    guard.extend(recs.into_iter());
                }
            }
        }
        OutputMode::Ndjson(file) => {
            if !recs.is_empty() {
                if let Ok(mut guard) = file.lock() {
                    for rec in recs {
                        if let Ok(line) = serde_json::to_string(&rec) {
                            let _ = guard.write_all(line.as_bytes());
                            let _ = guard.write_all(b"\n");
                        }
                    }
                }
            }
        }
        OutputMode::PerFile(dir) => {
            if !recs.is_empty() {
                let outpath = per_file_path(dir, source_path, source_label);
                if let Ok(mut f) = File::create(&outpath) {
                    if let Ok(j) = serde_json::to_string_pretty(&recs) {
                        let _ = f.write_all(j.as_bytes());
                    }
                }
            }
        }
        OutputMode::None => {
            if cli.json {
                if !recs.is_empty() {
                    match serde_json::to_string_pretty(&recs) {
                        Ok(j) => println!("{}", j),
                        Err(e) => error!("Failed to serialize JSON output: {}", e),
                    }
                }
            } else if !out.is_empty() {
                use std::io::stdout;
                let _lock = stdout().lock();
                println!("{}", out);
            }
        }
    }
}

pub fn load_baseline(path: &str) -> Option<Baseline> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn filter_baseline(records: Vec<MatchRecord>, baseline: &Baseline) -> Vec<MatchRecord> {
    let ignored: std::collections::HashSet<_> = baseline.ignored_fingerprints.iter().collect();
    records
        .into_iter()
        .filter(|r| !ignored.contains(&r.fingerprint()))
        .collect()
}

pub fn generate_baseline(records: &[MatchRecord], path: &str) -> std::io::Result<()> {
    let fingerprints = records.iter().map(|r| r.fingerprint()).collect();
    let baseline = Baseline {
        ignored_fingerprints: fingerprints,
    };
    let json = serde_json::to_string_pretty(&baseline)?;
    fs::write(path, json)
}

pub fn finalize_output(output_mode: &OutputMode, cli: &Cli) {
    if let Some(path) = &cli.output {
        match output_mode {
            OutputMode::Single(col) => match col.lock() {
                Ok(guard) => {
                    let mut records = guard.clone();
                    if let Some(baseline_path) = &cli.baseline {
                        if let Some(baseline) = load_baseline(baseline_path) {
                            records = filter_baseline(records, &baseline);
                        }
                    }

                    if let Some(gen_path) = &cli.generate_baseline {
                        let _ = generate_baseline(&records, gen_path);
                    }

                    if records.is_empty() {
                        info!("No matches found; not writing output file {}", path);
                    } else {
                        match serde_json::to_string_pretty(&records) {
                            Ok(j) => match fs::write(path, j) {
                                Ok(()) => info!("Wrote JSON output to {}", path),
                                Err(e) => error!("Failed to write JSON to {}: {}", path, e),
                            },
                            Err(e) => error!("Failed to serialize JSON output: {}", e),
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write output file: {}", e),
            },
            OutputMode::Story(col, outpath) => match col.lock() {
                Ok(guard) => {
                    let mut records = guard.clone();
                    if let Some(baseline_path) = &cli.baseline {
                        if let Some(baseline) = load_baseline(baseline_path) {
                            records = filter_baseline(records, &baseline);
                        }
                    }

                    if let Some(gen_path) = &cli.generate_baseline {
                        let _ = generate_baseline(&records, gen_path);
                    }

                    if records.is_empty() {
                        info!(
                            "No matches found; not writing story output {}",
                            outpath.display()
                        );
                    } else {
                        let report = build_story_report(&records);
                        match fs::write(outpath, report) {
                            Ok(()) => info!("Wrote story output to {}", outpath.display()),
                            Err(e) => {
                                error!("Failed to write story to {}: {}", outpath.display(), e)
                            }
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write story output: {}", e),
            },
            OutputMode::Sarif(col, outpath) => match col.lock() {
                Ok(guard) => {
                    let mut records = guard.clone();
                    if let Some(baseline_path) = &cli.baseline {
                        if let Some(baseline) = load_baseline(baseline_path) {
                            records = filter_baseline(records, &baseline);
                        }
                    }

                    if let Some(gen_path) = &cli.generate_baseline {
                        let _ = generate_baseline(&records, gen_path);
                    }

                    if records.is_empty() {
                        info!(
                            "No matches found; not writing SARIF output {}",
                            outpath.display()
                        );
                    } else {
                        let report = build_sarif_report(&records);
                        match fs::write(outpath, report) {
                            Ok(()) => info!("Wrote SARIF output to {}", outpath.display()),
                            Err(e) => {
                                error!("Failed to write SARIF to {}: {}", outpath.display(), e)
                            }
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write SARIF output: {}", e),
            },
            OutputMode::Csv(col, outpath) => match col.lock() {
                Ok(guard) => {
                    let mut records = guard.clone();
                    if let Some(baseline_path) = &cli.baseline {
                        if let Some(baseline) = load_baseline(baseline_path) {
                            records = filter_baseline(records, &baseline);
                        }
                    }

                    if let Some(gen_path) = &cli.generate_baseline {
                        let _ = generate_baseline(&records, gen_path);
                    }

                    if records.is_empty() {
                        info!(
                            "No matches found; not writing CSV output {}",
                            outpath.display()
                        );
                    } else {
                        let report = build_csv_report(&records);
                        match fs::write(outpath, report) {
                            Ok(()) => info!("Wrote CSV output to {}", outpath.display()),
                            Err(e) => {
                                error!("Failed to write CSV to {}: {}", outpath.display(), e)
                            }
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write CSV output: {}", e),
            },
            OutputMode::Junit(col, outpath) => match col.lock() {
                Ok(guard) => {
                    let mut records = guard.clone();
                    if let Some(baseline_path) = &cli.baseline {
                        if let Some(baseline) = load_baseline(baseline_path) {
                            records = filter_baseline(records, &baseline);
                        }
                    }

                    if let Some(gen_path) = &cli.generate_baseline {
                        let _ = generate_baseline(&records, gen_path);
                    }

                    if records.is_empty() {
                        info!(
                            "No matches found; not writing JUnit output {}",
                            outpath.display()
                        );
                    } else {
                        let report = build_junit_report(&records);
                        match fs::write(outpath, report) {
                            Ok(()) => info!("Wrote JUnit output to {}", outpath.display()),
                            Err(e) => {
                                error!("Failed to write JUnit to {}: {}", outpath.display(), e)
                            }
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write JUnit output: {}", e),
            },
            OutputMode::Ndjson(_) => {
                info!("NDJSON output written incrementally to {}", path);
            }
            OutputMode::PerFile(_) => {
                info!("Per-file JSON output written to directory {}", path);
            }
            OutputMode::None => {
                if let Some(_gen_path) = &cli.generate_baseline {
                    // This is tricky because records are printed to stdout in 'None' mode.
                    // For now, let's assume 'None' mode doesn't support generate_baseline easily
                    // unless we collect them.
                }
            }
        }
    } else {
        // Handle case where --generate-baseline is used without --output
        if let Some(gen_path) = &cli.generate_baseline {
            match output_mode {
                OutputMode::Single(col)
                | OutputMode::Story(col, _)
                | OutputMode::Sarif(col, _)
                | OutputMode::Csv(col, _)
                | OutputMode::Junit(col, _) => {
                    if let Ok(guard) = col.lock() {
                        let mut records = guard.clone();
                        if let Some(baseline_path) = &cli.baseline {
                            if let Some(baseline) = load_baseline(baseline_path) {
                                records = filter_baseline(records, &baseline);
                            }
                        }
                        let _ = generate_baseline(&records, gen_path);
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn build_sarif_report(records: &[MatchRecord]) -> String {
    let mut results = Vec::new();
    for rec in records {
        results.push(serde_json::json!({
            "ruleId": rec.kind,
            "message": {
                "text": format!("Found {} match: {}", rec.kind, rec.matched)
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rec.source
                        },
                        "region": {
                            "startLine": rec.line,
                            "startColumn": rec.col
                        }
                    }
                }
            ],
            "properties": {
                "entropy": rec.entropy,
                "identifier": rec.identifier
            }
        }));
    }

    let sarif = serde_json::json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "argus",
                        "informationUri": "https://github.com/google/argus",
                        "rules": []
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

pub fn build_story_report(records: &[MatchRecord]) -> String {
    let mut out = String::new();
    let mut grouped: std::collections::BTreeMap<String, Vec<&MatchRecord>> =
        std::collections::BTreeMap::new();
    for rec in records {
        grouped.entry(rec.source.clone()).or_default().push(rec);
    }

    out.push_str("# argus Story Mode\n\n");
    out.push_str(&format!("Total findings: {}\n\n", records.len()));

    for (source, mut recs) in grouped {
        recs.sort_by_key(|r| r.line);
        out.push_str(&format!("## {}\n\n", source));
        for rec in recs {
            let line = if rec.line > 0 {
                format!("L{}", rec.line)
            } else {
                "".to_string()
            };
            out.push_str(&format!("- **{}** {} — {}\n", rec.kind, line, rec.matched));
            if !rec.context.is_empty() {
                let ctx = rec.context.replace('\n', " ");
                out.push_str(&format!("  - Context: {}\n", ctx));
            }
        }
        out.push('\n');
    }

    out
}

pub fn build_csv_report(records: &[MatchRecord]) -> String {
    let mut out = String::from("source,line,col,kind,matched,entropy,identifier,context\n");
    for rec in records {
        let entropy = rec.entropy.map(|e| e.to_string()).unwrap_or_default();
        let identifier = rec.identifier.as_deref().unwrap_or_default();
        // Simple escaping for context and matched (replace double quotes with two double quotes and wrap in quotes)
        let source = format!("\"{}\"", rec.source.replace('"', "\"\""));
        let matched = format!("\"{}\"", rec.matched.replace('"', "\"\""));
        let context = format!("\"{}\"", rec.context.replace('"', "\"\""));
        let kind = format!("\"{}\"", rec.kind.replace('"', "\"\""));
        let ident = format!("\"{}\"", identifier.replace('"', "\"\""));

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            source, rec.line, rec.col, kind, matched, entropy, ident, context
        ));
    }
    out
}

pub fn build_junit_report(records: &[MatchRecord]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<testsuites>\n");
    out.push_str(&format!(
        "  <testsuite name=\"argus\" tests=\"{}\">\n",
        records.len()
    ));

    for rec in records {
        let matched_esc = rec
            .matched
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");
        let source_esc = rec
            .source
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");
        let context_esc = rec
            .context
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");

        out.push_str(&format!(
            "    <testcase name=\"{}\" classname=\"{}\" file=\"{}\" line=\"{}\">\n",
            rec.kind, source_esc, source_esc, rec.line
        ));
        out.push_str(&format!(
            "      <failure message=\"Secret detected: {}\">",
            matched_esc
        ));
        out.push_str(&format!(
            "Kind: {}, Entropy: {:?}, Identifier: {:?}\nContext: {}",
            rec.kind, rec.entropy, rec.identifier, context_esc
        ));
        out.push_str("</failure>\n");
        out.push_str("    </testcase>\n");
    }

    out.push_str("  </testsuite>\n");
    out.push_str("</testsuites>\n");
    out
}

fn per_file_path(dir: &Path, source_path: Option<&Path>, source_label: &str) -> PathBuf {
    let mut outpath = dir.to_path_buf();
    if let Some(path) = source_path {
        if let Some(name) = path.file_name() {
            outpath.push(name);
            outpath.set_extension("json");
            return outpath;
        }
    }

    if let Some(name) = Path::new(source_label).file_name() {
        outpath.push(name);
        outpath.set_extension("json");
    } else {
        outpath.push("output.json");
    }
    outpath
}
