// main.rs
use aho_corasick::AhoCorasick;
use log::{error, info, warn};
use base64::{engine::general_purpose, Engine as _};
use env_logger;
use serde::Serialize;
use std::fmt::Write as FmtWrite;
use std::time::Duration;
use std::io::Read;
use clap::Parser;
use clap::CommandFactory;
use ignore::WalkBuilder;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::time::Instant;
use serde_json;
use tempfile::NamedTempFile;
use std::sync::{Arc, Mutex};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::path::PathBuf;

#[derive(Clone)]
enum OutputMode {
    None,
    Single(Arc<Mutex<Vec<MatchRecord>>>),
    Ndjson(Arc<Mutex<std::fs::File>>),
    PerFile(PathBuf),
}

#[derive(Parser)]
#[command(author = "Seuriin", version, about = "A high-performance, entropy-based secret scanner.", long_about = None)]
struct Cli {
    /// Target files, directories, or URLs
    #[arg(short, long)]
    target: Vec<String>,

    /// Keywords to find (supports multiple: -k token -k secret)
    #[arg(short, long)]
    keyword: Vec<String>,

    /// Enable Entropy Scanning (finds hidden keys/secrets automatically)
    #[arg(short, long)]
    entropy: bool,

    /// Minimum entropy threshold (0.0 - 8.0). Default 4.5 is good for base64 keys.
    #[arg(long, default_value_t = 4.5)]
    threshold: f64,

    /// Context window size
    #[arg(short, long, default_value_t = 80)]
    context: usize,

    /// Number of threads to use (0 = auto-detect logical cores)
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,
    /// Emit machine-readable JSON output
    #[arg(long)]
    json: bool,
    /// Write JSON output to a file
    #[arg(long)]
    output: Option<String>,
    /// Disable colorized output
    #[arg(long = "no-color")]
    no_color: bool,
    /// Output format: single | ndjson | per-file
    #[arg(long, default_value_t = String::from("single"))]
    output_format: String,
}

/// Calculates the Shannon Entropy (randomness) of a byte slice.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u32; 256];
    for &b in data {
        frequencies[b as usize] += 1;
    }

    let len = data.len() as f64;
    frequencies
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Checks if a string is valid Base64 that decodes to common readable text.
fn is_harmless_text(candidate: &str) -> bool {
    if candidate.contains(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '=') {
        return false;
    }

    if let Ok(decoded) = general_purpose::STANDARD.decode(candidate) {
        let readable_count = decoded
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        let ratio = readable_count as f64 / decoded.len() as f64;
        return ratio > 0.85;
    }

    false
}

/// Detects standard character sets (alphabets, digits) which have high entropy but are not secrets.
fn is_likely_charset(candidate: &str) -> bool {
    if candidate.contains("abcde")
        || candidate.contains("ABCDE")
        || candidate.contains("12345")
        || candidate.contains("vwxyz")
    {
        return true;
    }
    false
}

#[derive(Debug, Serialize)]
struct MatchRecord {
    source: String,
    kind: String,
    matched: String,
    line: usize,
    col: usize,
    entropy: Option<f64>,
    context: String,
    identifier: Option<String>,
}

/// Prettify and colorize a snippet; returns a String suitable for human output.
fn format_prettified(raw: &str, matched_word: &str) -> String {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut indentation = 0usize;
    for line in raw.split([';', '{', '}']) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let prefix = "  ".repeat(indentation + 1);
        let highlighted = trimmed.replace(matched_word, &matched_word.bold().bright_yellow().to_string());
        let _ = writeln!(out, "{}{}", prefix, highlighted);

        if raw.contains('{') {
            indentation += 1;
        }
        if raw.contains('}') {
            indentation = indentation.saturating_sub(1);
        }
    }
    out
}

/// Scans backwards from the secret's start position to find a variable name or key.
fn find_preceding_identifier(bytes: &[u8], start_index: usize) -> Option<String> {
    if start_index == 0 {
        return None;
    }

    let mut cursor = start_index - 1;
    let limit = start_index.saturating_sub(64);

    while cursor > limit {
        let b = bytes[cursor];
        if b == b'"' || b == b'\'' || b == b'`' || b.is_ascii_whitespace() {
            cursor -= 1;
        } else {
            break;
        }
    }

    let mut found_assignment = false;
    while cursor > limit {
        let b = bytes[cursor];
        if b == b'=' || b == b':' {
            found_assignment = true;
            cursor -= 1;
            break;
        } else if b.is_ascii_whitespace() {
            cursor -= 1;
        } else {
            return None;
        }
    }

    if !found_assignment {
        return None;
    }

    while cursor > limit && bytes[cursor].is_ascii_whitespace() {
        cursor -= 1;
    }

    let end_id = cursor + 1;
    while cursor > limit {
        let b = bytes[cursor];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'$' {
            cursor -= 1;
        } else {
            break;
        }
    }
    let start_id = cursor + 1;

    if start_id < end_id {
        let raw = String::from_utf8_lossy(&bytes[start_id..end_id]);
        let cleaned = raw.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if !cleaned.is_empty() {
            return Some(cleaned.to_string());
        }
    }

    None
}

fn scan_for_secrets(source_label: &str, bytes: &[u8], threshold: f64, context_size: usize) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
        let mut records: Vec<MatchRecord> = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    let min_len = 20;
    let max_len = 120;
    let mut _count = 0;

    for (i, &b) in bytes.iter().enumerate() {
        let is_secret_char = b.is_ascii_alphanumeric()
            || b == b'+'
            || b == b'/'
            || b == b'='
            || b == b'-'
            || b == b'_';

        if is_secret_char {
            if !in_word {
                start = i;
                in_word = true;
            }
        } else if in_word {
            in_word = false;
            let len = i - start;

            if len >= min_len && len <= max_len {
                let candidate_bytes = &bytes[start..i];
                let score = calculate_entropy(candidate_bytes);

                if score > threshold {
                    let snippet_str = String::from_utf8_lossy(candidate_bytes);

                    if is_harmless_text(&snippet_str) {
                        continue;
                    }
                    if is_likely_charset(&snippet_str) {
                        continue;
                    }

                    _count += 1;

                    let preceding = &bytes[..start];
                    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
                    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
                    let col = if last_nl == 0 { start } else { start - last_nl };

                    let ctx_start = start.saturating_sub(context_size);
                    let ctx_end = (i + context_size).min(bytes.len());
                    let raw_context = String::from_utf8_lossy(&bytes[ctx_start..ctx_end]);

                    let identifier = find_preceding_identifier(bytes, start);

                    let _ = write!(
                        out,
                        "{}[L:{} C:{} Entropy:{:.1}] ",
                        "[".dimmed(),
                        line.bright_magenta(),
                        col.bright_blue(),
                        score
                    );

                    if let Some(id) = identifier.clone() {
                        let _ = writeln!(out, "{} = {}", id.cyan().bold(), "SECRET_MATCH".red().bold());
                    } else {
                        let _ = writeln!(out, "{}", "Unassigned High-Entropy Block".red().bold());
                    }

                    // prettifier prints directly; capture its output by calling it and
                    // appending a simple snippet instead to keep output deterministic.
                    let pretty = format_prettified(&raw_context, &snippet_str);
                    let _ = writeln!(out, "{}", pretty);
                    let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

                    // record for JSON
                    records.push(MatchRecord {
                        source: source_label.to_string(),
                        kind: "entropy".to_string(),
                        matched: snippet_str.to_string(),
                        line,
                        col,
                        entropy: Some(score),
                        context: raw_context.to_string(),
                        identifier,
                    });
                }
            }
        }
    }

    (out, records)
}

fn process_search(bytes: &[u8], label: &str, keywords: &[String], context_size: usize) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();

    if keywords.is_empty() {
        return (out, records);
    }

    // Construct Aho-Corasick automaton for keyword matching.
    let ac = match AhoCorasick::new(keywords) {
        Ok(ac) => ac,
        Err(e) => {
            let _ = writeln!(out, "Warning: failed to build Aho-Corasick automaton: {}", e);
            return (out, records);
        }
    };

    // Perform the search first so we can buffer output per-file and avoid interleaving.
    let matches: Vec<_> = ac.find_iter(bytes).collect();

    if matches.is_empty() {
        return (out, records);
    }

    let _ = writeln!(out, "\n🔍 Scanning {} for {} patterns...", label.cyan(), keywords.len().yellow());
    let _ = writeln!(out, "{}", "━".repeat(60).dimmed());

    for mat in &matches {
        let pos = mat.start();
        let matched_word = &keywords[mat.pattern().as_usize()];

        let preceding = &bytes[..pos];
        let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
        let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
        let col = if last_nl == 0 { pos } else { pos - last_nl };

        let start = pos.saturating_sub(context_size);
        let end = (pos + mat.len() + context_size).min(bytes.len());
        let raw_snippet = String::from_utf8_lossy(&bytes[start..end]);

        let _ = writeln!(
            out,
            "{}[L:{} C:{} Match:{}]{}",
            "[".dimmed(),
            line.bright_magenta(),
            col.bright_blue(),
            matched_word.bright_yellow().bold(),
            "]".dimmed()
        );

        let pretty = format_prettified(&raw_snippet, matched_word);
        let _ = writeln!(out, "{}", pretty);
        let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

        // record for JSON output
        let identifier = find_preceding_identifier(bytes, pos);
        records.push(MatchRecord {
            source: label.to_string(),
            kind: "keyword".to_string(),
            matched: matched_word.to_string(),
            line,
            col,
            entropy: None,
            context: raw_snippet.to_string(),
            identifier,
        });
    }
    let _ = writeln!(out, "✨ Found {} keyword matches.", matches.len().green().bold());

    (out, records)
}

fn run_analysis(source_label: &str, bytes: &[u8], cli: &Cli) -> (String, Vec<MatchRecord>) {
    // Buffer per-file output to avoid interleaving when running in parallel.
    let mut file_output = String::new();

    let mut records: Vec<MatchRecord> = Vec::new();

    if !cli.keyword.is_empty() {
        let (s, mut r) = process_search(bytes, source_label, &cli.keyword, cli.context);
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if cli.entropy {
        let (s, mut r) = scan_for_secrets(source_label, bytes, cli.threshold, cli.context);
        file_output.push_str(&s);
        records.append(&mut r);
    }

    (file_output, records)
}

/// Recursive scanner that isolates WalkBuilder from OwoColorize to prevent trait collision.
fn run_recursive_scan(input: &str, cli: &Cli, output_mode: OutputMode) {
    // IMPORTANT: Do NOT import OwoColorize in this function scope.
    let walker = WalkBuilder::new(input)
        .hidden(false)
        .git_ignore(true)
        .build();

    // Use Rayon's par_bridge to turn the iterator into a parallel stream
    const MAX_MMAP_SIZE: u64 = 200 * 1024 * 1024; // 200 MB

    walker.into_iter().par_bridge().for_each(|result| {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() {
                    let metadata = match path.metadata() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    if metadata.len() == 0 {
                        return;
                    }

                    if metadata.len() > MAX_MMAP_SIZE {
                        warn!("Skipping large file {} ({} bytes)", path.display(), metadata.len());
                        return;
                    }

                    if let Ok(mut file) = File::open(path) {
                        // Peek at first KB to detect likely binary files
                        let mut peek = [0u8; 1024];
                        match file.read(&mut peek) {
                            Ok(n) if n > 0 => {
                                if peek[..n].contains(&0) {
                                    warn!("Skipping binary file {}", path.display());
                                    return;
                                }
                            }
                            _ => {}
                        }

                        // Safety: File is mapped read-only and OS-backed.
                        match unsafe { Mmap::map(&file) } {
                            Ok(mmap) => {
                                let (out, recs) = run_analysis(&path.to_string_lossy(), &mmap, cli);
                                match &output_mode {
                                    OutputMode::Single(col) => {
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
                                            // write one file per source
                                            let mut outpath = dir.clone();
                                            // sanitize filename
                                            if let Some(name) = path.file_name() {
                                                outpath.push(name);
                                                outpath.set_extension("json");
                                            } else {
                                                outpath.push("output.json");
                                            }
                                            if let Ok(mut f) = std::fs::File::create(&outpath) {
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
                                            println!("{}", out);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Could not map file {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!("Walker error: {}", err);
            }
        }
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let start_time = Instant::now();
    let cli = Cli::parse();

    // If run with no arguments, print full help and exit.
    if std::env::args().len() <= 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // Initialize logging from environment (RUST_LOG)
    env_logger::Builder::from_default_env().format_timestamp(None).init();

    // Handle colorized output toggle
    if cli.no_color {
        owo_colors::set_override(false);
    }

    // Configure global thread pool if -j is set
    if cli.threads > 0 {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
        {
            Ok(()) => info!("Set global thread pool to {} threads", cli.threads),
            Err(e) => {
                warn!("Could not set global thread pool: {}. Continuing with default.", e);
            }
        }
    }

    if cli.keyword.is_empty() && !cli.entropy {
        error!("Provide a keyword (-k) OR enable entropy scanning (--entropy)");
        return Ok(());
    }

    // Create a configured HTTP agent with reasonable timeouts to avoid hanging.
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(5))
        .build();

    // Determine output mode based on flags
    let output_mode = if let Some(path) = &cli.output {
        match cli.output_format.as_str() {
            "ndjson" => {
                // create or append
                match OpenOptions::new().create(true).append(true).open(path) {
                    Ok(f) => OutputMode::Ndjson(Arc::new(Mutex::new(f))),
                    Err(e) => {
                        error!("Failed to open NDJSON output {}: {}", path, e);
                        OutputMode::None
                    }
                }
            }
            "per-file" => {
                let dir = PathBuf::from(path);
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    error!("Failed to create output directory {}: {}", path, e);
                    OutputMode::None
                } else {
                    OutputMode::PerFile(dir)
                }
            }
            _ => {
                // single in-memory collector
                OutputMode::Single(Arc::new(Mutex::new(Vec::new())))
            }
        }
    } else {
        OutputMode::None
    };

    for input in &cli.target {
        if input.starts_with("http") {
            info!("Streaming {}", input);
            match agent.get(input).call() {
                Ok(response) => {
                    let mut tmp = NamedTempFile::new()?;
                    std::io::copy(&mut response.into_reader(), &mut tmp)?;

                    let file = tmp.as_file();
                    // Safety: Temp file is exclusive to this process.
                            match unsafe { Mmap::map(file) } {
                        Ok(mmap) => {
                            let (out, recs) = run_analysis(input, &mmap, &cli);
                            match &output_mode {
                                OutputMode::Single(col) => {
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
                                        let mut outpath = dir.clone();
                                        if let Some(name) = std::path::Path::new(input).file_name() {
                                            outpath.push(name);
                                            outpath.set_extension("json");
                                        } else {
                                            outpath.push("output.json");
                                        }
                                        if let Ok(mut f) = std::fs::File::create(&outpath) {
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
                                        println!("{}", out);
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("Could not map streamed file for {}: {}", input, e),
                    }
                }
                Err(e) => {
                    warn!("HTTP error fetching {}: {}", input, e);
                }
            }
        } else {
            run_recursive_scan(input, &cli, output_mode.clone());
        }
    }

    let duration = start_time.elapsed();
    println!("🏁 Scan completed in {:.2?}", duration);

    // Handle writing when output_mode is Single (in-memory collector).
    if let Some(path) = &cli.output {
        match &output_mode {
            OutputMode::Single(col) => match col.lock() {
                Ok(guard) => {
                    if guard.is_empty() {
                        info!("No matches found; not writing output file {}", path);
                    } else {
                        match serde_json::to_string_pretty(&*guard) {
                            Ok(j) => match std::fs::write(path, j) {
                                Ok(()) => info!("Wrote JSON output to {}", path),
                                Err(e) => error!("Failed to write JSON to {}: {}", path, e),
                            },
                            Err(e) => error!("Failed to serialize JSON output: {}", e),
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write output file: {}", e),
            },
            OutputMode::Ndjson(_) => {
                info!("NDJSON output written incrementally to {}", path);
            }
            OutputMode::PerFile(_) => {
                info!("Per-file JSON output written to directory {}", path);
            }
            OutputMode::None => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_is_zero() {
        let data = b"aaaaaa";
        let e = calculate_entropy(data);
        assert!(e >= 0.0 && e < 0.0001);
    }

    #[test]
    fn harmless_base64_detected() {
        // "hello world" -> aGVsbG8gd29ybGQ=
        let s = "aGVsbG8gd29ybGQ=";
        assert!(is_harmless_text(s));
        assert!(!is_harmless_text("not_base64!$#"));
    }

    #[test]
    fn detect_likely_charset() {
        assert!(is_likely_charset("abcdefgabcde"));
        assert!(is_likely_charset("123456"));
        assert!(!is_likely_charset("randomstringwithhighentropy"));
    }

    #[test]
    fn find_identifier_before_secret() {
        let s = b"const apiKey = \"ABCDEF123456\";";
        // start index of 'ABCDEF123456'
        let start = s.windows(12).position(|w| w == b"ABCDEF123456").unwrap();
        let id = find_preceding_identifier(s, start).unwrap();
        assert_eq!(id, "apiKey");
    }

    #[test]
    fn process_search_records() {
        let data = b"let token = \"secret123\";\n";
        let keywords = vec!["token".to_string()];
        let (out, records) = process_search(data, "test.rs", &keywords, 10);
        assert!(out.contains("token"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "keyword");
    }
}