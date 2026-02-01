use base64::{engine::general_purpose, Engine as _};
use memchr;
use memchr::memmem;
use log::info;
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;

use crate::output::MatchRecord;
use crate::utils::{find_preceding_identifier, format_prettified};

/// Calculates the Shannon Entropy (randomness) of a byte slice.
pub fn calculate_entropy(data: &[u8]) -> f64 {
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
pub fn is_harmless_text(candidate: &str) -> bool {
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
pub fn is_likely_charset(candidate: &str) -> bool {
    if candidate.contains("abcde")
        || candidate.contains("ABCDE")
        || candidate.contains("12345")
        || candidate.contains("vwxyz")
    {
        return true;
    }
    false
}

fn is_likely_url_context(bytes: &[u8], start: usize, end: usize) -> bool {
    let window_start = start.saturating_sub(128);
    let window_end = (end + 128).min(bytes.len());
    let window = &bytes[window_start..window_end];

    memmem::find(window, b"http://").is_some()
        || memmem::find(window, b"https://").is_some()
        || memmem::find(window, b"url(").is_some()
}

pub fn scan_for_secrets(
    source_label: &str,
    bytes: &[u8],
    threshold: f64,
    context_size: usize,
    emit_tags: &HashSet<String>,
) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    let min_len = 20;
    let max_len = 120;
    let mut url_hits = 0usize;
    let mut header_written = false;

    let mut ensure_header = |buffer: &mut String| {
        if !header_written {
            let _ = writeln!(
                buffer,
                "\n🔐 Entropy scanning {} (threshold {:.1})...",
                source_label.cyan(),
                threshold
            );
            let _ = writeln!(buffer, "{}", "━".repeat(60).dimmed());
            header_written = true;
        }
    };

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

                    if is_likely_url_context(bytes, start, i) {
                        url_hits += 1;
                        if emit_tags.contains("url") {
                            ensure_header(&mut out);
                            let preceding = &bytes[..start];
                            let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
                            let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
                            let col = if last_nl == 0 { start } else { start - last_nl };

                            let ctx_start = start.saturating_sub(context_size);
                            let ctx_end = (i + context_size).min(bytes.len());
                            let raw_context = String::from_utf8_lossy(&bytes[ctx_start..ctx_end]);

                            let _ = write!(
                                out,
                                "{}[L:{} C:{} Tag:{}] ",
                                "[".dimmed(),
                                line.bright_magenta(),
                                col.bright_blue(),
                                "url".bright_yellow().bold()
                            );
                            let _ = writeln!(out, "{}", "URL_CONTEXT".cyan().bold());

                            let pretty = format_prettified(&raw_context, &snippet_str);
                            let _ = writeln!(out, "{}", pretty);
                            let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

                            records.push(MatchRecord {
                                source: source_label.to_string(),
                                kind: "url".to_string(),
                                matched: snippet_str.to_string(),
                                line,
                                col,
                                entropy: Some(score),
                                context: raw_context.to_string(),
                                identifier: None,
                            });
                        }
                        continue;
                    }
                    if is_harmless_text(&snippet_str) {
                        continue;
                    }
                    if is_likely_charset(&snippet_str) {
                        continue;
                    }

                    let preceding = &bytes[..start];
                    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
                    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
                    let col = if last_nl == 0 { start } else { start - last_nl };

                    let ctx_start = start.saturating_sub(context_size);
                    let ctx_end = (i + context_size).min(bytes.len());
                    let raw_context = String::from_utf8_lossy(&bytes[ctx_start..ctx_end]);

                    let identifier = find_preceding_identifier(bytes, start);

                    ensure_header(&mut out);
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

                    let pretty = format_prettified(&raw_context, &snippet_str);
                    let _ = writeln!(out, "{}", pretty);
                    let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

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

    if url_hits > 0 {
        info!(
            "{}: skipped {} URL-context entropy candidates due to emit-tags",
            source_label,
            url_hits
        );
        ensure_header(&mut out);
        let _ = writeln!(
            out,
            "{} Skipped {} URL-context entropy candidates (tagged as url and held back)",
            "⚠️".bright_yellow().bold(),
            url_hits
        );
    }

    (out, records)
}

