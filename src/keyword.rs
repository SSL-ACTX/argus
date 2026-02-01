use aho_corasick::AhoCorasick;
use memchr;
use std::fmt::Write as FmtWrite;

use crate::output::MatchRecord;
use crate::utils::{find_preceding_identifier, format_prettified};

pub fn process_search(bytes: &[u8], label: &str, keywords: &[String], context_size: usize) -> (String, Vec<MatchRecord>) {
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

