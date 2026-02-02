use base64::{engine::general_purpose, Engine as _};
use memchr;
use memchr::memmem;
use log::info;
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;

use crate::output::MatchRecord;
use crate::heuristics::{analyze_flow_context_with_mode, format_context_graph, format_flow_compact, FlowMode};
use crate::utils::{find_preceding_identifier, format_prettified_with_hint};

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
    deep_scan: bool,
    flow_mode: FlowMode,
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
    let mut candidates: Vec<CandidatePos> = Vec::new();

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

                            let pretty = format_prettified_with_hint(&raw_context, &snippet_str, Some(source_label));
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
                    candidates.push(CandidatePos { start, line, col });

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

                    let pretty = format_prettified_with_hint(&raw_context, &snippet_str, Some(source_label));
                    let _ = writeln!(out, "{}", pretty);

                    let flow = if flow_mode != FlowMode::Off {
                        analyze_flow_context_with_mode(bytes, start, flow_mode)
                    } else {
                        None
                    };

                    if deep_scan {
                        let (count, nearest) = repeat_stats(bytes, candidate_bytes, start);
                        let shape = token_shape_hints(&snippet_str);
                        let shape_str = if shape.is_empty() {
                            "shape n/a".to_string()
                        } else {
                            format!("shape {}", shape.join(","))
                        };
                        let type_str = token_type_hint_with_context(&snippet_str, &raw_context)
                            .map(|t| format!("type {}", t))
                            .unwrap_or_else(|| "type n/a".to_string());
                        let (alpha_pct, digit_pct, other_pct) = composition_percentages(&snippet_str);
                        let id_hint = identifier
                            .as_deref()
                            .map(|id| format!("; id {}", id))
                            .unwrap_or_default();
                        let (signals, confidence) = context_signals(&raw_context, identifier.as_deref(), &snippet_str);
                        let signals_str = if signals.is_empty() {
                            "signals n/a".to_string()
                        } else {
                            format!("signals {}", signals.join(","))
                        };
                        let _ = writeln!(
                            out,
                            "{} appears {} times; nearest repeat {} bytes away; len {}; {}; {}; mix a{}% d{}% s{}%; {}; conf {}/10{}",
                            "Story:".bright_green().bold(),
                            count.to_string().bright_yellow(),
                            nearest
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "n/a".to_string())
                                .bright_yellow(),
                            snippet_str.len().to_string().bright_yellow(),
                            shape_str.bright_cyan(),
                            type_str.bright_cyan(),
                            alpha_pct.to_string().bright_magenta(),
                            digit_pct.to_string().bright_magenta(),
                            other_pct.to_string().bright_magenta(),
                            signals_str.bright_blue(),
                            confidence.to_string().bright_red(),
                            id_hint
                        );
                        let owner = preferred_owner_identifier(identifier.as_deref(), &raw_context, &snippet_str);
                        if let Some(flow) = flow.as_ref() {
                            if let Some(lines) = format_context_graph(flow, owner.as_deref()) {
                                let _ = writeln!(out, "{}", "Context:".bright_cyan().bold());
                                for line in lines {
                                    let styled = style_context_line(&line);
                                    let _ = writeln!(out, "{}", styled);
                                }
                            }
                        }
                    }

                    if let Some(flow) = flow.as_ref() {
                        if let Some(line) = format_flow_compact(flow) {
                            let _ = writeln!(out, "{} {}", "Flow:".bright_magenta().bold(), line.bright_cyan());
                        }
                    }

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

    if deep_scan && !candidates.is_empty() {
        let mut clusters = cluster_candidates(&mut candidates);
        if !clusters.is_empty() {
            clusters.sort_by(|a, b| b.size.cmp(&a.size));
            ensure_header(&mut out);
            let max_size = clusters.first().map(|c| c.size).unwrap_or(0);
            let _ = writeln!(
                out,
                "Cluster: {} clusters; largest {}",
                clusters.len(),
                max_size
            );
            for cluster in clusters.iter().take(3) {
                let _ = writeln!(
                    out,
                    "  • L{}:C{} → L{}:C{} ({} hits)",
                    cluster.start_line,
                    cluster.start_col,
                    cluster.end_line,
                    cluster.end_col,
                    cluster.size
                );
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

fn repeat_stats(bytes: &[u8], needle: &[u8], pos: usize) -> (usize, Option<usize>) {
    if needle.is_empty() {
        return (0, None);
    }
    let mut positions = Vec::new();
    for p in memmem::find_iter(bytes, needle) {
        positions.push(p);
    }
    if positions.is_empty() {
        return (0, None);
    }
    positions.sort_unstable();
    let mut nearest: Option<usize> = None;
    for &p in &positions {
        if p == pos {
            continue;
        }
        let dist = if p >= pos { p - pos } else { pos - p };
        nearest = Some(nearest.map(|d: usize| d.min(dist)).unwrap_or(dist));
    }
    (positions.len(), nearest)
}

struct CandidatePos {
    start: usize,
    line: usize,
    col: usize,
}

struct Cluster {
    size: usize,
    start_line: usize,
    start_col: usize,
    end_line: usize,
    end_col: usize,
}

fn cluster_candidates(cands: &mut Vec<CandidatePos>) -> Vec<Cluster> {
    const WINDOW: usize = 128;
    cands.sort_by(|a, b| a.start.cmp(&b.start));
    let mut clusters = Vec::new();
    let mut current: Vec<&CandidatePos> = Vec::new();

    for cand in cands.iter() {
        if let Some(last) = current.last() {
            if cand.start.saturating_sub(last.start) <= WINDOW {
                current.push(cand);
                continue;
            }
            if current.len() >= 2 {
                clusters.push(build_cluster(&current));
            }
            current.clear();
        }
        current.push(cand);
    }

    if current.len() >= 2 {
        clusters.push(build_cluster(&current));
    }

    clusters
}

fn build_cluster(group: &[&CandidatePos]) -> Cluster {
    let first = group.first().unwrap();
    let last = group.last().unwrap();
    Cluster {
        size: group.len(),
        start_line: first.line,
        start_col: first.col,
        end_line: last.line,
        end_col: last.col,
    }
}

fn token_shape_hints(token: &str) -> Vec<&'static str> {
    let mut hints = Vec::new();
    if is_uuid_like(token) {
        hints.push("uuid");
    }
    if is_jwt_like(token) {
        hints.push("jwt");
    }
    if is_hex_like(token) {
        hints.push("hex");
    }
    if is_base64_like(token) {
        hints.push("base64");
    } else if is_base64url_like(token) {
        hints.push("base64url");
    }
    hints
}

fn composition_percentages(token: &str) -> (u8, u8, u8) {
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut other = 0usize;
    for ch in token.chars() {
        if ch.is_ascii_alphabetic() {
            alpha += 1;
        } else if ch.is_ascii_digit() {
            digit += 1;
        } else {
            other += 1;
        }
    }
    let len = token.chars().count().max(1);
    let ap = ((alpha * 100) / len) as u8;
    let dp = ((digit * 100) / len) as u8;
    let op = ((other * 100) / len) as u8;
    (ap, dp, op)
}

fn is_hex_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && len % 2 == 0
        && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base64_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && len % 4 == 0
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn is_base64url_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn is_uuid_like(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }
    let bytes = token.as_bytes();
    for &i in &[8usize, 13, 18, 23] {
        if bytes[i] != b'-' {
            return false;
        }
    }
    token
        .chars()
        .enumerate()
        .all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
}

fn is_jwt_like(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| is_base64url_like(p))
}

fn token_type_hint(token: &str) -> Option<&'static str> {
    if token.starts_with("AKIA") && token.len() >= 20 {
        return Some("aws-access-key-id");
    }
    if token.starts_with("ASIA") && token.len() >= 20 {
        return Some("aws-temp-key-id");
    }
    if token.starts_with("ghp_") || token.starts_with("gho_") || token.starts_with("ghu_") {
        return Some("github-pat");
    }
    if token.starts_with("xoxb-") || token.starts_with("xoxa-") || token.starts_with("xoxp-") {
        return Some("slack-token");
    }
    if token.starts_with("sk_live_") || token.starts_with("rk_live_") {
        return Some("stripe-key");
    }
    if is_jwt_like(token) {
        return Some("jwt");
    }
    if is_uuid_like(token) {
        return Some("uuid");
    }
    if is_hex_like(token) {
        return Some("hex");
    }
    if is_base64url_like(token) {
        return Some("base64url");
    }
    if is_base64_like(token) {
        return Some("base64");
    }
    None
}

fn token_type_hint_with_context(token: &str, context: &str) -> Option<&'static str> {
    if is_telegram_bot_token_context(token, context) {
        return Some("telegram-bot-token");
    }
    token_type_hint(token)
}

fn context_signals(raw: &str, identifier: Option<&str>, token: &str) -> (Vec<&'static str>, u8) {
    let mut signals = Vec::new();
    let mut score = 0u8;
    let lower = raw.to_lowercase();

    if lower.contains("authorization") || lower.contains("bearer ") {
        signals.push("auth-header");
        score = score.saturating_add(3);
    }
    if lower.contains("x-") || lower.contains("-h ") || lower.contains("header") {
        signals.push("header");
        score = score.saturating_add(2);
    }
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("secret") || lower.contains("token") {
        signals.push("secret-keyword");
        score = score.saturating_add(2);
    }
    if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
        signals.push("password");
        score = score.saturating_add(2);
    }
    if lower.contains("?" ) && lower.contains("=") {
        signals.push("url-param");
        score = score.saturating_add(1);
    }
    if let Some(id) = identifier {
        let id_l = id.to_lowercase();
        if id_l.contains("key") || id_l.contains("token") || id_l.contains("secret") || id_l.contains("pass") {
            signals.push("id-hint");
            score = score.saturating_add(2);
        }
    }
    if is_jwt_like(token) {
        signals.push("jwt");
        score = score.saturating_add(3);
    } else if is_base64_like(token) || is_base64url_like(token) {
        signals.push("b64");
        score = score.saturating_add(1);
    }

    if is_telegram_bot_token_context(token, raw) {
        signals.push("telegram");
        score = score.saturating_add(3);
    }

    (signals, score.min(10))
}

fn is_telegram_bot_token_context(token: &str, context: &str) -> bool {
    if token.len() < 30 || token.len() > 64 {
        return false;
    }
    let bytes = context.as_bytes();
    let mut start = 0usize;
    while let Some(idx) = context[start..].find(token) {
        let pos = start + idx;
        if pos > 0 && bytes[pos - 1] == b':' {
            let mut i = pos - 1;
            let mut digits = 0usize;
            while i > 0 {
                i -= 1;
                let b = bytes[i];
                if b.is_ascii_digit() {
                    digits += 1;
                    continue;
                }
                break;
            }
            if digits >= 6 && digits <= 12 {
                return true;
            }
        }
        start = pos + token.len();
    }
    false
}

fn preferred_owner_identifier(
    identifier: Option<&str>,
    context: &str,
    token: &str,
) -> Option<String> {
    if let Some(id) = identifier {
        if !id.chars().all(|c| c.is_ascii_digit()) {
            return Some(id.to_string());
        }
    }

    if is_telegram_bot_token_context(token, context) {
        if let Some(assign) = find_assignment_lhs(context) {
            return Some(assign);
        }
    }

    None
}

fn style_context_line(line: &str) -> String {
    use owo_colors::OwoColorize;
    if let Some((prefix, rest)) = line.split_once(' ') {
        if prefix == "├─" || prefix == "└─" {
            return format!("{} {}", prefix.bright_cyan(), rest.bright_white());
        }
    }
    line.bright_white().to_string()
}

fn find_assignment_lhs(context: &str) -> Option<String> {
    if let Some(eq_idx) = context.find('=') {
        let left = &context[..eq_idx];
        let mut end = left.len();
        let bytes = left.as_bytes();
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 {
            let b = bytes[start - 1];
            if b.is_ascii_alphanumeric() || b == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        if start < end {
            return Some(left[start..end].to_string());
        }
    }
    None
}

