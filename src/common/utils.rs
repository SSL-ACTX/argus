use std::fmt::Write as FmtWrite;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_color_enabled(enabled: bool) {
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn confidence_tier(confidence: u8) -> (&'static str, &'static str) {
    if confidence >= 7 {
        ("🔴", "loud")
    } else if confidence >= 4 {
        ("🟡", "normal")
    } else {
        ("⚫", "quiet")
    }
}

fn colors_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

/// Prettify a snippet; returns a String suitable for human output.
pub fn format_prettified(raw: &str, matched_word: &str) -> String {
    format_prettified_with_hint(raw, matched_word, None)
}

pub fn format_prettified_with_hint(
    raw: &str,
    matched_word: &str,
    source_hint: Option<&str>,
) -> String {
    if colors_enabled() {
        if let Some(highlighted) = maybe_highlight(raw, source_hint) {
            let _ = matched_word;
            return highlighted;
        }
    }

    let mut out = String::new();
    let mut indentation = 0usize;
    for line in raw.split([';', '{', '}']) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let prefix = "  ".repeat(indentation + 1);
        let _ = writeln!(out, "{}{}", prefix, trimmed);

        if raw.contains('{') {
            indentation += 1;
        }
        if raw.contains('}') {
            indentation = indentation.saturating_sub(1);
        }
    }
    out
}

#[cfg(feature = "highlighting")]
fn format_prettified_highlight(raw: &str, source_hint: Option<&str>) -> String {
    use std::sync::OnceLock;
    use syntect::easy::HighlightLines;
    use syntect::highlighting::{Theme, ThemeSet};
    use syntect::parsing::SyntaxSet;
    use syntect::util::as_24_bit_terminal_escaped;

    static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
    static THEME: OnceLock<Theme> = OnceLock::new();

    let syntax_set = SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines);
    let theme = THEME.get_or_init(|| {
        let ts = ThemeSet::load_defaults();
        ts.themes
            .get("base16-ocean.dark")
            .cloned()
            .or_else(|| ts.themes.values().next().cloned())
            .unwrap_or_default()
    });

    let syntax = match source_hint.and_then(detect_extension) {
        Some(ext) => syntax_set
            .find_syntax_by_extension(&ext)
            .unwrap_or_else(|| syntax_set.find_syntax_plain_text()),
        None => syntax_set.find_syntax_plain_text(),
    };
    let mut highlighter = HighlightLines::new(syntax, theme);

    let mut out = String::new();
    let mut indentation = 0usize;
    for line in raw.split([';', '{', '}']) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let prefix = "  ".repeat(indentation + 1);
        if let Ok(ranges) = highlighter.highlight_line(trimmed, syntax_set) {
            let escaped = as_24_bit_terminal_escaped(&ranges[..], false);
            let _ = writeln!(out, "{}{}\x1b[0m", prefix, escaped);
        } else {
            let _ = writeln!(out, "{}{}", prefix, trimmed);
        }

        if raw.contains('{') {
            indentation += 1;
        }
        if raw.contains('}') {
            indentation = indentation.saturating_sub(1);
        }
    }

    out.push_str("\x1b[0m");
    out
}

#[cfg(feature = "highlighting")]
fn maybe_highlight(raw: &str, source_hint: Option<&str>) -> Option<String> {
    if colors_enabled() {
        Some(format_prettified_highlight(raw, source_hint))
    } else {
        None
    }
}

#[cfg(not(feature = "highlighting"))]
fn maybe_highlight(_raw: &str, _source_hint: Option<&str>) -> Option<String> {
    None
}

#[cfg(feature = "highlighting")]
fn detect_extension(source_hint: &str) -> Option<String> {
    let mut end = source_hint.len();
    if let Some(idx) = source_hint.find('?') {
        end = end.min(idx);
    }
    if let Some(idx) = source_hint.find('#') {
        end = end.min(idx);
    }
    let trimmed = &source_hint[..end];
    let file = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let ext = file.rsplit('.').next()?;
    if ext == file || ext.is_empty() {
        None
    } else {
        Some(ext.to_lowercase())
    }
}

pub fn find_preceding_identifier(bytes: &[u8], start_index: usize) -> Option<String> {
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

#[derive(Clone, Default)]
pub struct LineFilter {
    ranges: Vec<(usize, usize)>,
}

impl LineFilter {
    pub fn new(ranges: Vec<(usize, usize)>) -> Self {
        Self { ranges }
    }

    pub fn allows(&self, line: usize) -> bool {
        self.ranges.iter().any(|(s, e)| line >= *s && line <= *e)
    }
}

use std::sync::OnceLock;

static ENTROPY_LOOKUP: OnceLock<[f64; 1024]> = OnceLock::new();

fn get_entropy_lookup() -> &'static [f64; 1024] {
    ENTROPY_LOOKUP.get_or_init(|| {
        let mut table = [0.0f64; 1024];
        for i in 1..1024 {
            let n = i as f64;
            table[i] = n * n.log2();
        }
        table
    })
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0u32; 256];
    for &b in data {
        frequencies[b as usize] += 1;
    }

    let len = data.len() as f64;
    let log2_len = len.log2();
    let lookup = get_entropy_lookup();

    let mut sum_n_log2_n = 0.0;
    for &n in frequencies.iter() {
        if n > 0 {
            if (n as usize) < lookup.len() {
                sum_n_log2_n += lookup[n as usize];
            } else {
                let nf = n as f64;
                sum_n_log2_n += nf * nf.log2();
            }
        }
    }

    log2_len - (sum_n_log2_n / len)
}

pub fn is_harmless_text(candidate: &str) -> bool {
    use base64::{engine::general_purpose, Engine as _};

    if candidate.starts_with("sourceMappingURL") || candidate.contains(".js.map") {
        return true;
    }
    if candidate.starts_with("assets/") || candidate.starts_with("/assets/") {
        return true;
    }
    if candidate.starts_with("PHN")
        || candidate.starts_with("iVBORw")
        || candidate.starts_with("PD94bW")
    {
        // Base64 signatures for PNG, SVG, or other common assets
        return true;
    }
    if candidate.len() > 14 && candidate.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }

    if candidate.contains(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '=') {
        return false;
    }
    if let Ok(decoded) = general_purpose::STANDARD.decode(candidate) {
        let readable_count = decoded
            .iter()
            .filter(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        let ratio = readable_count as f64 / decoded.len() as f64;
        return ratio > 0.85;
    }
    false
}

pub fn is_likely_charset(candidate: &str) -> bool {
    candidate.contains("abcde")
        || candidate.contains("ABCDE")
        || candidate.contains("12345")
        || candidate.contains("vwxyz")
}

pub fn composition_percentages(token: &str) -> (u8, u8, u8) {
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

pub fn token_shape_hints(token: &str) -> Vec<&'static str> {
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

pub fn is_hex_like(token: &str) -> bool {
    let len = token.len();
    len >= 16 && len % 2 == 0 && token.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_base64_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && len % 4 == 0
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub fn is_base64url_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

pub fn is_uuid_like(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }
    let bytes = token.as_bytes();
    for &i in &[8usize, 13, 18, 23] {
        if bytes[i] != b'-' {
            return false;
        }
    }
    token.chars().enumerate().all(|(i, c)| {
        if [8, 13, 18, 23].contains(&i) {
            c == '-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

pub fn is_jwt_like(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| is_base64url_like(p))
}

pub fn token_type_hint(token: &str) -> Option<&'static str> {
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

pub fn token_type_hint_with_context(token: &str, context: &str) -> Option<&'static str> {
    if is_telegram_bot_token_context(token, context) {
        return Some("telegram-bot-token");
    }
    token_type_hint(token)
}

pub fn is_telegram_bot_token_context(token: &str, context: &str) -> bool {
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

pub fn style_context_line(line: &str) -> String {
    line.to_string()
}

pub fn style_story_text(raw: &str) -> String {
    let mut out = String::new();
    let prefix_marker = "┃";

    for (idx, line) in raw.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            out.push_str(prefix_marker);
            continue;
        }

        let styled_line = if let Some(rest) = trimmed.strip_prefix("Story:") {
            format!("{} Story:{}", prefix_marker, rest)
        } else if let Some(rest) = trimmed.strip_prefix("Source:") {
            format!("{} Source:{}", prefix_marker, rest)
        } else {
            format!("{} {}", prefix_marker, trimmed)
        };
        out.push_str(&styled_line);
    }
    out
}

pub fn style_flow_line(line: &str) -> String {
    line.to_string()
}

pub fn find_assignment_lhs(context: &str) -> Option<String> {
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

pub fn preferred_owner_identifier(
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
