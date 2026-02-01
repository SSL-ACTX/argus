use std::fmt::Write as FmtWrite;

/// Prettify and colorize a snippet; returns a String suitable for human output.
pub fn format_prettified(raw: &str, matched_word: &str) -> String {
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

#[derive(Debug, Default)]
pub struct FlowContext {
    pub scope_kind: Option<String>,
    pub scope_name: Option<String>,
    pub scope_container: Option<String>,
    pub scope_path: Option<String>,
    pub block_depth: usize,
    pub nearest_control: Option<String>,
    pub nearest_control_line: Option<usize>,
    pub nearest_control_col: Option<usize>,
    pub assignment_distance: Option<usize>,
    pub return_distance: Option<usize>,
    pub scope_line: Option<usize>,
    pub scope_col: Option<usize>,
    pub scope_distance: Option<usize>,
    pub call_chain_hint: Option<String>,
    pub scope_path_distance: Option<usize>,
    pub scope_path_depth: Option<usize>,
}

pub fn analyze_flow_context(bytes: &[u8], pos: usize) -> FlowContext {
    let window_start = pos.saturating_sub(2048);
    let window_end = (pos + 2048).min(bytes.len());
    let window = &bytes[window_start..window_end];

    let mut ctx = FlowContext::default();

    // Estimate block depth by counting braces in the window prefix.
    let prefix = &window[..pos.saturating_sub(window_start)];
    let mut depth = 0isize;
    for &b in prefix {
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
        }
    }
    ctx.block_depth = depth.max(0) as usize;

    // Nearest control keyword backwards.
    let controls: &[&[u8]] = &[
        b"if",
        b"else",
        b"for",
        b"while",
        b"switch",
        b"return",
        b"try",
        b"catch",
    ];
    let mut nearest: Option<(String, usize, usize)> = None;
    for kw in controls.iter() {
        if let Some(idx) = rfind_token(prefix, kw) {
            let dist = prefix.len().saturating_sub(idx);
            if nearest.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                let abs_pos = window_start + idx;
                let (line, col) = line_col_abs(window_start, window, abs_pos);
                nearest = Some((String::from_utf8_lossy(kw).to_string(), line, col));
            }
        }
    }
    if let Some((kw, line, col)) = nearest {
        ctx.nearest_control = Some(kw);
        ctx.nearest_control_line = Some(line);
        ctx.nearest_control_col = Some(col);
    }

    // Nearest assignment '=' not part of '==' or '=>'
    if let Some(idx) = rfind_assignment(prefix) {
        ctx.assignment_distance = Some(prefix.len().saturating_sub(idx));
    }

    // Nearest return (distance)
    if let Some(idx) = rfind_token(prefix, b"return") {
        ctx.return_distance = Some(prefix.len().saturating_sub(idx));
    }

    // Heuristic container (class/struct/impl)
    if let Some(container) = find_container_name(prefix) {
        ctx.scope_container = Some(container);
    }

    // Namespace/module breadcrumb
    if let Some(path) = find_scope_path(prefix) {
        ctx.scope_path = Some(path);
        ctx.scope_path_distance = rfind_any_scope_keyword_distance(prefix);
        ctx.scope_path_depth = ctx.scope_path.as_ref().map(|p| p.split("::").count());
    }

    // Heuristic function name detection
    if let Some((name, line, col, abs_pos)) = find_function_name(prefix, window_start) {
        ctx.scope_kind = Some("function".to_string());
        ctx.scope_name = Some(name);
        ctx.scope_line = Some(line);
        ctx.scope_col = Some(col);
        ctx.scope_distance = Some(pos.saturating_sub(abs_pos));
    } else if let Some((name, abs_pos)) = find_assignment_name(window, window_start) {
        let (line, col) = line_col_abs(window_start, window, abs_pos);
        ctx.scope_kind = Some("assignment".to_string());
        ctx.scope_name = Some(name);
        ctx.scope_line = Some(line);
        ctx.scope_col = Some(col);
        ctx.scope_distance = Some(pos.saturating_sub(abs_pos));
    }

    // Call-chain hint from nearby dot-chains or function calls
    if let Some(chain) = infer_call_chain(prefix) {
        ctx.call_chain_hint = Some(chain);
    }

    ctx
}

fn rfind_token(haystack: &[u8], token: &[u8]) -> Option<usize> {
    if token.is_empty() || haystack.len() < token.len() {
        return None;
    }
    for i in (0..=haystack.len() - token.len()).rev() {
        if &haystack[i..i + token.len()] == token {
            return Some(i);
        }
    }
    None
}

fn rfind_assignment(haystack: &[u8]) -> Option<usize> {
    for i in (0..haystack.len()).rev() {
        if haystack[i] == b'=' {
            let prev = if i > 0 { Some(haystack[i - 1]) } else { None };
            let next = if i + 1 < haystack.len() { Some(haystack[i + 1]) } else { None };
            if prev == Some(b'=') || next == Some(b'=') || next == Some(b'>') {
                continue;
            }
            return Some(i);
        }
    }
    None
}

fn find_function_name(prefix: &[u8], window_start: usize) -> Option<(String, usize, usize, usize)> {
    // Prefer nearest "function name" or Rust "fn name" before position.
    if let Some(idx) = rfind_token(prefix, b"function") {
        let name = read_identifier(&prefix[idx + 8..]);
        if let Some(name) = name {
            let abs_pos = window_start + idx;
            let (line, col) = line_col_abs(window_start, prefix, abs_pos);
            return Some((name, line, col, abs_pos));
        }
    }
    if let Some(idx) = rfind_token(prefix, b"fn") {
        let name = read_identifier(&prefix[idx + 2..]);
        if let Some(name) = name {
            let abs_pos = window_start + idx;
            let (line, col) = line_col_abs(window_start, prefix, abs_pos);
            return Some((name, line, col, abs_pos));
        }
    }
    None
}

fn find_container_name(prefix: &[u8]) -> Option<String> {
    // Look for "class X" / "struct X" / "impl X" backwards.
    let containers: &[&[u8]] = &[b"class", b"struct", b"impl"];
    for kw in containers.iter() {
        if let Some(idx) = rfind_token(prefix, kw) {
            let name = read_identifier(&prefix[idx + kw.len()..]);
            if let Some(name) = name {
                return Some(name);
            }
        }
    }
    None
}

fn find_scope_path(prefix: &[u8]) -> Option<String> {
    // Heuristic breadcrumb from nearest module/namespace declarations
    let keywords: &[&[u8]] = &[b"mod", b"module", b"namespace", b"package"];
    let mut parts: Vec<String> = Vec::new();
    for kw in keywords.iter() {
        if let Some(idx) = rfind_token(prefix, kw) {
            if let Some(name) = read_identifier(&prefix[idx + kw.len()..]) {
                parts.push(name);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        parts.reverse();
        Some(parts.join("::"))
    }
}

fn rfind_any_scope_keyword_distance(prefix: &[u8]) -> Option<usize> {
    let keywords: &[&[u8]] = &[b"mod", b"module", b"namespace", b"package"];
    let mut best: Option<usize> = None;
    for kw in keywords.iter() {
        if let Some(idx) = rfind_token(prefix, kw) {
            let dist = prefix.len().saturating_sub(idx);
            best = Some(best.map(|b| b.min(dist)).unwrap_or(dist));
        }
    }
    best
}

pub fn is_likely_code(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    let text_ratio = sample.iter().filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count() as f64
        / sample_len.max(1) as f64;
    if text_ratio < 0.7 {
        return false;
    }
    // If it looks like markdown or prose-heavy text, skip flow analysis.
    if memchr::memmem::find(sample, b"```").is_some() {
        return false;
    }
    let mut md_lines = 0usize;
    let mut non_empty_lines = 0usize;
    for line in sample.split(|&b| b == b'\n') {
        let mut i = 0;
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        let trimmed = &line[i..];
        if trimmed.is_empty() {
            continue;
        }
        non_empty_lines += 1;
        let md = trimmed.starts_with(b"#")
            || trimmed.starts_with(b"-")
            || trimmed.starts_with(b"*")
            || trimmed.starts_with(b">")
            || trimmed.starts_with(b"|")
            || (trimmed.len() > 1 && trimmed[0].is_ascii_digit() && trimmed[1] == b'.')
            || trimmed.starts_with(b"```")
            || trimmed.starts_with(b"- [")
            || trimmed.starts_with(b"* [");
        if md {
            md_lines += 1;
        }
    }
    if non_empty_lines > 0 && md_lines * 2 >= non_empty_lines {
        return false;
    }
    let mut score = 0i32;
    let tokens: &[&[u8]] = &[
        b"function",
        b"class",
        b"struct",
        b"impl",
        b"fn",
        b"def",
        b"trait",
        b"enum",
        b"interface",
        b"let",
        b"const",
        b"var",
        b"import",
        b"export",
        b"using",
        b"async",
        b"=>",
        b"{",
    ];
    for token in tokens.iter() {
        if contains_word(sample, token) {
            score += 1;
        }
    }
    let semicolons = memchr::memmem::find_iter(sample, b";").count();
    let braces = memchr::memmem::find_iter(sample, b"{").count();
    let parens = memchr::memmem::find_iter(sample, b"(").count();
    let code_punct = (semicolons + braces + parens) as i32;
    (score >= 2 && code_punct >= 2) || (score >= 3)
}

fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    for idx in memchr::memmem::find_iter(haystack, needle) {
        let left_ok = if idx == 0 {
            true
        } else {
            !is_ident_char(haystack[idx - 1])
        };
        let right_idx = idx + needle.len();
        let right_ok = if right_idx >= haystack.len() {
            true
        } else {
            !is_ident_char(haystack[right_idx])
        };
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn read_identifier(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$') {
        i += 1;
    }
    if i > start {
        Some(String::from_utf8_lossy(&bytes[start..i]).to_string())
    } else {
        None
    }
}

fn find_assignment_name(window: &[u8], window_start: usize) -> Option<(String, usize)> {
    for i in (0..window.len()).rev() {
        if window[i] == b'=' {
            let prev = if i > 0 { window[i - 1] } else { 0 };
            let next = if i + 1 < window.len() { window[i + 1] } else { 0 };
            if prev == b'=' || next == b'=' || next == b'>' {
                continue;
            }
            let mut j = i;
            while j > 0 && window[j - 1].is_ascii_whitespace() {
                j -= 1;
            }
            let end = j;
            while j > 0 && (window[j - 1].is_ascii_alphanumeric() || window[j - 1] == b'_' || window[j - 1] == b'$') {
                j -= 1;
            }
            if end > j {
                let name = String::from_utf8_lossy(&window[j..end]).to_string();
                return Some((name, window_start + j));
            }
        }
    }
    None
}

fn infer_call_chain(prefix: &[u8]) -> Option<String> {
    // Heuristic: find nearest "identifier.identifier" chain before current position.
    let mut best: Option<String> = None;
    let mut i = prefix.len();
    while i > 0 {
        i -= 1;
        if prefix[i] == b'.' {
            let left = read_ident_backward(prefix, i);
            let right = read_ident_forward(prefix, i + 1);
            if let (Some(l), Some(r)) = (left, right) {
                best = Some(format!("{}.{}", l, r));
                break;
            }
        }
    }
    best
}

fn read_ident_backward(bytes: &[u8], pos: usize) -> Option<String> {
    if pos == 0 { return None; }
    let mut i = pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let end = i;
    while i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b'$') {
        i -= 1;
    }
    if end > i {
        Some(String::from_utf8_lossy(&bytes[i..end]).to_string())
    } else {
        None
    }
}

fn read_ident_forward(bytes: &[u8], pos: usize) -> Option<String> {
    let mut i = pos;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$') {
        i += 1;
    }
    if i > start {
        Some(String::from_utf8_lossy(&bytes[start..i]).to_string())
    } else {
        None
    }
}

fn line_col_abs(window_start: usize, window: &[u8], abs_pos: usize) -> (usize, usize) {
    let rel = abs_pos.saturating_sub(window_start).min(window.len());
    let preceding = &window[..rel];
    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
    let col = if last_nl == 0 { rel } else { rel - last_nl };
    (line, col)
}

