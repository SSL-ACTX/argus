use aho_corasick::AhoCorasick;
use memchr;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

#[cfg(feature = "tree-sitter")]
use tree_sitter::{self, Language};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowMode {
    Off,
    Heuristic,
    JsAst,
    PyAst,
    GoAst,
    RustAst,
    JavaAst,
}

#[derive(Debug, Default)]
pub struct FlowContext {
    pub scope_kind: Option<String>,
    pub scope_name: Option<String>,
    pub scope_container: Option<String>,
    pub scope_path: Option<String>,
    pub block_depth: usize,
    pub cognitive_complexity: usize,
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
    pub semantic_context: Vec<String>,
    pub taint_summary: Option<String>,
    pub flow_stack: Vec<String>,
    pub import_hints: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TokenType {
    Keyword,
    Operator,
    Identifier,
    BraceOpen,
    BraceClose,
    Other,
}

#[derive(Debug, Clone)]
pub struct CodeToken<'a> {
    pub kind: TokenType,
    pub text: &'a str,
    pub pos: usize,
}

pub struct CodeTokenizer<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CodeTokenizer<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    pub fn next_token(&mut self) -> Option<CodeToken<'a>> {
        while !self.is_eof() {
            let b = self.peek()?;
            if b.is_ascii_whitespace() {
                self.advance();
                continue;
            }

            // Comments
            if b == b'/' {
                if let Some(next) = self.bytes.get(self.pos + 1) {
                    if *next == b'/' {
                        // Inline comment
                        while !self.is_eof() && self.peek() != Some(b'\n') {
                            self.advance();
                        }
                        continue;
                    } else if *next == b'*' {
                        // Block comment
                        self.advance(); // /
                        self.advance(); // *
                        while !self.is_eof() {
                            if self.peek() == Some(b'*')
                                && self.bytes.get(self.pos + 1) == Some(&b'/')
                            {
                                self.advance(); // *
                                self.advance(); // /
                                break;
                            }
                            self.advance();
                        }
                        continue;
                    }
                }
            }

            // Strings
            if b == b'"' || b == b'\'' || b == b'`' {
                let quote = b;
                self.advance();
                while !self.is_eof() {
                    let c = self.advance()?;
                    if c == b'\\' {
                        self.advance(); // Skip escaped char
                    } else if c == quote {
                        break;
                    }
                }
                // We skip strings entirely for heuristic analysis
                continue;
            }

            let start = self.pos;
            if b == b'{' {
                self.advance();
                return Some(CodeToken {
                    kind: TokenType::BraceOpen,
                    text: "{",
                    pos: start,
                });
            }
            if b == b'}' {
                self.advance();
                return Some(CodeToken {
                    kind: TokenType::BraceClose,
                    text: "}",
                    pos: start,
                });
            }

            // Identifiers and Keywords
            if is_ident_start(b) {
                while !self.is_eof() && is_ident_char(self.peek().unwrap_or(0)) {
                    self.advance();
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
                let kind = if is_heuristic_keyword(text) {
                    TokenType::Keyword
                } else {
                    TokenType::Identifier
                };
                return Some(CodeToken {
                    kind,
                    text,
                    pos: start,
                });
            }

            // Operators
            if is_operator_char(b) {
                while !self.is_eof() && is_operator_char(self.peek().unwrap_or(0)) {
                    self.advance();
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
                return Some(CodeToken {
                    kind: TokenType::Operator,
                    text,
                    pos: start,
                });
            }

            self.advance();
            let text = std::str::from_utf8(&self.bytes[start..start + 1]).unwrap_or("");
            return Some(CodeToken {
                kind: TokenType::Other,
                text,
                pos: start,
            });
        }
        None
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_heuristic_keyword(s: &str) -> bool {
    matches!(
        s,
        "if" | "else"
            | "for"
            | "while"
            | "switch"
            | "case"
            | "catch"
            | "match"
            | "select"
            | "try"
            | "async"
            | "await"
            | "return"
            | "fn"
            | "function"
            | "def"
            | "func"
            | "unsafe"
            | "finally"
    )
}
pub fn parse_tree_for_mode(bytes: &[u8], mode: FlowMode) -> Option<CacheTree> {
    #[cfg(feature = "tree-sitter")]
    {
        use tree_sitter::Parser;
        let mut parser = Parser::new();
        match mode {
            FlowMode::JsAst => {
                #[cfg(feature = "js-ast")]
                {
                    parser.set_language(js_language()).ok()?;
                    parser.parse(bytes, None).map(std::sync::Arc::new)
                }
                #[cfg(not(feature = "js-ast"))]
                None
            }
            FlowMode::PyAst => {
                #[cfg(feature = "py-ast")]
                {
                    parser.set_language(py_language()).ok()?;
                    parser.parse(bytes, None).map(std::sync::Arc::new)
                }
                #[cfg(not(feature = "py-ast"))]
                None
            }
            FlowMode::GoAst => {
                #[cfg(feature = "go-ast")]
                {
                    parser.set_language(go_language()).ok()?;
                    parser.parse(bytes, None).map(std::sync::Arc::new)
                }
                #[cfg(not(feature = "go-ast"))]
                None
            }
            FlowMode::RustAst => {
                #[cfg(feature = "rust-ast")]
                {
                    parser.set_language(rust_language()).ok()?;
                    parser.parse(bytes, None).map(std::sync::Arc::new)
                }
                #[cfg(not(feature = "rust-ast"))]
                None
            }
            FlowMode::JavaAst => {
                #[cfg(feature = "java-ast")]
                {
                    parser.set_language(java_language()).ok()?;
                    parser.parse(bytes, None).map(std::sync::Arc::new)
                }
                #[cfg(not(feature = "java-ast"))]
                None
            }
            _ => None,
        }
    }
    #[cfg(not(feature = "tree-sitter"))]
    {
        let _ = (bytes, mode);
        None
    }
}

#[cfg(feature = "tree-sitter")]
pub type CacheTree = std::sync::Arc<tree_sitter::Tree>;
#[cfg(not(feature = "tree-sitter"))]
pub type CacheTree = ();

#[derive(Debug, Default, Clone)]
pub struct FileAnalysisCache {
    pub import_hints: Vec<String>,
    pub tree: Option<CacheTree>,
}

pub fn analyze_flow_context(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> FlowContext {
    let window_start = pos.saturating_sub(2048);
    let window_end = (pos + 2048).min(bytes.len());
    let window = &bytes[window_start..window_end];

    let mut ctx = FlowContext::default();

    // Use cached import hints or scan (rare fallback)
    ctx.import_hints = cache
        .map(|c| c.import_hints.clone())
        .unwrap_or_else(|| scan_import_hints(bytes));

    let prefix = &window[..pos.saturating_sub(window_start)];

    // Combined lexical pass for all heuristic signals
    let mut depth = 0isize;
    let mut complexity = 0usize;
    let mut stack = Vec::new();
    let mut last_kw = None;
    let mut nearest_ctrl: Option<(String, usize)> = None;
    let mut nearest_assign: Option<usize> = None;
    let mut nearest_ret: Option<usize> = None;
    let mut best_func: Option<(String, usize, usize, usize)> = None;
    let mut best_container: Option<String> = None;
    let mut scope_path_parts = Vec::new();
    let mut rfind_scope_dist = None;

    let controls = &[
        "if", "else", "for", "while", "switch", "case", "return", "try", "catch", "match",
        "select", "defer", "go", "await", "yield", "finally", "using",
    ];
    let func_keywords = &["function", "fn", "def", "func"];
    let container_keywords = &[
        "class",
        "struct",
        "impl",
        "interface",
        "trait",
        "enum",
        "namespace",
        "module",
    ];
    let scope_path_keywords = &["mod", "module", "namespace", "package"];
    let stack_keywords = &[
        "if", "else", "for", "while", "switch", "try", "catch", "finally", "async", "unsafe",
        "match",
    ];

    let mut tokenizer = CodeTokenizer::new(prefix);
    while let Some(token) = tokenizer.next_token() {
        match token.kind {
            TokenType::BraceOpen => {
                depth += 1;
                stack.push(last_kw.take().unwrap_or_else(|| "block".to_string()));
            }
            TokenType::BraceClose => {
                depth -= 1;
                stack.pop();
                last_kw = None;
            }
            TokenType::Keyword => {
                let text = token.text;
                let adds_nesting_bonus = matches!(
                    text,
                    "if" | "else" | "for" | "while" | "switch" | "catch" | "match" | "select"
                );
                let is_structural_increment =
                    adds_nesting_bonus || matches!(text, "case" | "finally" | "unsafe");

                if is_structural_increment {
                    complexity += 1;
                    if adds_nesting_bonus {
                        complexity += (depth - 1).max(0) as usize;
                    }
                }

                if stack_keywords.contains(&text) {
                    last_kw = Some(text.to_string());
                } else if text == "return" {
                    last_kw = None;
                }

                if controls.contains(&text) {
                    let dist = prefix.len().saturating_sub(token.pos);
                    if nearest_ctrl
                        .as_ref()
                        .map(|(_, d)| dist < *d)
                        .unwrap_or(true)
                    {
                        nearest_ctrl = Some((text.to_string(), dist));
                        let abs_pos = window_start + token.pos;
                        let (line, col) = line_col_abs(window_start, window, abs_pos);
                        ctx.nearest_control = Some(text.to_string());
                        ctx.nearest_control_line = Some(line);
                        ctx.nearest_control_col = Some(col);
                    }
                    if text == "return" {
                        nearest_ret = Some(dist);
                    }
                }

                if func_keywords.contains(&text) {
                    if let Some(name_token) = tokenizer.next_token() {
                        if name_token.kind == TokenType::Identifier {
                            let abs_pos = window_start + token.pos;
                            let (line, col) = line_col_abs(window_start, window, abs_pos);
                            best_func = Some((name_token.text.to_string(), line, col, abs_pos));
                        }
                    }
                }

                if container_keywords.contains(&text) {
                    if let Some(name_token) = tokenizer.next_token() {
                        if name_token.kind == TokenType::Identifier {
                            best_container = Some(name_token.text.to_string());
                        }
                    }
                }

                if scope_path_keywords.contains(&text) {
                    let dist = prefix.len().saturating_sub(token.pos);
                    rfind_scope_dist =
                        Some(rfind_scope_dist.map(|b: usize| b.min(dist)).unwrap_or(dist));
                    if let Some(name_token) = tokenizer.next_token() {
                        if name_token.kind == TokenType::Identifier {
                            scope_path_parts.push(name_token.text.to_string());
                        }
                    }
                }
            }
            TokenType::Operator => {
                if token.text == "&&" || token.text == "||" {
                    complexity += 1;
                } else if token.text == "=" {
                    nearest_assign = Some(prefix.len().saturating_sub(token.pos));
                }
            }
            TokenType::Other => {
                if token.text == ";" {
                    last_kw = None;
                }
            }
            _ => {}
        }
    }

    ctx.block_depth = depth.max(0) as usize;
    ctx.cognitive_complexity = complexity;
    ctx.flow_stack = stack;
    ctx.assignment_distance = nearest_assign;
    ctx.return_distance = nearest_ret;
    ctx.scope_container = best_container;

    if !scope_path_parts.is_empty() {
        ctx.scope_path = Some(scope_path_parts.join("::"));
        ctx.scope_path_distance = rfind_scope_dist;
        ctx.scope_path_depth = ctx.scope_path.as_ref().map(|p| p.split("::").count());
    }

    if let Some((name, line, col, abs_pos)) = best_func {
        ctx.scope_kind = Some("function".to_string());
        ctx.scope_name = Some(name);
        ctx.scope_line = Some(line);
        ctx.scope_col = Some(col);
        ctx.scope_distance = Some(pos.saturating_sub(abs_pos));
    }

    // Detect semantic clusters
    ctx.semantic_context = detect_semantic_clusters(window);

    // Heuristic Taint
    ctx.taint_summary = analyze_taint(window, pos.saturating_sub(window_start));

    // Call-chain hint from nearby dot-chains or function calls
    if let Some(chain) = infer_call_chain(prefix) {
        ctx.call_chain_hint = Some(chain);
    }

    ctx
}

pub fn analyze_flow_context_with_mode(
    bytes: &[u8],
    pos: usize,
    mode: FlowMode,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    match mode {
        FlowMode::Off => None,
        FlowMode::Heuristic => Some(analyze_flow_context(bytes, pos, cache)),
        FlowMode::JsAst => analyze_flow_context_js(bytes, pos, cache)
            .or_else(|| Some(analyze_flow_context(bytes, pos, cache))),
        FlowMode::PyAst => analyze_flow_context_py(bytes, pos, cache)
            .or_else(|| Some(analyze_flow_context(bytes, pos, cache))),
        FlowMode::GoAst => analyze_flow_context_go(bytes, pos, cache)
            .or_else(|| Some(analyze_flow_context(bytes, pos, cache))),
        FlowMode::RustAst => analyze_flow_context_rust(bytes, pos, cache)
            .or_else(|| Some(analyze_flow_context(bytes, pos, cache))),
        FlowMode::JavaAst => analyze_flow_context_java(bytes, pos, cache)
            .or_else(|| Some(analyze_flow_context(bytes, pos, cache))),
    }
}

pub fn format_flow_compact(flow: &FlowContext) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    if flow.scope_kind.is_some() || flow.scope_name.is_some() {
        let kind = flow
            .scope_kind
            .clone()
            .unwrap_or_else(|| "scope".to_string());
        let mut name = flow
            .scope_name
            .as_deref()
            .and_then(normalize_name)
            .unwrap_or_else(|| "<anon>".to_string());

        // Semantic Guessing: if name is minified (<= 2 chars), try to find a better one
        if name.len() <= 2 && name != "<anon>" {
            if let Some(guess) = guess_semantic_name(flow) {
                name = format!("{} (~{})", name, guess);
            }
        }

        let mut s = format!("scope {}:{}", kind, name);
        if let (Some(l), Some(c)) = (flow.scope_line, flow.scope_col) {
            s.push_str(&format!(" L{}:C{}", l, c));
        }
        if let Some(d) = flow.scope_distance {
            s.push_str(&format!(" d{}", d));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(path) = &flow.scope_path {
        let mut s = format!("path {}", path);
        if let Some(depth) = flow.scope_path_depth {
            s.push_str(&format!(" depth{}", depth));
        }
        if let Some(dist) = flow.scope_path_distance {
            s.push_str(&format!(" d{}", dist));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(container) = flow.scope_container.as_deref().and_then(normalize_name) {
        parts.push(format!("[container {}]", container));
    }

    if let Some(ctrl) = &flow.nearest_control {
        let mut s = format!("ctrl {}", ctrl);
        if let (Some(l), Some(c)) = (flow.nearest_control_line, flow.nearest_control_col) {
            s.push_str(&format!(" L{}:C{}", l, c));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(assign) = flow.assignment_distance {
        parts.push(format!("[assign d{}]", assign));
    }

    if let Some(ret) = flow.return_distance {
        parts.push(format!("[return d{}]", ret));
    }

    if let Some(chain) = &flow.call_chain_hint {
        let trimmed = trim_value(chain, 32);
        if trimmed.len() > 1 {
            parts.push(format!("[chain {}]", trimmed));
        }
    }

    if flow.block_depth > 0 {
        parts.push(format!("[depth {}]", flow.block_depth));
    }

    if flow.cognitive_complexity > 0 {
        parts.push(format!("[complexity {}]", flow.cognitive_complexity));
    }

    if !flow.semantic_context.is_empty() {
        parts.push(format!("[semantics {}]", flow.semantic_context.join(",")));
    }

    if let Some(taint) = &flow.taint_summary {
        parts.push(format!("[taint {}]", taint));
    }

    if !flow.flow_stack.is_empty() {
        parts.push(format!("[flow {}]", flow.flow_stack.join(">")));
    }

    if !flow.import_hints.is_empty() {
        parts.push(format!("[imports {}]", flow.import_hints.join(",")));
    }

    if parts.is_empty() {
        None
    } else {
        Some(trim_value(&parts.join(" "), 180))
    }
}

pub fn format_context_graph(flow: &FlowContext, identifier: Option<&str>) -> Option<Vec<String>> {
    let mut items: Vec<String> = Vec::new();

    if let Some(id) = identifier.and_then(normalize_owner_identifier) {
        items.push(format!("owner: {}", id));
    }

    if let Some(taint) = &flow.taint_summary {
        items.push(format!("taint: {}", taint));
    }

    if !flow.import_hints.is_empty() {
        items.push(format!("imports: {}", flow.import_hints.join(", ")));
    }

    if !flow.flow_stack.is_empty() {
        items.push(format!("flow: {}", flow.flow_stack.join(" > ")));
    }

    if flow.cognitive_complexity > 0 {
        items.push(format!("complexity: {}", flow.cognitive_complexity));
    }

    if !flow.semantic_context.is_empty() {
        items.push(format!("semantics: {}", flow.semantic_context.join(", ")));
    }

    if flow.scope_kind.is_some() || flow.scope_name.is_some() {
        let kind = flow
            .scope_kind
            .clone()
            .unwrap_or_else(|| "scope".to_string());
        let name = flow
            .scope_name
            .clone()
            .unwrap_or_else(|| "<anon>".to_string());
        let mut s = format!("scope: {} {}", kind, name);
        if let (Some(l), Some(c)) = (flow.scope_line, flow.scope_col) {
            s.push_str(&format!(" @L{}:C{}", l, c));
        }
        items.push(s);
    }

    if let Some(container) = &flow.scope_container {
        items.push(format!("container: {}", container));
    }

    if let Some(path) = &flow.scope_path {
        items.push(format!("path: {}", path));
    }

    if let Some(chain) = &flow.call_chain_hint {
        items.push(format!("call: {}", trim_value(chain, 48)));
    }

    if let Some(ctrl) = &flow.nearest_control {
        let mut s = format!("ctrl: {}", ctrl);
        if let (Some(l), Some(c)) = (flow.nearest_control_line, flow.nearest_control_col) {
            s.push_str(&format!(" @L{}:C{}", l, c));
        }
        items.push(s);
    }

    if items.is_empty() {
        return None;
    }

    let total = items.len();
    let mut lines = Vec::with_capacity(total);
    for (i, item) in items.into_iter().enumerate() {
        if i + 1 == total {
            lines.push(format!("└─ {}", item));
        } else {
            lines.push(format!("├─ {}", item));
        }
    }
    Some(lines)
}

fn normalize_owner_identifier(id: &str) -> Option<String> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if trimmed.len() < 2 {
        return None;
    }
    Some(trimmed.to_string())
}

pub fn is_likely_code(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    let text_ratio = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64
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
        b"func",
        b"trait",
        b"enum",
        b"interface",
        b"namespace",
        b"package",
        b"let",
        b"const",
        b"var",
        b"import",
        b"export",
        b"using",
        b"async",
        b"public",
        b"private",
        b"static",
        b"include",
        b"require",
        b"=>",
        b"{",
    ];
    let primary: &[&[u8]] = &[
        b"function",
        b"fn",
        b"def",
        b"func",
        b"class",
        b"import",
        b"export",
        b"package",
        b"namespace",
    ];
    let mut primary_hit = false;
    for token in tokens.iter() {
        if contains_word(sample, token) {
            score += 1;
            if primary.iter().any(|p| *p == *token) {
                primary_hit = true;
            }
        }
    }
    let semicolons = memchr::memmem::find_iter(sample, b";").count();
    let braces = memchr::memmem::find_iter(sample, b"{").count();
    let parens = memchr::memmem::find_iter(sample, b"(").count();
    let code_punct = (semicolons + braces + parens) as i32;
    primary_hit && ((score >= 2 && code_punct >= 2) || (score >= 3))
}

pub fn is_likely_code_for_path(path: &Path, bytes: &[u8]) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    if let Some(ext) = ext.as_deref() {
        if is_data_extension(ext) {
            return false;
        }
        if is_code_extension(ext) {
            return is_likely_code(bytes);
        }
    }
    is_strongly_likely_code(bytes)
}

pub fn flow_mode_for_source(
    source_path: Option<&Path>,
    source_hint: Option<&str>,
    flow_scan: bool,
    bytes: &[u8],
) -> FlowMode {
    if !flow_scan {
        return FlowMode::Off;
    }

    let ext = source_path
        .and_then(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase())
        })
        .or_else(|| source_hint.and_then(extract_extension_from_hint));

    if let Some(ext) = ext.as_deref() {
        match ext {
            "js" | "mjs" | "cjs" | "ts" => {
                return if cfg!(feature = "js-ast") {
                    FlowMode::JsAst
                } else {
                    FlowMode::Heuristic
                };
            }
            "py" => {
                return if cfg!(feature = "py-ast") {
                    FlowMode::PyAst
                } else {
                    FlowMode::Heuristic
                };
            }
            "go" => {
                return if cfg!(feature = "go-ast") {
                    FlowMode::GoAst
                } else {
                    FlowMode::Heuristic
                };
            }
            "rs" => {
                return if cfg!(feature = "rust-ast") {
                    FlowMode::RustAst
                } else {
                    FlowMode::Heuristic
                };
            }
            "java" => {
                return if cfg!(feature = "java-ast") {
                    FlowMode::JavaAst
                } else {
                    FlowMode::Heuristic
                };
            }
            _ => {}
        }
        if is_data_extension(ext) {
            return FlowMode::Off;
        }
        if is_code_extension(ext) {
            return if is_likely_code(bytes) {
                FlowMode::Heuristic
            } else {
                FlowMode::Off
            };
        }
    }

    if is_strongly_likely_code(bytes) {
        FlowMode::Heuristic
    } else {
        FlowMode::Off
    }
}

pub fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

pub fn is_operator_char(b: u8) -> bool {
    b"&|+-*/%=!<>^~".contains(&b)
}

pub fn is_word_boundary(haystack: &[u8], start: usize, len: usize) -> bool {
    let left_ok = if start == 0 {
        true
    } else {
        !is_ident_char(haystack[start - 1])
    };
    let right_idx = start + len;
    let right_ok = if right_idx >= haystack.len() {
        true
    } else {
        !is_ident_char(haystack[right_idx])
    };
    left_ok && right_ok
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
                if is_reasonable_ident(&l) && is_reasonable_ident(&r) && !is_file_extension(&r) {
                    best = Some(format!("{}.{}", l, r));
                    break;
                }
            }
        }
    }
    best
}

fn read_ident_backward(bytes: &[u8], pos: usize) -> Option<String> {
    if pos == 0 {
        return None;
    }
    let mut i = pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let end = i;
    while i > 0
        && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b'$')
    {
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
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
    {
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

fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    for idx in memchr::memmem::find_iter(haystack, needle) {
        if is_word_boundary(haystack, idx, needle.len()) {
            return true;
        }
    }
    false
}

pub fn find_identifier_usages(bytes: &[u8], id: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let id_bytes = id.as_bytes();
    for pos in memchr::memmem::find_iter(bytes, id_bytes) {
        if is_word_boundary(bytes, pos, id_bytes.len()) {
            positions.push(pos);
        }
    }
    positions
}

static CODE_LIKELIHOOD_AC: OnceLock<(AhoCorasick, Vec<&'static str>)> = OnceLock::new();

fn is_strongly_likely_code(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    if is_prose_like(sample) {
        return false;
    }

    let (ac, tokens) = CODE_LIKELIHOOD_AC.get_or_init(|| {
        let tokens: &[&str] = &[
            "function",
            "class",
            "struct",
            "impl",
            "fn",
            "def",
            "func",
            "trait",
            "enum",
            "interface",
            "namespace",
            "package",
            "let",
            "const",
            "var",
            "import",
            "export",
            "using",
            "async",
            "public",
            "private",
            "static",
            "include",
            "require",
            "=>",
            "{",
        ];
        (
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(tokens)
                .unwrap(),
            tokens.to_vec(),
        )
    });

    let primary = [
        "function",
        "fn",
        "def",
        "func",
        "class",
        "import",
        "export",
        "package",
        "namespace",
    ];

    let mut score = 0i32;
    let mut primary_hit = false;
    let mut seen_indices = HashSet::new();

    for mat in ac.find_iter(sample) {
        if seen_indices.insert(mat.pattern()) {
            let text = tokens[mat.pattern().as_usize()];
            if text.len() > 2 {
                if is_word_boundary(sample, mat.start(), text.len()) {
                    score += 1;
                    if primary.contains(&text) {
                        primary_hit = true;
                    }
                }
            } else {
                score += 1;
            }
        }
    }

    let semicolons = memchr::memmem::find_iter(sample, b";").count();
    let braces = memchr::memmem::find_iter(sample, b"{").count();
    let parens = memchr::memmem::find_iter(sample, b"(").count();
    let code_punct = (semicolons + braces + parens) as i32;
    primary_hit && score >= 4 && code_punct >= 6
}

fn is_prose_like(sample: &[u8]) -> bool {
    let text_ratio = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64
        / sample.len().max(1) as f64;
    if text_ratio < 0.7 {
        return true;
    }
    if memchr::memmem::find(sample, b"```").is_some() {
        return true;
    }
    let lt = memchr::memmem::find_iter(sample, b"<").count();
    let gt = memchr::memmem::find_iter(sample, b">").count();
    if lt > 10 && gt > 10 && memchr::memmem::find(sample, b"<script").is_none() {
        return true;
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
    non_empty_lines > 0 && md_lines * 2 >= non_empty_lines
}

fn normalize_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn is_reasonable_ident(raw: &str) -> bool {
    let s = raw.trim();
    if s.len() < 2 || s.len() > 32 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let first = s.chars().next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    !s.chars().any(|c| c.is_whitespace())
}

fn is_file_extension(raw: &str) -> bool {
    matches!(
        raw.to_ascii_lowercase().as_str(),
        "js" | "css" | "png" | "jpg" | "jpeg" | "svg" | "html"
    )
}

fn is_code_extension(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "go"
            | "java"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "rb"
            | "php"
            | "swift"
            | "kt"
            | "kts"
            | "scala"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "sql"
            | "lua"
            | "r"
            | "m"
            | "mm"
            | "dart"
            | "clj"
            | "ex"
            | "exs"
            | "el"
            | "erl"
            | "hs"
            | "ml"
            | "fs"
            | "fsx"
            | "s"
            | "asm"
    )
}

fn is_data_extension(ext: &str) -> bool {
    matches!(
        ext,
        "md" | "markdown"
            | "txt"
            | "rst"
            | "adoc"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "lock"
            | "csv"
            | "tsv"
            | "log"
            | "html"
            | "htm"
            | "xml"
            | "env"
    )
}

fn extract_extension_from_hint(hint: &str) -> Option<String> {
    let mut end = hint.len();
    if let Some(idx) = hint.find('?') {
        end = end.min(idx);
    }
    if let Some(idx) = hint.find('#') {
        end = end.min(idx);
    }
    let trimmed = &hint[..end];
    let file = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let ext = file.rsplit('.').next()?;
    if ext == file || ext.is_empty() {
        None
    } else {
        Some(ext.to_lowercase())
    }
}

#[cfg(feature = "js-ast")]
fn analyze_flow_context_js(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    use std::cell::RefCell;
    use tree_sitter::{Parser, Query};

    thread_local! {
        static PARSER: RefCell<Parser> = {
            let mut parser = Parser::new();
            let _ = parser.set_language(js_language());
            RefCell::new(parser)
        };
    }

    static FUNC_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();
    static CTRL_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();
    static ASSIGN_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();

    let func_query = FUNC_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(function_declaration name: (identifier) @name) @func\
             (method_definition name: (property_identifier) @name) @func\
             (function_expression name: (identifier) @name) @func\
             (arrow_function) @func",
        )
    });
    let ctrl_query = CTRL_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(if_statement) @ctrl\
             (for_statement) @ctrl\
             (for_in_statement) @ctrl\
             (while_statement) @ctrl\
             (do_statement) @ctrl\
             (switch_statement) @ctrl\
             (try_statement) @ctrl\
             (catch_clause) @ctrl\
             (return_statement) @ctrl",
        )
    });
    let assign_query = ASSIGN_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(assignment_expression) @assign (variable_declarator) @assign",
        )
    });

    let tree = if let Some(tree) = cache.and_then(|c| c.tree.as_ref()) {
        tree.clone()
    } else {
        PARSER.with(|parser| {
            let mut parser = parser.borrow_mut();
            let _ = parser.set_included_ranges(&[]);
            parser.parse(bytes, None).map(std::sync::Arc::new)
        })?
    };

    let root = tree.root_node();
    let node = root.descendant_for_byte_range(pos, pos)?;

    let mut ctx = FlowContext::default();
    ctx.import_hints = cache.map(|c| c.import_hints.clone()).unwrap_or_default();

    let mut depth = 0usize;
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "statement_block" || n.kind() == "block" {
            depth += 1;
        }
        cursor = n.parent();
    }
    ctx.block_depth = depth;

    if let Ok(func_query) = func_query {
        if let Some((func_node, name)) = find_js_enclosing_function(root, node, bytes, func_query) {
            ctx.scope_kind = Some("function".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));

            // Deep AST Analysis
            ctx.cognitive_complexity = compute_js_cognitive_complexity(func_node, bytes);
            ctx.taint_summary = compute_js_taint_flow(func_node, node, bytes);
            ctx.flow_stack = estimate_ast_flow_stack(func_node, node);
        }
    }

    if let Ok(ctrl_query) = ctrl_query {
        if let Some(ctrl_node) = find_js_control_ancestor(root, node, bytes, ctrl_query) {
            ctx.nearest_control = Some(ctrl_node.kind().to_string());
            let start = ctrl_node.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    if let Ok(assign_query) = assign_query {
        if let Some(assign) = find_js_assignment_ancestor(root, node, bytes, assign_query) {
            ctx.assignment_distance = Some(pos.saturating_sub(assign.start_byte()));
        }
    }

    if let Some(ret) = find_js_return_ancestor(node) {
        ctx.return_distance = Some(pos.saturating_sub(ret.start_byte()));
    }

    if let Some(chain) = find_js_call_chain(node, bytes) {
        ctx.call_chain_hint = Some(chain);
    }

    Some(ctx)
}

static IMPORT_AC: OnceLock<(AhoCorasick, Vec<&'static str>)> = OnceLock::new();

pub fn scan_import_hints(bytes: &[u8]) -> Vec<String> {
    // Only scan first 8KB of file for imports
    let sample_len = bytes.len().min(8192);
    let sample = &bytes[..sample_len];

    let (ac, kws) = IMPORT_AC.get_or_init(|| {
        let keywords: &[&str] = &[
            "import",
            "require",
            "use",
            "include",
            "from",
            "package",
            "crypto",
            "os",
            "child_process",
            "requests",
            "axios",
            "fs",
            "path",
            "sql",
            "postgres",
            "mysql",
            "mongodb",
            "dotenv",
            "jsonwebtoken",
        ];
        (
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(keywords)
                .unwrap(),
            keywords.to_vec(),
        )
    });

    let mut hints = Vec::new();
    let suspicious_libs: &[(&str, &str)] = &[
        ("crypto", "crypto"),
        ("os", "os"),
        ("child_process", "process"),
        ("requests", "net"),
        ("axios", "net"),
        ("fs", "io"),
        ("path", "io"),
        ("sql", "db"),
        ("postgres", "db"),
        ("mysql", "db"),
        ("mongodb", "db"),
        ("dotenv", "env"),
        ("jsonwebtoken", "auth"),
    ];

    let mut found_libs = HashSet::new();
    let mut import_kw_positions = Vec::new();
    let import_kws = ["import", "require", "use", "include", "from", "package"];

    for mat in ac.find_iter(sample) {
        let text = kws[mat.pattern().as_usize()];
        if import_kws.contains(&text) {
            import_kw_positions.push(mat.start());
        } else {
            for (lib, label) in suspicious_libs {
                if *lib == text {
                    found_libs.insert((*lib, *label, mat.start()));
                }
            }
        }
    }

    for (_lib, label, lib_pos) in found_libs {
        // Check if any import keyword is near this lib
        for &kw_pos in &import_kw_positions {
            if (kw_pos as isize - lib_pos as isize).abs() < 100 {
                if !hints.contains(&label.to_string()) {
                    hints.push(label.to_string());
                }
                break;
            }
        }
    }

    hints
}

fn analyze_taint(window: &[u8], rel_pos: usize) -> Option<String> {
    let mut sources_found = Vec::new();
    let mut sinks_found = Vec::new();

    let mut tokenizer = CodeTokenizer::new(window);
    while let Some(token) = tokenizer.next_token() {
        if is_taint_source(token.text) {
            sources_found.push((token.text.to_string(), token.pos));
        }
        if is_taint_sink(token.text) {
            sinks_found.push((token.text.to_string(), token.pos));
        }
    }

    let mut best_source = None;
    for (name, pos) in sources_found {
        if pos < rel_pos {
            best_source = Some(name);
        }
    }

    let mut best_sink = None;
    for (name, pos) in sinks_found {
        if (pos as isize - rel_pos as isize).abs() < 256 {
            best_sink = Some(name);
            break;
        }
    }

    match (best_source, best_sink) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", extract_taint_source_base(&src), sink)),
        (Some(src), None) => Some(format!("{}->?", extract_taint_source_base(&src))),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

static SEMANTIC_AC: OnceLock<(AhoCorasick, Vec<(&'static str, &'static [&'static [u8]])>)> =
    OnceLock::new();

pub fn detect_semantic_clusters(window: &[u8]) -> Vec<String> {
    let (ac, clusters) = SEMANTIC_AC.get_or_init(|| {
        let clusters: &[(&'static str, &'static [&'static [u8]])] = &[
            (
                "Auth",
                &[
                    b"login",
                    b"auth",
                    b"password",
                    b"token",
                    b"credential",
                    b"session",
                    b"jwt",
                    b"cookie",
                    b"apikey",
                    b"secret",
                ],
            ),
            (
                "DB",
                &[
                    b"select",
                    b"insert",
                    b"update",
                    b"delete",
                    b"query",
                    b"sql",
                    b"db",
                    b"database",
                    b"table",
                    b"connection",
                    b"transaction",
                ],
            ),
            (
                "Net",
                &[
                    b"http",
                    b"https",
                    b"tcp",
                    b"udp",
                    b"socket",
                    b"connect",
                    b"request",
                    b"response",
                    b"url",
                    b"fetch",
                    b"proxy",
                    b"dns",
                ],
            ),
            (
                "Crypto",
                &[
                    b"encrypt", b"decrypt", b"hash", b"sign", b"verify", b"cipher", b"aes", b"rsa",
                    b"key", b"iv", b"salt", b"hmac",
                ],
            ),
            (
                "Web",
                &[
                    b"html",
                    b"dom",
                    b"react",
                    b"component",
                    b"render",
                    b"element",
                    b"style",
                    b"css",
                    b"frontend",
                    b"client",
                ],
            ),
            (
                "IO",
                &[
                    b"read", b"write", b"file", b"fs", b"path", b"open", b"close", b"stream",
                    b"pipe",
                ],
            ),
            (
                "Process",
                &[
                    b"spawn", b"exec", b"fork", b"thread", b"mutex", b"lock", b"process", b"kill",
                    b"signal",
                ],
            ),
        ];

        let mut all_kws = Vec::new();
        for (_, kws) in clusters {
            for &kw in *kws {
                all_kws.push(kw);
            }
        }
        (
            AhoCorasick::new(all_kws).expect("failed to build semantic AC"),
            clusters.to_vec(),
        )
    });

    let mut detected = Vec::new();
    let mut cluster_hits = vec![0usize; clusters.len()];
    let mut seen_kws_per_cluster = vec![HashSet::new(); clusters.len()];

    for mat in ac.find_iter(window) {
        let pattern_idx = mat.pattern().as_usize();
        // Map pattern_idx back to cluster
        let mut current_idx = 0;
        for (cluster_idx, (_, kws)) in clusters.iter().enumerate() {
            if pattern_idx < current_idx + kws.len() {
                let kw_idx = pattern_idx - current_idx;
                let kw = kws[kw_idx];
                if is_word_boundary(window, mat.start(), kw.len()) {
                    if seen_kws_per_cluster[cluster_idx].insert(kw) {
                        cluster_hits[cluster_idx] += 1;
                    }
                }
                break;
            }
            current_idx += kws.len();
        }
    }

    let strong: &[&[u8]] = &[
        b"apikey",
        b"jwt",
        b"sql",
        b"https",
        b"encrypt",
        b"decrypt",
        b"fs",
        b"http",
        b"socket",
        b"password",
    ];

    for (i, (name, kws)) in clusters.iter().enumerate() {
        if cluster_hits[i] >= 2 {
            detected.push(name.to_string());
        } else if cluster_hits[i] == 1 {
            for &skw in strong {
                if kws.contains(&skw) && seen_kws_per_cluster[i].contains(skw) {
                    detected.push(name.to_string());
                    break;
                }
            }
        }
    }
    detected
}

#[cfg(feature = "js-ast")]
static JS_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "js-ast")]
fn js_language() -> &'static Language {
    JS_LANGUAGE.get_or_init(|| tree_sitter_javascript::LANGUAGE.into())
}

#[cfg(not(feature = "js-ast"))]
fn analyze_flow_context_js(
    _bytes: &[u8],
    _pos: usize,
    _cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    None
}

#[cfg(feature = "js-ast")]
fn find_js_enclosing_function<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m
            .captures
            .iter()
            .find(|c| {
                let k = c.node.kind();
                k.contains("function") || k == "method_definition" || k == "arrow_function"
            })
            .map(|c| c.node)
            .unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| {
                let k = c.node.kind();
                k == "identifier" || k == "property_identifier"
            })
            .map(|c| node_text(bytes, c.node));

        let start = func_node.start_byte();
        if start <= node.start_byte() && func_node.end_byte() >= node.end_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "js-ast")]
fn find_js_control_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let ctrl_node = m.captures[0].node;
        let start = ctrl_node.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((ctrl_node, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(feature = "js-ast")]
fn find_js_assignment_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let assign_node = m.captures[0].node;
        let start = assign_node.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((assign_node, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(feature = "js-ast")]
fn find_js_return_ancestor<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "return_statement" {
            return Some(n);
        }
        cursor = n.parent();
    }
    None
}

#[cfg(feature = "js-ast")]
fn compute_js_cognitive_complexity(func_node: tree_sitter::Node, bytes: &[u8]) -> usize {
    let mut complexity = 0usize;
    let mut stack = vec![(func_node, 0usize)]; // (node, nesting_level)

    while let Some((node, nesting)) = stack.pop() {
        let kind = node.kind();
        let mut new_nesting = nesting;
        let mut increment = 0usize;

        match kind {
            "if_statement" | "for_statement" | "for_in_statement" | "while_statement"
            | "do_statement" | "switch_statement" | "catch_clause" | "ternary_expression" => {
                increment = 1 + nesting;
                new_nesting += 1;
            }
            "else" => {
                // Else usually doesn't increase nesting but is an increment
                increment = 1;
            }
            "binary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| node_text(bytes, n));
                if let Some(op_text) = op {
                    if op_text == "&&" || op_text == "||" {
                        increment = 1;
                    }
                }
            }
            _ => {}
        }

        complexity += increment;

        // Push children with updated nesting
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push((child_cursor.node(), new_nesting));
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    complexity
}

#[cfg(feature = "js-ast")]
fn compute_js_taint_flow(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
    bytes: &[u8],
) -> Option<String> {
    let target_text = node_text(bytes, target_node);
    if !is_reasonable_ident(&target_text) {
        return None;
    }

    // 1. Def-Use analysis: Find where target_text is assigned
    let mut source_name = None;
    let mut stack = vec![func_node];

    while let Some(node) = stack.pop() {
        if node.kind() == "variable_declarator" || node.kind() == "assignment_expression" {
            let left = node.child_by_field_name("left").or_else(|| node.child(0));
            let right = node.child_by_field_name("right").or_else(|| node.child(2));

            if let (Some(l), Some(r)) = (left, right) {
                if node_text(bytes, l) == target_text {
                    let r_text = node_text(bytes, r);
                    if is_taint_source(&r_text) {
                        source_name = Some(extract_taint_source_base(&r_text));
                        break;
                    }
                }
            }
        }
        // Also check function parameters
        if node.kind() == "formal_parameters" {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    if node_text(bytes, c.node()) == target_text {
                        source_name = Some("param".to_string());
                        break;
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // 2. Reachability: Check if target_text is used in a sink
    let mut sink_name = None;
    stack = vec![func_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            let func = node.child_by_field_name("function");
            let args = node.child_by_field_name("arguments");
            if let (Some(f), Some(a)) = (func, args) {
                let f_text = node_text(bytes, f);
                if is_taint_sink(&f_text) {
                    // Check if target_text is in arguments
                    if node_text(bytes, a).contains(&target_text) {
                        sink_name = Some(f_text);
                        break;
                    }
                }
            }
        }
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    match (source_name, sink_name) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", src, sink)),
        (Some(src), None) => Some(format!("{}->?", src)),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

fn is_taint_source(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("req")
        || lower.contains("params")
        || lower.contains("env")
        || lower.contains("input")
}

fn extract_taint_source_base(text: &str) -> String {
    if text.contains("req") {
        "req".to_string()
    } else if text.contains("params") {
        "params".to_string()
    } else if text.contains("env") {
        "env".to_string()
    } else {
        "input".to_string()
    }
}

fn is_taint_sink(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("execute")
        || lower.contains("eval")
        || lower.contains("send")
        || lower.contains("write")
        || lower.contains("query")
        || lower.contains("fetch")
        || lower.contains("system")
        || lower.contains("exec")
        || lower.contains("spawn")
        || lower.contains("connect")
        || lower.contains("open")
}

#[cfg(feature = "js-ast")]
fn find_js_call_chain<'a>(node: tree_sitter::Node<'a>, bytes: &'a [u8]) -> Option<String> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "member_expression" {
            let obj = n.child_by_field_name("object");
            let prop = n.child_by_field_name("property");
            if let (Some(o), Some(p)) = (obj, prop) {
                let left = node_text(bytes, o);
                let right = node_text(bytes, p);
                if is_reasonable_ident(&left) && is_reasonable_ident(&right) {
                    return Some(format!("{}.{}", left, right));
                }
            }
        }
        cursor = n.parent();
    }
    None
}

#[cfg(feature = "tree-sitter")]
fn node_text<'a>(bytes: &'a [u8], node: tree_sitter::Node<'a>) -> String {
    let range = node.byte_range();
    String::from_utf8_lossy(&bytes[range]).to_string()
}

#[cfg(feature = "tree-sitter")]
fn byte_to_point(bytes: &[u8], pos: usize) -> tree_sitter::Point {
    let mut row = 0usize;
    let mut col = 0usize;
    let end = pos.min(bytes.len());
    for &b in &bytes[..end] {
        if b == b'\n' {
            row += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    tree_sitter::Point { row, column: col }
}

fn trim_value(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(max_len.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}
fn guess_semantic_name(flow: &FlowContext) -> Option<String> {
    // If we have a control flow keyword nearby, use it.
    if let Some(ctrl) = &flow.nearest_control {
        if ctrl.len() > 3 {
            return Some(ctrl.clone());
        }
    }
    // Or if the distance to a specific assignment is small
    if let Some(dist) = flow.assignment_distance {
        if dist < 50 {
            return Some("active-component".to_string());
        }
    }
    None
}

#[cfg(feature = "py-ast")]
static PY_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "py-ast")]
fn py_language() -> &'static Language {
    PY_LANGUAGE.get_or_init(|| tree_sitter_python::LANGUAGE.into())
}

#[cfg(feature = "tree-sitter")]
fn estimate_ast_flow_stack(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
) -> Vec<String> {
    let mut stack = Vec::new();
    let mut cursor = Some(target_node);
    while let Some(node) = cursor {
        if node == func_node {
            break;
        }
        let kind = node.kind();
        let label = match kind {
            "if_statement" | "if_expression" | "if_let_expression" => Some("if"),
            "for_statement" | "for_expression" => Some("for"),
            "while_statement" | "while_expression" | "while_let_expression" => Some("while"),
            "switch_statement" | "match_expression" | "match_statement" => Some("match"),
            "try_statement" | "try_expression" => Some("try"),
            "catch_clause" | "except_clause" => Some("catch"),
            "finally_clause" | "finally" => Some("finally"),
            "unsafe_block" => Some("unsafe"),
            "loop_expression" => Some("loop"),
            "with_statement" => Some("with"),
            _ => None,
        };
        if let Some(l) = label {
            stack.push(l.to_string());
        }
        cursor = node.parent();
    }
    stack.reverse();
    stack
}

#[cfg(feature = "py-ast")]
fn analyze_flow_context_py(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(py_language()).ok()?;

    let tree = if let Some(tree) = cache.and_then(|c| c.tree.as_ref()) {
        tree.clone()
    } else {
        parser.parse(bytes, None).map(std::sync::Arc::new)?
    };

    let root = tree.root_node();
    let point = byte_to_point(bytes, pos);
    let node = root.descendant_for_point_range(point, point)?;

    let mut ctx = FlowContext::default();
    ctx.import_hints = cache.map(|c| c.import_hints.clone()).unwrap_or_default();

    let func_query = tree_sitter::Query::new(
        py_language(),
        "(function_definition name: (identifier) @name) @func",
    )
    .ok();
    let class_query = tree_sitter::Query::new(
        py_language(),
        "(class_definition name: (identifier) @name) @class",
    )
    .ok();
    let ctrl_query = tree_sitter::Query::new(
        py_language(),
        "[\"if\" \"for\" \"while\" \"with\" \"try\" \"except\" \"finally\"] @ctrl",
    )
    .ok();

    if let Some(q) = func_query {
        if let Some((func_node, name)) = find_py_ancestor(root, node, bytes, &q) {
            ctx.scope_kind = Some("function".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));

            // Deep AST Analysis
            ctx.cognitive_complexity = compute_py_cognitive_complexity(func_node, bytes);
            ctx.taint_summary = compute_py_taint_flow(func_node, node, bytes);
            ctx.flow_stack = estimate_ast_flow_stack(func_node, node);
        }
    }
    if ctx.scope_kind.is_none() {
        if let Some(q) = class_query {
            if let Some((class_node, name)) = find_py_ancestor(root, node, bytes, &q) {
                ctx.scope_kind = Some("class".to_string());
                ctx.scope_name = name;
                let start = class_node.start_position();
                ctx.scope_line = Some(start.row + 1);
                ctx.scope_col = Some(start.column + 1);
            }
        }
    }

    if let Some(q) = ctrl_query {
        if let Some(ctrl) = find_py_ctrl_ancestor(root, node, bytes, &q) {
            ctx.nearest_control = Some(ctrl.kind().to_string());
            let start = ctrl.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    Some(ctx)
}

#[cfg(feature = "py-ast")]
fn find_py_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m
            .captures
            .iter()
            .find(|c| {
                let k = c.node.kind();
                k == "function_definition" || k == "class_definition"
            })
            .map(|c| c.node)
            .unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "identifier")
            .map(|c| node_text(bytes, c.node));

        let start = func_node.start_byte();
        if start <= node.start_byte() && func_node.end_byte() >= node.end_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "py-ast")]
fn compute_py_cognitive_complexity(func_node: tree_sitter::Node, _bytes: &[u8]) -> usize {
    let mut complexity = 0usize;
    let mut stack = vec![(func_node, 0usize)];

    while let Some((node, nesting)) = stack.pop() {
        let kind = node.kind();
        let mut new_nesting = nesting;
        let mut increment = 0usize;

        match kind {
            "if_statement"
            | "for_statement"
            | "while_statement"
            | "with_statement"
            | "try_statement"
            | "except_clause"
            | "conditional_expression" => {
                increment = 1 + nesting;
                new_nesting += 1;
            }
            "elif_clause" | "else_clause" => {
                increment = 1;
            }
            "boolean_operator" => {
                increment = 1;
            }
            _ => {}
        }

        complexity += increment;

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push((child_cursor.node(), new_nesting));
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    complexity
}

#[cfg(feature = "py-ast")]
fn compute_py_taint_flow(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
    bytes: &[u8],
) -> Option<String> {
    let target_text = node_text(bytes, target_node);
    if !is_reasonable_ident(&target_text) {
        return None;
    }

    let mut source_name = None;
    let mut stack = vec![func_node];

    while let Some(node) = stack.pop() {
        if node.kind() == "assignment" {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(l), Some(r)) = (left, right) {
                if node_text(bytes, l) == target_text {
                    let r_text = node_text(bytes, r);
                    if is_taint_source(&r_text) {
                        source_name = Some(extract_taint_source_base(&r_text));
                        break;
                    }
                }
            }
        }
        if node.kind() == "parameters" {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    if node_text(bytes, c.node()) == target_text {
                        source_name = Some("param".to_string());
                        break;
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    let mut sink_name = None;
    stack = vec![func_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            let func = node.child_by_field_name("function");
            let args = node.child_by_field_name("arguments");
            if let (Some(f), Some(a)) = (func, args) {
                let f_text = node_text(bytes, f);
                if is_taint_sink(&f_text) {
                    if node_text(bytes, a).contains(&target_text) {
                        sink_name = Some(f_text);
                        break;
                    }
                }
            }
        }
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    match (source_name, sink_name) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", src, sink)),
        (Some(src), None) => Some(format!("{}->?", src)),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

#[cfg(feature = "py-ast")]
fn find_py_ctrl_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let n = m.captures[0].node;
        let start = n.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((n, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(feature = "go-ast")]
static GO_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "go-ast")]
fn go_language() -> &'static Language {
    GO_LANGUAGE.get_or_init(|| tree_sitter_go::LANGUAGE.into())
}

#[cfg(feature = "go-ast")]
fn analyze_flow_context_go(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(go_language()).ok()?;

    let tree = if let Some(tree) = cache.and_then(|c| c.tree.as_ref()) {
        tree.clone()
    } else {
        parser.parse(bytes, None).map(std::sync::Arc::new)?
    };

    let root = tree.root_node();
    let point = byte_to_point(bytes, pos);
    let node = root.descendant_for_point_range(point, point)?;

    let mut ctx = FlowContext::default();
    ctx.import_hints = cache.map(|c| c.import_hints.clone()).unwrap_or_default();

    let func_query = tree_sitter::Query::new(
        go_language(),
        "(function_declaration name: (identifier) @name) @func",
    )
    .ok();
    let method_query = tree_sitter::Query::new(
        go_language(),
        "(method_declaration name: (field_identifier) @name) @func",
    )
    .ok();
    let ctrl_query = tree_sitter::Query::new(
        go_language(),
        "[\"if\" \"for\" \"switch\" \"select\" \"defer\" \"go\"] @ctrl",
    )
    .ok();

    if let Some(q) = func_query {
        if let Some((func_node, name)) = find_go_ancestor(root, node, bytes, &q) {
            ctx.scope_kind = Some("function".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));

            // Deep AST Analysis
            ctx.cognitive_complexity = compute_go_cognitive_complexity(func_node, bytes);
            ctx.taint_summary = compute_go_taint_flow(func_node, node, bytes);
            ctx.flow_stack = estimate_ast_flow_stack(func_node, node);
        }
    }
    if ctx.scope_kind.is_none() {
        if let Some(q) = method_query {
            if let Some((method_node, name)) = find_go_ancestor(root, node, bytes, &q) {
                ctx.scope_kind = Some("method".to_string());
                ctx.scope_name = name;
                let start = method_node.start_position();
                ctx.scope_line = Some(start.row + 1);
                ctx.scope_col = Some(start.column + 1);
            }
        }
    }

    if let Some(q) = ctrl_query {
        if let Some(ctrl) = find_go_ctrl_ancestor(root, node, bytes, &q) {
            ctx.nearest_control = Some(ctrl.kind().to_string());
            let start = ctrl.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    Some(ctx)
}

#[cfg(feature = "go-ast")]
fn find_go_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m
            .captures
            .iter()
            .find(|c| {
                let k = c.node.kind();
                k == "function_declaration" || k == "method_declaration"
            })
            .map(|c| c.node)
            .unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| {
                let k = c.node.kind();
                k == "identifier" || k == "field_identifier"
            })
            .map(|c| node_text(bytes, c.node));

        let start = func_node.start_byte();
        if start <= node.start_byte() && func_node.end_byte() >= node.end_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "go-ast")]
fn compute_go_cognitive_complexity(func_node: tree_sitter::Node, bytes: &[u8]) -> usize {
    let mut complexity = 0usize;
    let mut stack = vec![(func_node, 0usize)];

    while let Some((node, nesting)) = stack.pop() {
        let kind = node.kind();
        let mut new_nesting = nesting;
        let mut increment = 0usize;

        match kind {
            "if_statement" | "for_statement" | "switch_statement" | "select_statement"
            | "communication_case" | "case_clause" => {
                increment = 1 + nesting;
                new_nesting += 1;
            }
            "binary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| node_text(bytes, n));
                if let Some(op_text) = op {
                    if op_text == "&&" || op_text == "||" {
                        increment = 1;
                    }
                }
            }
            _ => {}
        }

        complexity += increment;

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push((child_cursor.node(), new_nesting));
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    complexity
}

#[cfg(feature = "go-ast")]
fn compute_go_taint_flow(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
    bytes: &[u8],
) -> Option<String> {
    let target_text = node_text(bytes, target_node);
    if !is_reasonable_ident(&target_text) {
        return None;
    }

    let mut source_name = None;
    let mut stack = vec![func_node];

    while let Some(node) = stack.pop() {
        if node.kind() == "assignment_statement" || node.kind() == "short_var_declaration" {
            let left = node.child_by_field_name("left").or_else(|| node.child(0));
            let right = node.child_by_field_name("right").or_else(|| node.child(2));
            if let (Some(l), Some(r)) = (left, right) {
                if node_text(bytes, l).contains(&target_text) {
                    let r_text = node_text(bytes, r);
                    if is_taint_source(&r_text) {
                        source_name = Some(extract_taint_source_base(&r_text));
                        break;
                    }
                }
            }
        }
        if node.kind() == "parameter_list" {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    if node_text(bytes, c.node()) == target_text {
                        source_name = Some("param".to_string());
                        break;
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    let mut sink_name = None;
    stack = vec![func_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            let func = node.child_by_field_name("function");
            let args = node.child_by_field_name("arguments");
            if let (Some(f), Some(a)) = (func, args) {
                let f_text = node_text(bytes, f);
                if is_taint_sink(&f_text) {
                    if node_text(bytes, a).contains(&target_text) {
                        sink_name = Some(f_text);
                        break;
                    }
                }
            }
        }
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    match (source_name, sink_name) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", src, sink)),
        (Some(src), None) => Some(format!("{}->?", src)),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

#[cfg(feature = "go-ast")]
fn find_go_ctrl_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let n = m.captures[0].node;
        let start = n.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((n, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(not(feature = "py-ast"))]
fn analyze_flow_context_py(
    _bytes: &[u8],
    _pos: usize,
    _cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    None
}

#[cfg(not(feature = "go-ast"))]
fn analyze_flow_context_go(
    _bytes: &[u8],
    _pos: usize,
    _cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    None
}

#[cfg(feature = "rust-ast")]
static RUST_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "rust-ast")]
fn compute_rust_cognitive_complexity(func_node: tree_sitter::Node, bytes: &[u8]) -> usize {
    let mut complexity = 0usize;
    let mut stack = vec![(func_node, 0usize)];

    while let Some((node, nesting)) = stack.pop() {
        let kind = node.kind();
        let mut new_nesting = nesting;
        let mut increment = 0usize;

        match kind {
            "if_expression"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
            | "match_expression"
            | "if_let_expression"
            | "while_let_expression" => {
                increment = 1 + nesting;
                new_nesting += 1;
            }
            "else_clause" => {
                increment = 1;
            }
            "binary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| node_text(bytes, n));
                if let Some(op_text) = op {
                    if op_text == "&&" || op_text == "||" {
                        increment = 1;
                    }
                }
            }
            _ => {}
        }

        complexity += increment;

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push((child_cursor.node(), new_nesting));
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    complexity
}

#[cfg(feature = "rust-ast")]
fn compute_rust_taint_flow(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
    bytes: &[u8],
) -> Option<String> {
    let target_text = node_text(bytes, target_node);
    if !is_reasonable_ident(&target_text) {
        return None;
    }

    let mut source_name = None;
    let mut stack = vec![func_node];

    while let Some(node) = stack.pop() {
        if node.kind() == "let_declaration" || node.kind() == "assignment_expression" {
            let left = node
                .child_by_field_name("pattern")
                .or_else(|| node.child(0));
            let right = node.child_by_field_name("value").or_else(|| node.child(2));
            if let (Some(l), Some(r)) = (left, right) {
                if node_text(bytes, l).contains(&target_text) {
                    let r_text = node_text(bytes, r);
                    if is_taint_source(&r_text) {
                        source_name = Some(extract_taint_source_base(&r_text));
                        break;
                    }
                }
            }
        }
        if node.kind() == "parameters" {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    if node_text(bytes, c.node()) == target_text {
                        source_name = Some("param".to_string());
                        break;
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    let mut sink_name = None;
    stack = vec![func_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            let func = node.child_by_field_name("function");
            let args = node.child_by_field_name("arguments");
            if let (Some(f), Some(a)) = (func, args) {
                let f_text = node_text(bytes, f);
                if is_taint_sink(&f_text) {
                    if node_text(bytes, a).contains(&target_text) {
                        sink_name = Some(f_text);
                        break;
                    }
                }
            }
        }
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    match (source_name, sink_name) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", src, sink)),
        (Some(src), None) => Some(format!("{}->?", src)),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

#[cfg(feature = "java-ast")]
fn compute_java_cognitive_complexity(func_node: tree_sitter::Node, bytes: &[u8]) -> usize {
    let mut complexity = 0usize;
    let mut stack = vec![(func_node, 0usize)];

    while let Some((node, nesting)) = stack.pop() {
        let kind = node.kind();
        let mut new_nesting = nesting;
        let mut increment = 0usize;

        match kind {
            "if_statement" | "for_statement" | "while_statement" | "do_statement"
            | "switch_statement" | "catch_clause" | "ternary_expression" => {
                increment = 1 + nesting;
                new_nesting += 1;
            }
            "else" => {
                increment = 1;
            }
            "binary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| node_text(bytes, n));
                if let Some(op_text) = op {
                    if op_text == "&&" || op_text == "||" {
                        increment = 1;
                    }
                }
            }
            _ => {}
        }

        complexity += increment;

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push((child_cursor.node(), new_nesting));
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    complexity
}

#[cfg(feature = "java-ast")]
fn compute_java_taint_flow(
    func_node: tree_sitter::Node,
    target_node: tree_sitter::Node,
    bytes: &[u8],
) -> Option<String> {
    let target_text = node_text(bytes, target_node);
    if !is_reasonable_ident(&target_text) {
        return None;
    }

    let mut source_name = None;
    let mut stack = vec![func_node];

    while let Some(node) = stack.pop() {
        if node.kind() == "variable_declarator" || node.kind() == "assignment_expression" {
            let left = node.child_by_field_name("name").or_else(|| node.child(0));
            let right = node.child_by_field_name("value").or_else(|| node.child(2));
            if let (Some(l), Some(r)) = (left, right) {
                if node_text(bytes, l) == target_text {
                    let r_text = node_text(bytes, r);
                    if is_taint_source(&r_text) {
                        source_name = Some(extract_taint_source_base(&r_text));
                        break;
                    }
                }
            }
        }
        if node.kind() == "formal_parameters" {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    if c.node().kind() == "formal_parameter" {
                        if let Some(id) = c.node().child_by_field_name("name") {
                            if node_text(bytes, id) == target_text {
                                source_name = Some("param".to_string());
                                break;
                            }
                        }
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    let mut sink_name = None;
    stack = vec![func_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "method_invocation" {
            let name = node.child_by_field_name("name");
            let args = node.child_by_field_name("arguments");
            if let (Some(n), Some(a)) = (name, args) {
                let n_text = node_text(bytes, n);
                if is_taint_sink(&n_text) {
                    if node_text(bytes, a).contains(&target_text) {
                        sink_name = Some(n_text);
                        break;
                    }
                }
            }
        }
        let mut child_cursor = node.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    match (source_name, sink_name) {
        (Some(src), Some(sink)) => Some(format!("{}->{}", src, sink)),
        (Some(src), None) => Some(format!("{}->?", src)),
        (None, Some(sink)) => Some(format!("?->{}", sink)),
        _ => None,
    }
}

#[cfg(feature = "rust-ast")]
fn rust_language() -> &'static Language {
    RUST_LANGUAGE.get_or_init(|| tree_sitter_rust::LANGUAGE.into())
}

#[cfg(feature = "rust-ast")]
fn analyze_flow_context_rust(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(rust_language()).ok()?;

    let tree = if let Some(tree) = cache.and_then(|c| c.tree.as_ref()) {
        tree.clone()
    } else {
        parser.parse(bytes, None).map(std::sync::Arc::new)?
    };

    let root = tree.root_node();
    let point = byte_to_point(bytes, pos);
    let node = root.descendant_for_point_range(point, point)?;

    let mut ctx = FlowContext::default();
    ctx.import_hints = cache.map(|c| c.import_hints.clone()).unwrap_or_default();

    let func_query = tree_sitter::Query::new(
        rust_language(),
        "(function_item name: (identifier) @name) @func",
    )
    .ok();
    let ctrl_query = tree_sitter::Query::new(
        rust_language(),
        "[\"if\" \"for\" \"while\" \"loop\" \"match\" \"if let\" \"while let\"] @ctrl",
    )
    .ok();

    if let Some(q) = func_query {
        if let Some((func_node, name)) = find_rust_ancestor(root, node, bytes, &q) {
            ctx.scope_kind = Some("function".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));

            // Deep AST Analysis
            ctx.cognitive_complexity = compute_rust_cognitive_complexity(func_node, bytes);
            ctx.taint_summary = compute_rust_taint_flow(func_node, node, bytes);
            ctx.flow_stack = estimate_ast_flow_stack(func_node, node);
        }
    }

    if let Some(q) = ctrl_query {
        if let Some(ctrl) = find_rust_ctrl_ancestor(root, node, bytes, &q) {
            ctx.nearest_control = Some(ctrl.kind().to_string());
            let start = ctrl.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    Some(ctx)
}

#[cfg(feature = "rust-ast")]
fn find_rust_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "function_item")
            .map(|c| c.node)
            .unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "identifier")
            .map(|c| node_text(bytes, c.node));

        let start = func_node.start_byte();
        if start <= node.start_byte() && func_node.end_byte() >= node.end_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "rust-ast")]
fn find_rust_ctrl_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let n = m.captures[0].node;
        let start = n.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((n, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(not(feature = "rust-ast"))]
fn analyze_flow_context_rust(
    _bytes: &[u8],
    _pos: usize,
    _cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    None
}

#[cfg(feature = "java-ast")]
static JAVA_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "java-ast")]
fn java_language() -> &'static Language {
    JAVA_LANGUAGE.get_or_init(|| tree_sitter_java::LANGUAGE.into())
}

#[cfg(feature = "java-ast")]
fn analyze_flow_context_java(
    bytes: &[u8],
    pos: usize,
    cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(java_language()).ok()?;

    let tree = if let Some(tree) = cache.and_then(|c| c.tree.as_ref()) {
        tree.clone()
    } else {
        parser.parse(bytes, None).map(std::sync::Arc::new)?
    };

    let root = tree.root_node();
    let point = byte_to_point(bytes, pos);
    let node = root.descendant_for_point_range(point, point)?;

    let mut ctx = FlowContext::default();
    ctx.import_hints = cache.map(|c| c.import_hints.clone()).unwrap_or_default();

    let func_query = tree_sitter::Query::new(
        java_language(),
        "(method_declaration name: (identifier) @name) @func",
    )
    .ok();
    let ctrl_query = tree_sitter::Query::new(
        java_language(),
        "[\"if\" \"for\" \"while\" \"switch\" \"try\" \"catch\" \"finally\" \"synchronized\" \"throw\" \"return\"] @ctrl",
    )
    .ok();

    if let Some(q) = func_query {
        if let Some((func_node, name)) = find_java_ancestor(root, node, bytes, &q) {
            ctx.scope_kind = Some("method".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));

            // Deep AST Analysis
            ctx.cognitive_complexity = compute_java_cognitive_complexity(func_node, bytes);
            ctx.taint_summary = compute_java_taint_flow(func_node, node, bytes);
            ctx.flow_stack = estimate_ast_flow_stack(func_node, node);
        }
    }

    if let Some(q) = ctrl_query {
        if let Some(ctrl) = find_java_ctrl_ancestor(root, node, bytes, &q) {
            ctx.nearest_control = Some(ctrl.kind().to_string());
            let start = ctrl.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    Some(ctx)
}

#[cfg(feature = "java-ast")]
fn find_java_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "method_declaration")
            .map(|c| c.node)
            .unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "identifier")
            .map(|c| node_text(bytes, c.node));

        let start = func_node.start_byte();
        if start <= node.start_byte() && func_node.end_byte() >= node.end_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "java-ast")]
fn find_java_ctrl_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let n = m.captures[0].node;
        let start = n.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((n, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(not(feature = "java-ast"))]
fn analyze_flow_context_java(
    _bytes: &[u8],
    _pos: usize,
    _cache: Option<&FileAnalysisCache>,
) -> Option<FlowContext> {
    None
}
