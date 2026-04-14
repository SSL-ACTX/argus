use crate::utils::confidence_tier;
use std::collections::HashSet;

pub struct GrammarContext<'a> {
    pub matched: &'a str,
    pub count: usize,
    pub occ_index: usize,
    pub neighbor: Option<usize>,
    pub call_sites: usize,
    pub span: Option<usize>,
    pub density: usize,
    pub signals: &'a [String],
    pub confidence: u8,
    pub nearest_call: Option<(usize, usize, usize)>,
    pub id_hint: &'a str,
    pub source_label: &'a str,
    pub token_type: Option<&'a str>,
    pub token_shape: Option<&'a str>,
    pub composition: Option<(u8, u8, u8)>, // alpha, digit, other
}

fn has<S: AsRef<str>>(signals: &[String], key: S) -> bool {
    signals.iter().any(|s| s == key.as_ref())
}

/// Very small rule-driven generator that composes a human-friendly paragraph
/// from the provided context. This intentionally stays deterministic and
/// conservative to avoid hallucinations while producing readable English.
pub fn generate_story(ctx: &GrammarContext<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Opening clause
    if ctx.count <= 1 {
        parts.push(format!(
            "Story: '{}' was observed once in {}.",
            ctx.matched, ctx.source_label
        ));
    } else {
        parts.push(format!(
            "Story: '{}' appears {} times in {}.",
            ctx.matched, ctx.count, ctx.source_label
        ));
    }

    // Structural metadata
    if let (Some(t_type), Some(t_shape)) = (ctx.token_type, ctx.token_shape) {
        if t_type == t_shape {
            parts.push(format!(
                "Structurally, it matches the signature of a {} token.",
                t_type
            ));
        } else {
            parts.push(format!(
                "Structurally, it resembles a {} ({} shape) token.",
                t_type, t_shape
            ));
        }
    } else if let Some(t_type) = ctx.token_type {
        parts.push(format!("This appears to be a {} token.", t_type));
    } else if let Some(t_shape) = ctx.token_shape {
        parts.push(format!("The token follows a {} shape.", t_shape));
    }

    // Composition details
    if let Some((a, d, o)) = ctx.composition {
        let mut comp_parts = Vec::new();
        if a > 0 {
            comp_parts.push(format!("{}% alpha", a));
        }
        if d > 0 {
            comp_parts.push(format!("{}% numeric", d));
        }
        if o > 0 {
            comp_parts.push(format!("{}% special", o));
        }
        if !comp_parts.is_empty() {
            parts.push(format!("Character mix: {}.", comp_parts.join(", ")));
        }
    }

    // Locality and density
    if let Some(span) = ctx.span {
        let density_word = if ctx.density > 60 {
            "highly concentrated"
        } else if ctx.density > 30 {
            "moderately active"
        } else {
            "thinly scattered"
        };
        parts.push(format!(
            "The instances span ~{} bytes and are {}.",
            span, density_word
        ));
    }
    if let Some(n) = ctx.neighbor {
        parts.push(format!(
            "A sibling instance was detected approximately {} bytes away.",
            n
        ));
    }

    // Call sites
    if ctx.call_sites > 0 {
        if let Some((l, c, d)) = ctx.nearest_call {
            parts.push(format!(
                "The scanner identified {} call-site(s) referencing this token, with the primary reference at L{} C{} (~{} bytes offset).",
                ctx.call_sites, l, c, d
            ));
        } else {
            parts.push(format!(
                "There are {} call-site(s) referencing this token within the local module.",
                ctx.call_sites
            ));
        }
    } else {
        parts.push("No immediate call-reference sites were found.".to_string());
    }

    // Signals-driven phrasing
    let mut ctx_phrases: Vec<String> = Vec::new();
    if has(ctx.signals, "auth-header") {
        ctx_phrases.push("found within an authentication header".to_string());
    }
    if has(ctx.signals, "header") {
        ctx_phrases.push("header-like context".to_string());
    }
    if has(ctx.signals, "keyword-hint") {
        ctx_phrases.push("token value resembles a sensitive secret".to_string());
    }
    if has(ctx.signals, "id-hint") {
        ctx_phrases.push("assigned to an identifier commonly associated with secrets".to_string());
    }
    if has(ctx.signals, "url-param") {
        ctx_phrases.push("embedded in a URL query parameter".to_string());
    }
    if has(ctx.signals, "doc-context") {
        ctx_phrases.push("located in documentation or example code".to_string());
    }
    if has(ctx.signals, "infra-context") {
        ctx_phrases.push("found in infrastructure or configuration paths".to_string());
    }
    if has(ctx.signals, "function-name") {
        ctx_phrases.push("used as a function name (false positive risk)".to_string());
    }
    if has(ctx.signals, "tooling-call-density") {
        ctx_phrases.push("highly repetitive usage typical of language tooling".to_string());
    }
    if has(ctx.signals, "parser-context") {
        ctx_phrases.push("adjacent to parser/lexer logic".to_string());
    }
    if has(ctx.signals, "generic-keyword") {
        ctx_phrases.push("generic keyword usage context".to_string());
    }
    if has(ctx.signals, "telegram") || has(ctx.signals, "telegram-bot-token") {
        ctx_phrases.push("strong Telegram Bot API signature detected".to_string());
    }

    if !ctx_phrases.is_empty() {
        parts.push(format!("Contextual signals: {}.", ctx_phrases.join(", ")));
    }

    if !ctx.id_hint.is_empty() {
        let hint = ctx
            .id_hint
            .trim_start_matches("; ")
            .trim_start_matches("id ");
        parts.push(format!("Identifier hint: '{}'.", hint));
    }

    // Confidence and guidance
    let (badge, tier_label) = confidence_tier(ctx.confidence);
    let sigs: HashSet<&str> = ctx.signals.iter().map(|s| s.as_str()).collect();

    let is_high_risk = ctx.confidence >= 8 || sigs.contains("high-risk-keyword");
    let is_medium_risk =
        (ctx.confidence >= 5) || (ctx.confidence >= 3 && sigs.contains("keyword-hint"));

    let guidance = if is_high_risk {
        "Strategic Risk: High — immediate defensive action and credential rotation recommended."
    } else if is_medium_risk {
        "Manual Audit Required: Significant patterns detected. Verify sensitivity in the target codebase."
    } else {
        "Informational: Low likelihood of exploitability. Observed for comprehensive documentation."
    };

    parts.push(format!(
        "{} {} — {} (Confidence rating: {}/10).",
        badge, tier_label, guidance, ctx.confidence
    ));

    // Join into a single structured paragraph
    let paragraph = parts.join(" ");

    format!("{}\n", paragraph)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_generates_story_with_markers() {
        let ctx = GrammarContext {
            matched: "token",
            count: 3,
            occ_index: 1,
            neighbor: Some(12),
            call_sites: 2,
            span: Some(200),
            density: 30,
            signals: &vec!["keyword-hint".to_string(), "auth-header".to_string()],
            confidence: 6,
            nearest_call: Some((10, 2, 50)),
            id_hint: "apiKey",
            source_label: "src/app.js",
            token_type: Some("hex"),
            token_shape: Some("hex"),
            composition: Some((50, 40, 10)),
        };
        let out = generate_story(&ctx);
        assert!(out.contains("Story:"));
        assert!(!out.contains("Source:"));
        assert!(out.contains("Medium confidence"));
    }
}
