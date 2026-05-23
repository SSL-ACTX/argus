use argus::report::grammar::{generate_story, GrammarContext};

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
    assert!(out.contains("normal"));
}
