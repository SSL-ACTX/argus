use argus::analysis::FlowMode;
use argus::cli::OutputTuning;
use argus::report::MatchRecord;
use argus::scanner::entropy::adaptive_confidence_entropy;
use argus::scanner::keyword::process_search;
use argus::scanner::{
    apply_suppression_rules, build_api_capability_hints, build_attack_surface_links,
    build_auth_drift_hints, build_comment_escalation_hints, build_endpoint_shape_morphing_hints,
    build_protocol_drift_hints, build_response_class_hints, build_shadowing_hints,
    build_suppression_hints, classify_endpoint, extract_attack_surface_hints, DiffSummary,
    LateralLinkage, SuppressionAuditTracker, SuppressionRule,
};

#[test]
fn attack_surface_extracts_endpoints() {
    let src = br#"
const API_BASE_URL = "http://localhost:5000";
const PROD = "https://api.example.com";
fetch(`${API_BASE_URL}/api/projects`);
fetch("/api/account/profile/me");
"#;
    let hints = extract_attack_surface_hints(src);
    assert!(hints.iter().any(|h| h.url.contains("localhost:5000")));
    assert!(hints
        .iter()
        .any(|h| h.url.contains("/api/account/profile/me")));
    assert!(hints
        .iter()
        .any(|h| h.url.contains("https://api.example.com")));
}

#[test]
fn classify_endpoint_detects_public_localhost() {
    assert_eq!(classify_endpoint("http://localhost:5000"), "localhost");
    assert_eq!(classify_endpoint("https://api.example.com"), "public");
    assert_eq!(classify_endpoint("/api/projects"), "relative");
}

#[test]
fn attack_surface_links_requests_to_endpoints() {
    let src = br#"
const API_BASE_URL = "http://localhost:5000";
fetch(`${API_BASE_URL}/api/projects`);
"#;
    let hints = extract_attack_surface_hints(src);
    let records = vec![MatchRecord {
        source: "test.js".to_string(),
        kind: "request-trace".to_string(),
        matched: "fetch".to_string(),
        line: 2,
        col: 1,
        entropy: None,
        context: "fetch(`${API_BASE_URL}/api/projects`)".to_string(),
        identifier: None,
    }];
    let links = build_attack_surface_links(&records, &hints);
    assert!(!links.is_empty());
    assert!(links.iter().any(|l| l.endpoint.contains("/api/projects")));
    assert!(links.iter().any(|l| l.class == "localhost"));
}

#[test]
fn diff_summary_renders() {
    let mut summary = DiffSummary::default();
    summary.update(
        "src/lib.rs",
        &[MatchRecord {
            source: "src/lib.rs".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 1,
            col: 1,
            entropy: None,
            context: "token".to_string(),
            identifier: None,
        }],
    );
    let out = summary.render().unwrap_or_default();
    assert!(out.contains("Diff Summary"));
    assert!(out.contains("keyword"));
}

#[test]
fn suppression_hints_generated_for_examples() {
    let recs = vec![MatchRecord {
        source: "src/app.js".to_string(),
        kind: "keyword".to_string(),
        matched: "token".to_string(),
        line: 10,
        col: 5,
        entropy: None,
        context: "// example token for docs".to_string(),
        identifier: Some("exampleToken".to_string()),
    }];
    let hints = build_suppression_hints(&recs);
    assert!(!hints.is_empty());
    assert!(hints[0].rule.contains("id:"));
}

#[test]
fn suppression_rules_filter_matches() {
    let recs = vec![MatchRecord {
        source: "src/app.js".to_string(),
        kind: "keyword".to_string(),
        matched: "token".to_string(),
        line: 10,
        col: 5,
        entropy: None,
        context: "token".to_string(),
        identifier: Some("apiToken".to_string()),
    }];
    let rules = vec![SuppressionRule::Id("apiToken".to_string())];
    let (filtered, suppressed) = apply_suppression_rules(&recs, &rules);
    assert_eq!(suppressed, 1);
    assert!(filtered.is_empty());
}

#[test]
fn adaptive_confidence_downweights_docs() {
    let raw = "// example token used in docs";
    let (signals, confidence) = adaptive_confidence_entropy(
        raw,
        Some("exampleToken"),
        "abcdEFGHijklMNOPqrstUVWX",
        5.2,
        "docs/README.md",
    );
    assert!(signals.iter().any(|s| *s == "doc-context"));
    assert!(confidence <= 6);
}

#[test]
fn adaptive_confidence_flags_infra_paths() {
    let raw = "const token = \"ABCD1234EFGH5678\";";
    let (signals, _confidence) = adaptive_confidence_entropy(
        raw,
        Some("apiToken"),
        "ABCD1234EFGH5678",
        5.1,
        "infra/k8s/secrets.yaml",
    );
    assert!(signals.iter().any(|s| *s == "infra-context"));
}

#[test]
fn suppression_audit_flags_stale_and_broad_rules() {
    let rules = vec![
        SuppressionRule::Id("nope".to_string()),
        SuppressionRule::SourceLineKind {
            source: "src/app.js".to_string(),
            line: 10,
            kind: "keyword".to_string(),
        },
    ];
    let recs = vec![
        MatchRecord {
            source: "src/app.js".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 10,
            col: 5,
            entropy: None,
            context: "token".to_string(),
            identifier: None,
        },
        MatchRecord {
            source: "src/app.js".to_string(),
            kind: "keyword".to_string(),
            matched: "secret".to_string(),
            line: 10,
            col: 15,
            entropy: None,
            context: "secret".to_string(),
            identifier: None,
        },
    ];

    let mut tracker = SuppressionAuditTracker::new(&rules);
    tracker.update(&recs);
    let audit = tracker.render();

    assert!(audit.iter().any(|a| a.status == "stale"));
    assert!(audit.iter().any(|a| a.status == "broad"));
}

#[test]
fn shadowing_detects_placeholder_then_secret() {
    let recs = vec![
        MatchRecord {
            source: "src/app.js".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 5,
            col: 10,
            entropy: None,
            context: "// example token".to_string(),
            identifier: Some("apiToken".to_string()),
        },
        MatchRecord {
            source: "src/app.js".to_string(),
            kind: "entropy".to_string(),
            matched: "ABCD1234EFGH5678".to_string(),
            line: 20,
            col: 8,
            entropy: Some(5.5),
            context: "const apiToken = \"ABCD1234EFGH5678\"".to_string(),
            identifier: Some("apiToken".to_string()),
        },
    ];

    let hints = build_shadowing_hints(&recs);
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].identifier, "apiToken");
    assert_eq!(hints[0].earlier_line, 5);
    assert_eq!(hints[0].line, 20);
}

#[test]
fn protocol_drift_detects_http_https() {
    let src = br#"
const A = "http://api.example.com/v1";
const B = "https://api.example.com/v1";
"#;
    let hints = extract_attack_surface_hints(src);
    let drift = build_protocol_drift_hints(&hints);
    assert!(!drift.is_empty());
    assert!(drift.iter().any(|d| d.base.contains("api.example.com/v1")));
}

#[test]
fn lateral_linkage_renders_for_shared_fingerprints() {
    let recs = vec![
        MatchRecord {
            source: "a.rs".to_string(),
            kind: "entropy".to_string(),
            matched: "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".to_string(),
            line: 1,
            col: 1,
            entropy: Some(5.1),
            context: "token".to_string(),
            identifier: None,
        },
        MatchRecord {
            source: "b.rs".to_string(),
            kind: "entropy".to_string(),
            matched: "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".to_string(),
            line: 2,
            col: 1,
            entropy: Some(5.1),
            context: "token".to_string(),
            identifier: None,
        },
    ];
    let mut linkage = LateralLinkage::default();
    linkage.update("a.rs", &recs[..1]);
    linkage.update("b.rs", &recs[1..]);
    let rendered = linkage.render().unwrap_or_default();
    assert!(rendered.contains("Lateral Linkage"));
}

#[test]
fn capability_infers_privileged_destructive() {
    let src = br#"
const ADMIN = "https://api.example.com/admin/users";
fetch(ADMIN, { method: "DELETE", headers: { "Authorization": "Bearer X" } });
"#;
    let hints = extract_attack_surface_hints(src);
    let records = vec![MatchRecord {
        source: "test.js".to_string(),
        kind: "request-trace".to_string(),
        matched: "fetch".to_string(),
        line: 2,
        col: 1,
        entropy: None,
        context:
            "fetch(ADMIN, { method: \"DELETE\", headers: { \"Authorization\": \"Bearer X\" } })"
                .to_string(),
        identifier: None,
    }];
    let caps = build_api_capability_hints(&records, &hints);
    assert!(caps.iter().any(|c| c.capability.contains("destructive")));
    assert!(caps.iter().any(|c| c.capability.contains("privileged")));
}

#[test]
fn comment_escalation_triggers_with_public_endpoint() {
    let src = br#"
const API = "https://api.example.com";
// token used in docs
"#;
    let hints = extract_attack_surface_hints(src);
    let recs = vec![MatchRecord {
        source: "src/app.js".to_string(),
        kind: "keyword".to_string(),
        matched: "token".to_string(),
        line: 2,
        col: 3,
        entropy: None,
        context: "// token used in docs".to_string(),
        identifier: None,
    }];
    let escalations = build_comment_escalation_hints(&recs, &hints);
    assert!(!escalations.is_empty());
}

#[test]
fn response_class_flags_sensitive_params() {
    let src = br#"
const API = "https://api.example.com/login";
"#;
    let hints = extract_attack_surface_hints(src);
    let records = vec![MatchRecord {
        source: "test.js".to_string(),
        kind: "request-trace".to_string(),
        matched: "fetch".to_string(),
        line: 2,
        col: 1,
        entropy: None,
        context: "fetch(API, { body: { password: 'x', token: 'y' } })".to_string(),
        identifier: None,
    }];
    let hints = build_response_class_hints(&records, &hints);
    assert!(hints.iter().any(|h| h.response == "sensitive"));
}

#[test]
fn auth_drift_detects_missing_auth_nearby() {
    let src = br#"
const API = "https://api.example.com/v1";
"#;
    let hints = extract_attack_surface_hints(src);
    let records = vec![
        MatchRecord {
            source: "test.js".to_string(),
            kind: "request-trace".to_string(),
            matched: "fetch".to_string(),
            line: 10,
            col: 1,
            entropy: None,
            context: "fetch(API, { headers: { Authorization: 'Bearer X' } })".to_string(),
            identifier: None,
        },
        MatchRecord {
            source: "test.js".to_string(),
            kind: "request-trace".to_string(),
            matched: "fetch".to_string(),
            line: 20,
            col: 1,
            entropy: None,
            context: "fetch(API, { method: 'POST' })".to_string(),
            identifier: None,
        },
    ];
    let drift = build_auth_drift_hints(&records, &hints);
    assert!(!drift.is_empty());
}

#[test]
fn endpoint_morphing_detects_template_with_multiple_bases() {
    let src = br#"
const API_BASE_URL = "http://localhost:5000";
const PROD_BASE_URL = "https://api.example.com";
fetch(`${API_BASE_URL}/v1/users`);
"#;
    let hints = extract_attack_surface_hints(src);
    let morph = build_endpoint_shape_morphing_hints(&hints);
    assert!(!morph.is_empty());
}

#[test]
fn keyword_function_name_downweights_in_scan_mode() {
    let data = b"function token(x){return x;} token(1);";
    let keywords = vec!["token".to_string()];
    let tuning = OutputTuning::scan();
    let (_out, records) = process_search(
        data,
        "test.js",
        &keywords,
        None,
        40,
        true,
        FlowMode::Heuristic,
        None,
        &tuning,
    );
    assert!(records.is_empty());
}

#[test]
fn keyword_story_collapses_when_not_expanded() {
    let data = b"token=1; token=2; token=3;";
    let keywords = vec!["token".to_string()];
    let tuning = OutputTuning {
        confidence_floor: 0,
        expand_story: false,
        debug: true,
    };
    let (out, _records) = process_search(
        data,
        "test.js",
        &keywords,
        None,
        40,
        true,
        FlowMode::Heuristic,
        None,
        &tuning,
    );
    assert!(out.contains("+2 similar occurrences"));
}
