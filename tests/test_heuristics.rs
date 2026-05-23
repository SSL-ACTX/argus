use argus::analysis::analyze_flow_context;

#[test]
fn test_adversarial_lexer_masking() {
    // This code has 'if' and 'for' and '{' inside strings and comments
    // A half-baked implementation would count them.
    let code = b"
    // if (true) { for (;;) {} }
    const x = \" if (false) { \";
    /*
       while (true) { }
    */
    if (a) { }
    ";
    let ctx = analyze_flow_context(code, code.len() - 5, None);
    // Only the last 'if (a)' should count.
    // Cognitive complexity: if(a) -> +1
    // Block depth: if(a) { } -> 0 (at the end)
    assert_eq!(ctx.cognitive_complexity, 1);
    assert_eq!(ctx.block_depth, 0);
}

#[test]
fn test_advanced_nesting_complexity() {
    let code = b"
    function complex() {
        if (a) {                // +1
            if (b) {            // +1 + 1 (nesting) = +2
                for (let i of c) { // +1 + 2 (nesting) = +3
                    if (d) {    // +1 + 3 (nesting) = +4
                    }
                }
            }
        }
    }
    ";
    // Total = 1 + 2 + 3 + 4 = 10
    let ctx = analyze_flow_context(code, code.len() - 50, None);
    assert_eq!(ctx.cognitive_complexity, 10);
}

#[test]
fn test_taint_lexical_boundary() {
    // 'req' is in a string, not a real source
    let code = b"const msg = 'this is a req'; db.execute(msg);";
    let ctx = analyze_flow_context(code, 35, None);
    // Should NOT detect 'req' as a source because it's in a string
    assert!(ctx
        .taint_summary
        .as_ref()
        .map(|s| !s.contains("req"))
        .unwrap_or(true));
}

#[test]
fn test_taint_actual_assignment() {
    let code = b"const data = req.body; db.execute(data);";
    let ctx = analyze_flow_context(code, 35, None);
    // Should detect req->execute
    assert!(ctx
        .taint_summary
        .as_ref()
        .map(|s| s.contains("req") && s.contains("execute"))
        .unwrap_or(false));
}

#[test]
fn test_flow_stack_adversarial() {
    let code = b"
    if (a) {
        // { fake block
        const x = \" { fake string \";
        if (b) {
            // inside
        }
    }
    ";
    // Find the actual byte position of "// inside"
    let code_str = std::str::from_utf8(code).unwrap();
    let pos = code_str.find("// inside").unwrap();

    let ctx = analyze_flow_context(code, pos, None);
    // stack should be ["if", "if"]
    assert_eq!(ctx.flow_stack, vec!["if".to_string(), "if".to_string()]);
}

#[test]
fn test_import_hints_detected() {
    let code = b"import crypto from 'crypto';\nconst key = 'abc';";
    let ctx = analyze_flow_context(code, 30, None);
    assert!(ctx.import_hints.contains(&"crypto".to_string()));
}

#[test]
fn test_import_hints_net() {
    let code = b"const axios = require('axios');\naxios.get(url);";
    let ctx = analyze_flow_context(code, 35, None);
    assert!(ctx.import_hints.contains(&"net".to_string()));
}
