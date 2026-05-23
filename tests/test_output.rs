use argus::report::{build_story_report, MatchRecord};

#[test]
fn story_report_groups_by_source() {
    let recs = vec![
        MatchRecord {
            source: "a.rs".to_string(),
            kind: "entropy".to_string(),
            matched: "ABC".to_string(),
            line: 1,
            col: 1,
            entropy: Some(5.0),
            context: "ctx".to_string(),
            identifier: None,
        },
        MatchRecord {
            source: "b.rs".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 2,
            col: 1,
            entropy: None,
            context: "ctx".to_string(),
            identifier: None,
        },
    ];
    let report = build_story_report(&recs);
    assert!(report.contains("## a.rs"));
    assert!(report.contains("## b.rs"));
}

#[test]
fn csv_report_contains_fields() {
    let recs = vec![MatchRecord {
        source: "test.rs".to_string(),
        kind: "entropy".to_string(),
        matched: "ABC\"DEF".to_string(),
        line: 1,
        col: 1,
        entropy: Some(5.0),
        context: "some,context".to_string(),
        identifier: Some("key".to_string()),
    }];
    let report = argus::report::build_csv_report(&recs);
    assert!(report.contains("source,line,col,kind,matched,entropy,identifier,context"));
    assert!(report.contains("\"test.rs\""));
    assert!(report.contains("\"ABC\"\"DEF\""));
    assert!(report.contains("\"some,context\""));
    assert!(report.contains("5"));
}

#[test]
fn junit_report_is_valid_xml_structure() {
    let recs = vec![MatchRecord {
        source: "test.rs".to_string(),
        kind: "entropy".to_string(),
        matched: "ABC&DEF".to_string(),
        line: 1,
        col: 1,
        entropy: Some(5.0),
        context: "ctx".to_string(),
        identifier: None,
    }];
    let report = argus::report::build_junit_report(&recs);
    assert!(report.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(report.contains("<testsuites>"));
    assert!(report.contains("<testsuite name=\"argus\" tests=\"1\">"));
    assert!(report.contains("ABC&amp;DEF"));
}
