#![cfg(feature = "wasm-ffi")]

use wasm_bindgen::prelude::*;

use crate::cli::{Cli, OutputPersona};
use crate::output::MatchRecord;
use crate::scan::run_analysis;

#[derive(serde::Deserialize)]
pub struct WasmScanOptions {
    pub keywords: Vec<String>,
    pub entropy: bool,
    pub threshold: f64,
    pub context: usize,
    pub deep_scan: bool,
    pub flow_scan: bool,
    pub request_trace: bool,
    pub confidence_floor: u8,
    pub expand: bool,
    pub mode: String,
}

impl Default for WasmScanOptions {
    fn default() -> Self {
        Self {
            keywords: Vec::new(),
            entropy: false,
            threshold: 4.5,
            context: 80,
            deep_scan: false,
            flow_scan: false,
            request_trace: false,
            confidence_floor: 0,
            expand: false,
            mode: "scan".to_string(),
        }
    }
}

#[wasm_bindgen]
pub fn scan_bytes_json(bytes: &[u8], options: JsValue) -> Result<JsValue, JsValue> {
    let opts: WasmScanOptions = if options.is_undefined() || options.is_null() {
        WasmScanOptions::default()
    } else {
        serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsValue::from_str(&format!("invalid options: {}", e)))?
    };

    if opts.keywords.is_empty() && !opts.entropy {
        return Err(JsValue::from_str("provide at least one keyword or enable entropy"));
    }

    let mode = match opts.mode.to_lowercase().as_str() {
        "debug" | "loud" => OutputPersona::Debug,
        _ => OutputPersona::Scan,
    };

    let cli = Cli {
        target: vec!["<memory>".to_string()],
        keyword: opts.keywords.clone(),
        entropy: opts.entropy,
        threshold: opts.threshold,
        context: opts.context,
        threads: 0,
        json: true,
        output: None,
        no_color: true,
        output_format: "single".to_string(),
        exclude: Vec::new(),
        emit_tags: None,
        deep_scan: opts.deep_scan,
        flow_scan: opts.flow_scan,
        request_trace: opts.request_trace,
        suppress: None,
        suppress_out: None,
        suppression_audit: false,
        diff: false,
        diff_base: "HEAD".to_string(),
        mode,
        quiet: matches!(mode, OutputPersona::Scan),
        loud: matches!(mode, OutputPersona::Debug),
        confidence_floor: opts.confidence_floor,
        expand: opts.expand,
    };

    let (_out, recs) = run_analysis(
        "<memory>",
        bytes,
        &cli,
        None,
        Some("<memory>"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let json = serde_wasm_bindgen::to_value(&recs)
        .map_err(|e| JsValue::from_str(&format!("serialize error: {}", e)))?;
    Ok(json)
}

#[wasm_bindgen]
pub fn scan_bytes_count(bytes: &[u8], options: JsValue) -> Result<usize, JsValue> {
    let out = scan_bytes_json(bytes, options)?;
    let recs: Vec<MatchRecord> = serde_wasm_bindgen::from_value(out)
        .map_err(|e| JsValue::from_str(&format!("deserialize error: {}", e)))?;
    Ok(recs.len())
}