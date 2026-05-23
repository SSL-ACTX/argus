use argus::cli::Cli;
use argus::common::set_color_enabled;
use argus::report::{build_output_mode, finalize_output};
use argus::scanner::{
    load_diff_map, load_suppression_rules, run_recursive_scan, DiffSummary, Heatmap,
    LateralLinkage, Lineage, SuppressionAuditTracker,
};
use clap::CommandFactory;
use clap::Parser;
use log::{error, info, warn};
use rayon::ThreadPoolBuilder;
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let cli = Cli::parse();

    // If run with no arguments, print help and exit.
    if std::env::args().len() <= 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // Initialize logging from environment (RUST_LOG)
    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .init();

    // Handle colorized output toggle
    if cli.no_color {
        set_color_enabled(false);
    }

    // Configure global thread pool if -j is set
    if cli.threads > 0 {
        match ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
        {
            Ok(()) => info!("Set global thread pool to {} threads", cli.threads),
            Err(e) => warn!(
                "Could not set global thread pool: {}. Continuing with default.",
                e
            ),
        }
    }

    if cli.keyword.is_empty() && !cli.entropy {
        error!("Provide a keyword (-k) OR enable entropy scanning (--entropy)");
        return Ok(());
    }

    let output_mode = build_output_mode(&cli);

    let heatmap = Arc::new(Mutex::new(Heatmap::default()));
    let lineage = Arc::new(Mutex::new(Lineage::default()));
    let lateral = Arc::new(Mutex::new(LateralLinkage::default()));
    let diff_summary = Arc::new(Mutex::new(DiffSummary::default()));

    let diff_map = if cli.diff {
        load_diff_map(&cli.diff_base)
    } else {
        None
    };

    let suppression_rules = cli
        .suppress
        .as_deref()
        .map(load_suppression_rules)
        .unwrap_or_default();

    let suppression_audit = if cli.suppression_audit && !suppression_rules.is_empty() {
        Some(Arc::new(Mutex::new(SuppressionAuditTracker::new(
            &suppression_rules,
        ))))
    } else {
        None
    };

    for input in &cli.target {
        run_recursive_scan(
            input,
            &cli,
            &output_mode,
            Some(&heatmap),
            Some(&lineage),
            Some(&lateral),
            Some(&diff_summary),
            suppression_audit.as_ref(),
            Some(&suppression_rules),
            diff_map.as_ref(),
        );
    }

    if !cli.json {
        if let Ok(guard) = heatmap.lock() {
            if let Some(summary) = guard.render() {
                println!("{}", summary);
            }
        }
        if let Ok(guard) = lineage.lock() {
            if let Some(summary) = guard.render() {
                println!("{}", summary);
            }
        }
        if let Ok(guard) = lateral.lock() {
            if let Some(summary) = guard.render() {
                println!("{}", summary);
            }
        }

        if cli.diff {
            if let Ok(guard) = diff_summary.lock() {
                if let Some(summary) = guard.render() {
                    println!("{}", summary);
                }
            }
        }
    }

    let duration = start_time.elapsed();
    println!("\n🏁 Scan completed in {:.2?}", duration);

    finalize_output(&output_mode, &cli);

    Ok(())
}
