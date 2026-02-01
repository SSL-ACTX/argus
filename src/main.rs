use rsearch::cli::Cli;
use rsearch::output::{build_output_mode, finalize_output, handle_output};
use rsearch::scan::{run_analysis, run_recursive_scan};
use clap::CommandFactory;
use clap::Parser;
use log::{error, info, warn};
use memmap2::Mmap;
use rayon::ThreadPoolBuilder;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

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
    env_logger::Builder::from_default_env().format_timestamp(None).init();

    // Handle colorized output toggle
    if cli.no_color {
        owo_colors::set_override(false);
    }

    // Configure global thread pool if -j is set
    if cli.threads > 0 {
        match ThreadPoolBuilder::new().num_threads(cli.threads).build_global() {
            Ok(()) => info!("Set global thread pool to {} threads", cli.threads),
            Err(e) => warn!("Could not set global thread pool: {}. Continuing with default.", e),
        }
    }

    if cli.keyword.is_empty() && !cli.entropy {
        error!("Provide a keyword (-k) OR enable entropy scanning (--entropy)");
        return Ok(());
    }

    // Create a configured HTTP agent with reasonable timeouts to avoid hanging.
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(5))
        .build();

    let output_mode = build_output_mode(&cli);

    for input in &cli.target {
        if input.starts_with("http") {
            info!("Streaming {}", input);
            match agent.get(input).call() {
                Ok(response) => {
                    let mut tmp = NamedTempFile::new()?;
                    std::io::copy(&mut response.into_reader(), &mut tmp)?;

                    let file = tmp.as_file();
                    // Safety: Temp file is exclusive to this process.
                    match unsafe { Mmap::map(file) } {
                        Ok(mmap) => {
                            let (out, recs) = run_analysis(input, &mmap, &cli);
                            handle_output(&output_mode, &cli, &out, recs, None, input);
                        }
                        Err(e) => warn!("Could not map streamed file for {}: {}", input, e),
                    }
                }
                Err(e) => warn!("HTTP error fetching {}: {}", input, e),
            }
        } else {
            run_recursive_scan(input, &cli, &output_mode);
        }
    }

    let duration = start_time.elapsed();
    println!("🏁 Scan completed in {:.2?}", duration);

    finalize_output(&output_mode, &cli);

    Ok(())
}