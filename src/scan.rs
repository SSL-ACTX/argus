use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use log::warn;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::cli::Cli;
use crate::entropy::scan_for_secrets;
use crate::keyword::process_search;
use crate::output::{handle_output, MatchRecord, OutputMode};
use std::collections::HashSet;

const MAX_MMAP_SIZE: u64 = 200 * 1024 * 1024; // 200 MB
const DEFAULT_EXCLUDES: &[&str] = &[
    "**/*.lock",
    "**/Cargo.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/Gemfile.lock",
    "**/composer.lock",
    "**/go.sum",
];

pub fn run_analysis(source_label: &str, bytes: &[u8], cli: &Cli) -> (String, Vec<MatchRecord>) {
    let mut file_output = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();

    let tag_set = parse_emit_tags(&cli.emit_tags);

    if !cli.keyword.is_empty() {
        let (s, mut r) = process_search(bytes, source_label, &cli.keyword, cli.context, cli.deep_scan);
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if cli.entropy {
        let (s, mut r) = scan_for_secrets(source_label, bytes, cli.threshold, cli.context, &tag_set, cli.deep_scan);
        file_output.push_str(&s);
        records.append(&mut r);
    }

    (file_output, records)
}

pub fn run_recursive_scan(input: &str, cli: &Cli, output_mode: &OutputMode) {
    let exclude_matcher = build_exclude_matcher(&cli.exclude);
    let walker = WalkBuilder::new(input)
        .hidden(false)
        .git_ignore(true)
        .build();

    walker.into_iter().par_bridge().for_each(|result| {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() {
                    if is_excluded_path(path, &exclude_matcher) {
                        return;
                    }

                    let metadata = match path.metadata() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    if metadata.len() == 0 {
                        return;
                    }

                    if metadata.len() > MAX_MMAP_SIZE {
                        warn!("Skipping large file {} ({} bytes)", path.display(), metadata.len());
                        return;
                    }

                    if let Ok(mut file) = File::open(path) {
                        let mut peek = [0u8; 1024];
                        match file.read(&mut peek) {
                            Ok(n) if n > 0 => {
                                if peek[..n].contains(&0) {
                                    warn!("Skipping binary file {}", path.display());
                                    return;
                                }
                            }
                            _ => {}
                        }

                        match unsafe { Mmap::map(&file) } {
                            Ok(mmap) => {
                                let (out, recs) = run_analysis(&path.to_string_lossy(), &mmap, cli);
                                handle_output(output_mode, cli, &out, recs, Some(path), &path.to_string_lossy());
                            }
                            Err(e) => {
                                warn!("Could not map file {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!("Walker error: {}", err);
            }
        }
    });
}

pub fn build_exclude_matcher(patterns: &[String]) -> Gitignore {
    let mut builder = GitignoreBuilder::new(".");
    for pat in DEFAULT_EXCLUDES {
        let _ = builder.add_line(None, pat);
    }
    for pat in patterns {
        let _ = builder.add_line(None, pat);
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

pub fn is_excluded_path(path: &Path, matcher: &Gitignore) -> bool {
    matcher.matched(path, path.is_dir()).is_ignore()
}

fn parse_emit_tags(raw: &Option<String>) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(s) = raw {
        for part in s.split(',') {
            let tag = part.trim().to_lowercase();
            if !tag.is_empty() {
                set.insert(tag);
            }
        }
    }
    set
}

