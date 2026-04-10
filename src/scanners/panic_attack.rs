// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// panic_attack scanner.
//
// Wraps the estate-standard `panic-attack assail` static analyser as a
// forensic signal: we run it against the *clone*, not the subject, and
// lift its structured JSON output into feature-vector dimensions. We do
// not re-implement panic-attack — the estate rule is that panic-attack
// is carried as a subprocess, not reinvented (CLAUDE.md).
//
// Invocation:
//
//   panic-attack assail --output-format json --output <report.json> <clone>
//
// The `--output` flag writes the structured report to a sidecar file,
// which keeps stdout clean for logging and lets us parse the JSON
// without racing the process's own print buffer. The sidecar is written
// into the clone's own tree (a subdirectory of the scene, so already
// inside the isolation boundary) and is parsed and discarded.
//
// Feature-vector dimensions lifted from panic-attack's `statistics`
// block (all scaled into f64):
//
//   * panic_attack.unsafe_blocks
//   * panic_attack.panic_sites
//   * panic_attack.unwrap_calls
//   * panic_attack.allocation_sites
//   * panic_attack.io_operations
//   * panic_attack.threading_constructs
//   * panic_attack.total_lines
//   * panic_attack.weak_points       (count, from the `weak_points` array)
//   * panic_attack.exit_code         (process exit status)
//   * panic_attack.invoked           (1.0 if we managed to run it)
//
// If panic-attack is missing or fails to invoke, we emit an Info
// finding explaining how to fix it and keep the rest of the scan
// running. panic-attack is expected to be on PATH in estate
// environments, so that branch is a safety net rather than the norm.

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

use crate::finding::{Finding, FindingSet, Location, Severity};

/// Scanner name used in Finding tuples and feature keys.
pub const NAME: &str = "panic_attack";

/// Subset of panic-attack's JSON report that we care about. Unknown
/// fields are ignored so panic-attack can grow its schema without
/// breaking us.
#[derive(Debug, Deserialize)]
struct AssailReport {
    #[serde(default)]
    language: String,
    #[serde(default)]
    weak_points: Vec<serde_json::Value>,
    #[serde(default)]
    statistics: Stats,
}

#[derive(Debug, Default, Deserialize)]
struct Stats {
    #[serde(default)]
    total_lines: u64,
    #[serde(default)]
    unsafe_blocks: u64,
    #[serde(default)]
    panic_sites: u64,
    #[serde(default)]
    unwrap_calls: u64,
    #[serde(default)]
    allocation_sites: u64,
    #[serde(default)]
    io_operations: u64,
    #[serde(default)]
    threading_constructs: u64,
}

/// Run the scanner against `clone_path`. If `skip` is true we emit a
/// single Info finding recording that it was skipped, which keeps the
/// feature vector dimensions stable across runs.
pub fn run(clone_path: &Path, skip: bool, set: &mut FindingSet) -> Result<()> {
    if skip {
        set.push(
            Finding::new(
                NAME,
                "skipped",
                Severity::Info,
                Location::Repo,
                "panic-attack invocation skipped by caller",
            )
            .with_feature("panic_attack.invoked", 0.0)
            .with_feature("panic_attack.skipped", 1.0),
        );
        return Ok(());
    }

    // Write the JSON report to a sidecar inside the clone. The scene
    // boundary already contains it, and we delete it at the end of the
    // function so no artefact leaks into the report directory.
    let report_path = clone_path.join(".robofishy-panic-attack.json");

    let spawn = Command::new("panic-attack")
        .arg("assail")
        .arg("--output-format")
        .arg("json")
        .arg("--output")
        .arg(&report_path)
        .arg(clone_path)
        .output();

    let output = match spawn {
        Ok(o) => o,
        Err(e) => {
            set.push(
                Finding::new(
                    NAME,
                    "unavailable",
                    Severity::Info,
                    Location::Repo,
                    format!(
                        "panic-attack not invokable ({e}); ensure it is on PATH"
                    ),
                )
                .with_feature("panic_attack.invoked", 0.0)
                .with_feature("panic_attack.unavailable", 1.0),
            );
            return Ok(());
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);

    // Parse the sidecar report. If parsing fails we still emit an
    // invocation record — we never want to lose the fact that we ran
    // panic-attack just because its schema drifted.
    let parsed: Option<AssailReport> = std::fs::read(&report_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());

    // Best-effort cleanup of the sidecar. Failures here are ignored:
    // the file lives inside the ephemeral clone and will disappear
    // with the scene directory anyway.
    let _ = std::fs::remove_file(&report_path);

    let (severity, rule, message, features): (Severity, &'static str, String, Vec<(String, f64)>) =
        match parsed {
            Some(report) => {
                let weak_count = report.weak_points.len() as u64;
                let any_hits = weak_count > 0
                    || report.statistics.unsafe_blocks > 0
                    || report.statistics.panic_sites > 0
                    || report.statistics.unwrap_calls > 0;

                let severity = if exit_code == 0 && !any_hits {
                    Severity::Info
                } else if weak_count > 0 || exit_code != 0 {
                    Severity::Strong
                } else {
                    Severity::Notice
                };

                let rule = if weak_count > 0 || exit_code != 0 {
                    "flagged"
                } else if any_hits {
                    "statistics_nonzero"
                } else {
                    "clean"
                };

                let message = format!(
                    "panic-attack: lang={}, weak_points={}, unsafe={}, panics={}, unwraps={}, exit={}",
                    report.language,
                    weak_count,
                    report.statistics.unsafe_blocks,
                    report.statistics.panic_sites,
                    report.statistics.unwrap_calls,
                    exit_code,
                );

                let features = vec![
                    ("panic_attack.invoked".to_string(), 1.0),
                    ("panic_attack.exit_code".to_string(), exit_code as f64),
                    ("panic_attack.weak_points".to_string(), weak_count as f64),
                    (
                        "panic_attack.total_lines".to_string(),
                        report.statistics.total_lines as f64,
                    ),
                    (
                        "panic_attack.unsafe_blocks".to_string(),
                        report.statistics.unsafe_blocks as f64,
                    ),
                    (
                        "panic_attack.panic_sites".to_string(),
                        report.statistics.panic_sites as f64,
                    ),
                    (
                        "panic_attack.unwrap_calls".to_string(),
                        report.statistics.unwrap_calls as f64,
                    ),
                    (
                        "panic_attack.allocation_sites".to_string(),
                        report.statistics.allocation_sites as f64,
                    ),
                    (
                        "panic_attack.io_operations".to_string(),
                        report.statistics.io_operations as f64,
                    ),
                    (
                        "panic_attack.threading_constructs".to_string(),
                        report.statistics.threading_constructs as f64,
                    ),
                ];

                (severity, rule, message, features)
            }
            None => {
                let severity = if exit_code == 0 {
                    Severity::Info
                } else {
                    Severity::Notice
                };
                let message = format!(
                    "panic-attack exited {exit_code} but report could not be parsed; {} bytes stderr",
                    output.stderr.len()
                );
                let features = vec![
                    ("panic_attack.invoked".to_string(), 1.0),
                    ("panic_attack.exit_code".to_string(), exit_code as f64),
                    ("panic_attack.parse_failed".to_string(), 1.0),
                ];
                (severity, "unparseable", message, features)
            }
        };

    let mut finding = Finding::new(NAME, rule, severity, Location::Repo, message);
    for (k, v) in features {
        finding = finding.with_feature(&k, v);
    }
    set.push(finding);

    Ok(())
}
