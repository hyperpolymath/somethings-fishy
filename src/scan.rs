// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! v0 shallow-signal scanner orchestrator.
//!
//! The public entry point is [`run_all`], which runs the four v0
//! scanners against a cloned target and returns a [`crate::finding::FindingSet`].

// Scanner orchestrator.
//
// v0 runs four shallow-signal scanners in a fixed order against a
// cloned target and collects their output into a single FindingSet.
// The order is deliberate:
//
//   1. agent_files      — cheapest, filesystem-only
//   2. commit_trailers  — one git subprocess, bounded history walk
//   3. banned_patterns  — full working-tree grep, most expensive FS op
//   4. panic_attack     — external subprocess, may be absent
//
// Ordering matters for two reasons. First, it keeps the cheapest work
// first so early failures surface fast. Second, it matches the order in
// ROADMAP v0 and ADR 0002, which the reports are read against.
//
// Error handling: a single scanner's failure does not abort the whole
// scan. Each scanner is wrapped so its error is recorded as an Info
// finding and the remaining scanners still run — partial forensic data
// is more useful than none. This is consistent with the ADR 0002
// principle that the tool should prefer "insufficient evidence" to
// silent gaps.

use anyhow::Result;
use std::path::Path;

use crate::finding::{Finding, FindingSet, Location, Severity};
use crate::scanners;

/// Scanner pipeline options.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Skip the panic-attack subprocess invocation. Useful in
    /// environments where `panic-attack` is not on PATH or where the
    /// caller wants a faster triage pass.
    pub skip_panic_attack: bool,
}

/// Run the full scanner pipeline against `clone_path`.
///
/// The signature returns `Result` to preserve the option of an abort-
/// on-catastrophic-failure path in future, but in v0 this function is
/// infallible in practice: individual scanner errors are captured as
/// Info findings and not propagated.
pub fn run_all(clone_path: &Path, options: Options) -> Result<FindingSet> {
    let mut set = FindingSet::new();

    wrap("agent_files", &mut set, |set| {
        scanners::agent_files::run(clone_path, set)
    });
    wrap("commit_trailers", &mut set, |set| {
        scanners::commit_trailers::run(clone_path, set)
    });
    wrap("banned_patterns", &mut set, |set| {
        scanners::banned_patterns::run(clone_path, set)
    });
    wrap("panic_attack", &mut set, |set| {
        scanners::panic_attack::run(clone_path, options.skip_panic_attack, set)
    });

    Ok(set)
}

/// Run a scanner closure and convert any error into an Info finding
/// tagged with the scanner's name. This keeps one broken scanner from
/// taking down the rest of the pipeline.
fn wrap<F>(scanner: &'static str, set: &mut FindingSet, f: F)
where
    F: FnOnce(&mut FindingSet) -> Result<()>,
{
    if let Err(e) = f(set) {
        set.push(
            Finding::new(
                scanner,
                "scanner_error",
                Severity::Info,
                Location::Repo,
                format!("{scanner} scanner failed: {e}"),
            )
            .with_feature(&format!("{scanner}.error"), 1.0),
        );
    }
}
