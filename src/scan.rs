// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// Scanner orchestrator.
//
// v0 stub: returns an empty FindingSet. The actual scanners
// (agent_files, commit_trailers, banned_patterns, panic_attack) are
// deferred to the next session — see ROADMAP v0. This stub exists so
// the Rust crate links end-to-end against the SPARK safety kernel,
// demonstrating that the FFI bridge is wired.

use anyhow::Result;
use std::path::Path;

use crate::finding::FindingSet;

/// Scanner pipeline options.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Skip the panic-attack subprocess invocation (v0 stub does not
    /// invoke it anyway).
    pub skip_panic_attack: bool,
}

/// Run the full scanner pipeline against `clone_path`.
///
/// v0 returns an empty FindingSet; the pipeline is populated in a
/// subsequent commit. This signature is stable — callers built against
/// v0 will continue to work when scanners are added.
pub fn run_all(_clone_path: &Path, _options: Options) -> Result<FindingSet> {
    Ok(FindingSet::new())
}
