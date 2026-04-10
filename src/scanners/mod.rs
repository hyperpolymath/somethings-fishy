// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Shallow-signal scanner implementations for v0.
//!
//! Four scanners: [`agent_files`], [`commit_trailers`],
//! [`banned_patterns`], [`panic_attack`]. Each exports a `run(...)`
//! function that pushes [`crate::finding::Finding`] values into a
//! shared [`crate::finding::FindingSet`], with a structured feature
//! vector per finding per ADR 0002.

// Shallow-signal scanner implementations for v0.
//
// Each scanner is a standalone module with a single entry point that takes
// the clone root (+ any scanner-specific options) and pushes Findings into
// a FindingSet. Scanners are strictly read-only and must never touch the
// subject outside the clone — the clone is already an independent working
// tree, so "read-only" here means "no writes, no subprocesses that mutate".
//
// Every scanner is expected to emit a feature vector on each Finding it
// produces, per ADR 0002: v1's classifier consumes these vectors directly
// without re-walking the repo. Features are scalar `f64` values keyed by
// a short string. Keys are namespaced by scanner (e.g. `agent_files.total`)
// so the downstream pipeline can ingest mixed streams without collisions.

/// agent-addressed files scanner (CLAUDE.md, .claude/, copilot-instructions.md, ...).
pub mod agent_files;
/// banned dangerous-pattern scanner (believe_me, @ts-ignore, transmute, ...).
pub mod banned_patterns;
/// git commit trailer / bot signature scanner.
pub mod commit_trailers;
/// panic-attack assail subprocess wrapper.
pub mod panic_attack;
