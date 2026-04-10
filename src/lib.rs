// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// robofishy library crate root.
//
// The library is split by concern so that v1 (classifier) and beyond can
// depend on the same building blocks without reaching through main.rs:
//
//   * `safe_io` — SPARK-verified write channel (the only sanctioned
//                 path for any filesystem mutation in the crate)
//   * `scene`   — isolation-area lifecycle; clone-first discipline
//   * `clone`   — git subprocess wrapper used by scene
//   * `scan`    — read-only scanner pipeline, orchestrator, Options
//   * `finding` — Finding type, FindingSet, stable content-addressed IDs
//   * `report`  — A2ML emission (S-expression format, estate convention)
//
// v0 deliberately exposes a simple synchronous API. Async and parallelism
// (chapeliser integration) are reserved for v1+.
//
// `#![forbid(unsafe_code)]` is NOT set at the crate level because
// `safe_io` contains the one sanctioned `extern "C"` block in the crate.
// Every other module is expected to be unsafe-free, and individual
// modules may add `#![forbid(unsafe_code)]` of their own.

#![warn(missing_docs)]

//! Agent-autopsy forensic triage library.
//!
//! See `ROADMAP.adoc` for the capability ladder and `docs/decisions/` for
//! the architectural decisions behind this crate.

pub mod clone;
pub mod finding;
pub mod report;
pub mod safe_io;
pub mod scan;
pub mod scanners;
pub mod scene;

/// Library version, surfaced in emitted reports for test-retest reliability.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
