// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// banned_patterns scanner.
//
// Greps the working tree for known-dangerous escape hatches and agent
// tells. The list is drawn from the estate-wide dangerous-patterns ban
// (see MEMORY.md / CLAUDE.md): verification bypasses, type-checker
// silencers, eval-class string evaluation, and the "unsafe escape
// hatches" agents reach for when they cannot actually solve a problem.
//
// Design notes:
//
//   * We use a single Aho-Corasick automaton over the full literal set,
//     which gives linear-time scan of each file regardless of pattern
//     count. That matters because the pattern list will grow.
//   * Patterns are matched as byte substrings. Word-boundary refinement
//     is a v1 concern — v0 prefers false positives (noise) to false
//     negatives (blind spots), consistent with the "insufficient
//     evidence" framing in ADR 0002.
//   * We skip binary files (detected by NUL byte in the first 8 KiB)
//     and cap any single file at 2 MiB — large generated files blow up
//     the scan and rarely contribute useful signal.
//   * Feature vector: per-pattern counts and a `banned_patterns.total`
//     aggregate on the summary Finding.

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use anyhow::Result;
use ignore::WalkBuilder;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::finding::{Finding, FindingSet, Location, Severity};

/// Scanner name used in Finding tuples and feature keys.
pub const NAME: &str = "banned_patterns";

/// Maximum file size we will scan. Anything larger is assumed to be
/// generated or a fixture and is skipped with an Info finding.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// One banned pattern. Kept minimal so new entries are cheap to add.
struct Pattern {
    /// Literal needle.
    needle: &'static str,
    /// Rule identifier.
    rule: &'static str,
    /// Short feature-vector key (appended after `banned_patterns.`).
    feature: &'static str,
    /// Severity. Most bans are Strong; a few noisier ones are Notice.
    severity: Severity,
}

const PATTERNS: &[Pattern] = &[
    // Idris / Agda / Lean / Coq verification escape hatches.
    Pattern {
        needle: "believe_me",
        rule: "idris_believe_me",
        feature: "believe_me",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "assert_total",
        rule: "idris_assert_total",
        feature: "assert_total",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "really_believe_me",
        rule: "idris_really_believe_me",
        feature: "really_believe_me",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "Admitted",
        rule: "coq_admitted",
        feature: "admitted",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "admit",
        rule: "lean_admit",
        feature: "admit",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "sorry",
        rule: "lean_sorry",
        feature: "sorry",
        severity: Severity::Notice,
    },
    // Haskell / OCaml unsafe coercions.
    Pattern {
        needle: "unsafeCoerce",
        rule: "haskell_unsafe_coerce",
        feature: "unsafe_coerce",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "Obj.magic",
        rule: "ocaml_obj_magic",
        feature: "obj_magic",
        severity: Severity::Strong,
    },
    // TypeScript / JS type-checker silencers.
    Pattern {
        needle: "@ts-ignore",
        rule: "ts_ignore",
        feature: "ts_ignore",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "@ts-nocheck",
        rule: "ts_nocheck",
        feature: "ts_nocheck",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "@ts-expect-error",
        rule: "ts_expect_error",
        feature: "ts_expect_error",
        severity: Severity::Notice,
    },
    // Python / general type-checker silencers.
    Pattern {
        needle: "# type: ignore",
        rule: "py_type_ignore",
        feature: "py_type_ignore",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "# noqa",
        rule: "py_noqa",
        feature: "py_noqa",
        severity: Severity::Info,
    },
    // Rust unsafe hatches commonly sprayed by agents that cannot fix
    // borrow-checker issues. `unsafe` alone is too noisy; we catch the
    // specific abuses.
    Pattern {
        needle: "std::mem::transmute",
        rule: "rust_transmute",
        feature: "rust_transmute",
        severity: Severity::Strong,
    },
    Pattern {
        needle: "unwrap_unchecked",
        rule: "rust_unwrap_unchecked",
        feature: "rust_unwrap_unchecked",
        severity: Severity::Strong,
    },
    // Dynamic string evaluation.
    Pattern {
        needle: "eval(",
        rule: "eval_call",
        feature: "eval_call",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "exec(",
        rule: "exec_call",
        feature: "exec_call",
        severity: Severity::Notice,
    },
    // Broader linter/type-checker silencers.
    Pattern {
        needle: "eslint-disable-next-line",
        rule: "eslint_disable",
        feature: "eslint_disable",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "# pylint: disable",
        rule: "pylint_disable",
        feature: "pylint_disable",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "@SuppressWarnings",
        rule: "java_suppress",
        feature: "java_suppress",
        severity: Severity::Notice,
    },
    // Agent tells in comments — useful base-rate signal.
    Pattern {
        needle: "TODO(claude)",
        rule: "todo_claude",
        feature: "todo_claude",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "TODO(copilot)",
        rule: "todo_copilot",
        feature: "todo_copilot",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "TODO(ai)",
        rule: "todo_ai",
        feature: "todo_ai",
        severity: Severity::Notice,
    },
    Pattern {
        needle: "XXX AI:",
        rule: "xxx_ai",
        feature: "xxx_ai",
        severity: Severity::Notice,
    },
];

/// Run the scanner against `clone_path`.
pub fn run(clone_path: &Path, set: &mut FindingSet) -> Result<()> {
    // Build the Aho-Corasick automaton once. `LeftmostFirst` with the
    // DFA kind gives deterministic ordering of overlapping matches,
    // which is what we want for stable finding IDs.
    let needles: Vec<&str> = PATTERNS.iter().map(|p| p.needle).collect();
    let ac = AhoCorasick::builder()
        .kind(Some(AhoCorasickKind::DFA))
        .match_kind(MatchKind::LeftmostFirst)
        .build(&needles)
        .expect("static needle list is non-empty and well-formed");

    let mut per_pattern: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut total_hits: u32 = 0;
    let mut files_scanned: u32 = 0;

    let walker = WalkBuilder::new(clone_path)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let rel = match path.strip_prefix(clone_path) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };

        // Skip our own manifest if we are dogfooded against somethings-
        // fishy — it literally contains the patterns as string literals.
        if is_self_scan_noise(&rel) {
            continue;
        }

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if looks_binary(&bytes) {
            continue;
        }
        files_scanned += 1;

        for mat in ac.find_iter(&bytes) {
            let pat = &PATTERNS[mat.pattern().as_usize()];
            let line = line_number_at(&bytes, mat.start());
            let finding = Finding::new(
                NAME,
                pat.rule,
                pat.severity,
                Location::File {
                    path: PathBuf::from(rel.to_string_lossy().into_owned()),
                    line: Some(line),
                },
                format!("banned pattern `{}` at line {line}", pat.needle),
            )
            .with_feature(&format!("banned_patterns.{}", pat.feature), 1.0);
            set.push(finding);
            *per_pattern.entry(pat.feature).or_insert(0) += 1;
            total_hits += 1;
        }
    }

    let mut summary = Finding::new(
        NAME,
        "summary",
        if total_hits == 0 {
            Severity::Info
        } else {
            Severity::Strong
        },
        Location::Repo,
        format!("banned_patterns: {total_hits} hits across {files_scanned} files"),
    )
    .with_feature("banned_patterns.total", total_hits as f64)
    .with_feature("banned_patterns.files_scanned", files_scanned as f64);
    for (feature, count) in &per_pattern {
        summary = summary.with_feature(&format!("banned_patterns.{feature}_count"), *count as f64);
    }
    set.push(summary);

    Ok(())
}

/// 1-indexed line number of a byte offset within `bytes`.
fn line_number_at(bytes: &[u8], offset: usize) -> u32 {
    let end = offset.min(bytes.len());
    let nl = bytes[..end].iter().filter(|&&b| b == b'\n').count();
    (nl + 1) as u32
}

/// Cheap binary heuristic: any NUL byte in the first 8 KiB.
fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(8192)];
    head.contains(&0)
}

/// Detect and skip files that would produce only self-referential hits
/// if robofishy is scanned against itself — this crate's pattern list,
/// its tests, and its documentation of the dangerous patterns ban.
fn is_self_scan_noise(rel: &Path) -> bool {
    let s = rel.to_string_lossy();
    s.starts_with("src/scanners/banned_patterns.rs")
        || s.starts_with("tests/") && s.contains("banned_patterns")
}
