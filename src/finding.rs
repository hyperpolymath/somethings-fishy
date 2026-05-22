// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// Finding and FindingSet types.
//
// Why this module exists as its own concern:
//
//   1. Every scanner produces Findings, and every downstream consumer
//      (report emitter, v1 classifier, v4 change-point detector) reads
//      them. A shared type avoids coupling scanners to report format.
//
//   2. Every Finding carries a **stable content-addressed ID**. ADR 0002
//      commits the project to test-retest reliability from v0 onwards,
//      which means repeated runs against the same input must produce
//      identical Finding IDs. The ID is derived from the tuple
//      (scanner, rule, location, content-hash) and is deterministic.
//
//   3. Every Finding carries an (optional) feature vector. v0 populates
//      these sparsely; v1's classifier will consume them without needing
//      to re-walk the repo.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A single forensic observation produced by one scanner rule.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable content-addressed identifier. Same input ⇒ same ID.
    pub id: String,

    /// Name of the scanner that produced the finding (e.g. `agent_files`).
    pub scanner: &'static str,

    /// Rule within the scanner (e.g. `claude_md_present`).
    pub rule: &'static str,

    /// Human-readable severity hint. v0 uses a coarse scale; v1 replaces
    /// this with calibrated confidence intervals.
    pub severity: Severity,

    /// Where in the cloned target this finding was observed. A path is
    /// relative to the clone root; line numbers are 1-indexed.
    pub location: Location,

    /// Short human-readable message. Reports should never show the raw
    /// message without also showing the scanner/rule tuple.
    pub message: String,

    /// Optional feature vector for v1+ consumption. v0 may leave this
    /// empty; scanners should still populate it whenever feasible.
    pub features: BTreeMap<String, f64>,
}

/// Coarse severity hint used in v0. v1+ will replace this with calibrated
/// confidence intervals from conformal prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Observational signal, no claim of harm.
    Info,
    /// Something an investigator should look at.
    Notice,
    /// Strong shallow signal of agent activity or damage.
    Strong,
}

impl Severity {
    /// A2ML-friendly lowercase keyword.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Strong => "strong",
        }
    }
}

/// Where in the target a finding was observed.
#[derive(Debug, Clone)]
pub enum Location {
    /// Applies to the target as a whole, not any particular file.
    Repo,
    /// A single file, optionally with a specific line.
    File {
        /// Repo-relative path of the file the finding refers to.
        path: PathBuf,
        /// Optional 1-indexed line number within `path`.
        line: Option<u32>,
    },
    /// A commit in the history.
    Commit {
        /// Full commit SHA (40 hex chars).
        sha: String,
    },
}

impl Location {
    fn ident(&self) -> String {
        match self {
            Self::Repo => "repo".into(),
            Self::File { path, line } => match line {
                Some(n) => format!("file:{}:{}", path.display(), n),
                None => format!("file:{}", path.display()),
            },
            Self::Commit { sha } => format!("commit:{sha}"),
        }
    }
}

impl Finding {
    /// Build a Finding and compute its stable content-addressed ID.
    ///
    /// The ID covers (scanner, rule, location, message) so that rerunning
    /// the same scanner against the same repo produces the same IDs even
    /// if the feature vector is absent. This is the test-retest guarantee.
    pub fn new(
        scanner: &'static str,
        rule: &'static str,
        severity: Severity,
        location: Location,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        let mut hasher = Sha256::new();
        hasher.update(b"robofishy:finding:v0\n");
        hasher.update(scanner.as_bytes());
        hasher.update(b"\n");
        hasher.update(rule.as_bytes());
        hasher.update(b"\n");
        hasher.update(location.ident().as_bytes());
        hasher.update(b"\n");
        hasher.update(message.as_bytes());
        let digest = hasher.finalize();
        // 16 hex chars is plenty for human-scale identification.
        let id = hex::encode(&digest[..8]);

        Self {
            id,
            scanner,
            rule,
            severity,
            location,
            message,
            features: BTreeMap::new(),
        }
    }

    /// Attach a scalar feature. Intended for v1 classifier consumption.
    pub fn with_feature(mut self, key: &str, value: f64) -> Self {
        self.features.insert(key.to_string(), value);
        self
    }
}

/// A collection of findings, grouped by the scanner that produced them.
///
/// BTreeMap keeps ordering deterministic across runs — another contributor
/// to the test-retest guarantee. Scanners do not de-duplicate across each
/// other; that is a report-layer concern if it ever becomes necessary.
#[derive(Debug, Default)]
pub struct FindingSet {
    groups: BTreeMap<&'static str, Vec<Finding>>,
}

impl FindingSet {
    /// Fresh, empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the set. Sorted into its scanner's bucket.
    pub fn push(&mut self, finding: Finding) {
        self.groups
            .entry(finding.scanner)
            .or_default()
            .push(finding);
    }

    /// Total findings across all scanners.
    pub fn total(&self) -> usize {
        self.groups.values().map(Vec::len).sum()
    }

    /// Number of distinct scanners that produced at least one finding.
    pub fn scanner_count(&self) -> usize {
        self.groups.len()
    }

    /// Iterate scanner groups in deterministic order.
    pub fn groups(&self) -> impl Iterator<Item = (&&'static str, &Vec<Finding>)> {
        self.groups.iter()
    }
}
