// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// Integration tests for the v0 scanner pipeline.
//
// We exercise the two scanners that need no external subprocess —
// agent_files and banned_patterns — by materialising a synthetic
// "repo" in a tempdir and asserting the scanners produce the expected
// Findings. commit_trailers and panic_attack need git and the
// panic-attack binary respectively; they are exercised by the e2e
// harness in `tests/e2e/` against real clones.

use std::fs;
use std::path::Path;

use robofishy::finding::{FindingSet, Location};
use robofishy::scanners::{agent_files, banned_patterns};

fn write(dir: &Path, rel: &str, body: &str) {
    let full = dir.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).expect("mkdir tempdir subpath");
    }
    fs::write(&full, body).expect("write test fixture");
}

#[test]
fn agent_files_detects_claude_and_copilot_markers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    write(root, "CLAUDE.md", "# instructions\n");
    write(root, ".github/copilot-instructions.md", "# copilot\n");
    write(root, "src/main.rs", "fn main() {}\n");
    write(root, "unrelated.txt", "plain\n");

    let mut set = FindingSet::new();
    agent_files::run(root, &mut set).expect("agent_files run");

    let findings: Vec<_> = set
        .groups()
        .filter(|(name, _)| **name == agent_files::NAME)
        .flat_map(|(_, group)| group.iter())
        .collect();

    let rules: Vec<_> = findings.iter().map(|f| f.rule).collect();
    assert!(rules.contains(&"claude_md"), "expected claude_md: {rules:?}");
    assert!(
        rules.contains(&"copilot_instructions"),
        "expected copilot_instructions: {rules:?}"
    );
    assert!(rules.contains(&"summary"), "expected summary: {rules:?}");

    let summary = findings
        .iter()
        .find(|f| f.rule == "summary")
        .expect("summary finding");
    assert_eq!(
        summary.features.get("agent_files.total").copied(),
        Some(2.0),
        "expected two matches in summary: {:?}",
        summary.features
    );
    assert!(matches!(summary.location, Location::Repo));
}

#[test]
fn banned_patterns_detects_unsafe_coerce_and_ts_ignore() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Put each hit in its own file so the line/location is predictable
    // and the self-scan noise filter doesn't accidentally match.
    write(
        root,
        "lib/dangerous.hs",
        "import Unsafe.Coerce\n\nfoo = unsafeCoerce 1\n",
    );
    write(root, "app/legacy.ts", "// @ts-ignore\nconst x: any = 1;\n");
    write(root, "README.md", "# plain\nno hits here.\n");

    let mut set = FindingSet::new();
    banned_patterns::run(root, &mut set).expect("banned_patterns run");

    let findings: Vec<_> = set
        .groups()
        .filter(|(name, _)| **name == banned_patterns::NAME)
        .flat_map(|(_, group)| group.iter())
        .collect();

    let rules: Vec<_> = findings.iter().map(|f| f.rule).collect();
    assert!(
        rules.contains(&"haskell_unsafe_coerce"),
        "expected haskell_unsafe_coerce: {rules:?}"
    );
    assert!(rules.contains(&"ts_ignore"), "expected ts_ignore: {rules:?}");

    let summary = findings
        .iter()
        .find(|f| f.rule == "summary")
        .expect("summary finding");
    let total = summary
        .features
        .get("banned_patterns.total")
        .copied()
        .unwrap_or(0.0);
    assert!(total >= 2.0, "expected >= 2 banned hits, got {total}");
}

#[test]
fn agent_files_summary_is_zero_on_clean_repo() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    write(root, "src/main.rs", "fn main(){}\n");
    write(root, "README.md", "# nothing interesting\n");

    let mut set = FindingSet::new();
    agent_files::run(root, &mut set).expect("agent_files run");

    let summary = set
        .groups()
        .filter(|(name, _)| **name == agent_files::NAME)
        .flat_map(|(_, g)| g.iter())
        .find(|f| f.rule == "summary")
        .expect("summary finding");
    assert_eq!(
        summary.features.get("agent_files.total").copied(),
        Some(0.0)
    );
}
