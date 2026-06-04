// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
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
use std::process::Command;

use robofishy::finding::{FindingSet, Location};
use robofishy::scanners::{agent_files, banned_patterns, commit_trailers, panic_attack};

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
    assert!(
        rules.contains(&"claude_md"),
        "expected claude_md: {rules:?}"
    );
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
    assert!(
        rules.contains(&"ts_ignore"),
        "expected ts_ignore: {rules:?}"
    );

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

/// Initialise a fresh git repo with a known identity in `dir` and
/// return Ok(()) if the subprocess chain works. Used by the
/// commit_trailers tests.
fn git_init(dir: &Path) {
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("spawn git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "--quiet", "--initial-branch=main"]);
    run(&["config", "user.name", "Test Harness"]);
    run(&["config", "user.email", "test@example.invalid"]);
    run(&["config", "commit.gpgsign", "false"]);
    run(&["config", "tag.gpgsign", "false"]);
}

fn git_commit(dir: &Path, message: &str) {
    let status = Command::new("git")
        .args(["commit", "--quiet", "--allow-empty", "-m", message])
        .current_dir(dir)
        .status()
        .expect("spawn git commit");
    assert!(status.success(), "git commit failed");
}

#[test]
fn commit_trailers_detects_claude_coauthor_and_copilot_actor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    git_init(root);

    git_commit(root, "initial: baseline commit");
    git_commit(
        root,
        "feat: add thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
    );
    git_commit(
        root,
        "chore(deps): bump foo\n\nSigned-off-by: copilot[bot] <198982749+Copilot@users.noreply.github.com>",
    );

    let mut set = FindingSet::new();
    commit_trailers::run(root, &mut set).expect("commit_trailers run");

    let findings: Vec<_> = set
        .groups()
        .filter(|(name, _)| **name == commit_trailers::NAME)
        .flat_map(|(_, g)| g.iter())
        .collect();

    let rules: Vec<_> = findings.iter().map(|f| f.rule).collect();
    assert!(
        rules.contains(&"coauthor_claude") || rules.contains(&"anthropic_noreply"),
        "expected a Claude signature rule: {rules:?}"
    );
    assert!(
        rules.contains(&"copilot_email"),
        "expected copilot_email rule: {rules:?}"
    );

    let summary = findings
        .iter()
        .find(|f| f.rule == "summary")
        .expect("summary finding");
    let seen = summary
        .features
        .get("commit_trailers.commits_seen")
        .copied()
        .unwrap_or(0.0);
    let flagged = summary
        .features
        .get("commit_trailers.commits_flagged")
        .copied()
        .unwrap_or(0.0);
    assert_eq!(seen, 3.0, "expected 3 commits, got {seen}");
    assert_eq!(flagged, 2.0, "expected 2 flagged commits, got {flagged}");
}

#[test]
fn commit_trailers_emits_info_when_not_a_git_repo() {
    // A plain directory with no .git tree exercises the graceful fallback.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut set = FindingSet::new();
    commit_trailers::run(tmp.path(), &mut set).expect("commit_trailers run");

    let rules: Vec<_> = set
        .groups()
        .filter(|(name, _)| **name == commit_trailers::NAME)
        .flat_map(|(_, g)| g.iter())
        .map(|f| f.rule)
        .collect();
    assert!(
        rules.contains(&"not_a_git_repo"),
        "expected not_a_git_repo: {rules:?}"
    );
}

#[test]
fn panic_attack_skip_mode_emits_stable_dimensions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut set = FindingSet::new();
    panic_attack::run(tmp.path(), /* skip */ true, &mut set).expect("panic_attack skip run");

    let finding = set
        .groups()
        .filter(|(name, _)| **name == panic_attack::NAME)
        .flat_map(|(_, g)| g.iter())
        .find(|f| f.rule == "skipped")
        .expect("skipped finding");
    assert_eq!(
        finding.features.get("panic_attack.invoked").copied(),
        Some(0.0)
    );
    assert_eq!(
        finding.features.get("panic_attack.skipped").copied(),
        Some(1.0)
    );
    assert!(matches!(finding.location, Location::Repo));
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
