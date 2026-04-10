// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// commit_trailers scanner.
//
// Walks the clone's commit history and flags commits that carry
// trailers, signatures, or generated-by markers associated with known
// agentic tools. This is one of the most reliable shallow signals
// available — trailers are typed by convention, persist through rebases
// when done correctly, and survive squash-merges about as well as
// anything else in git metadata.
//
// Implementation notes:
//
//   * We shell out to `git log` with a NUL-delimited format. Parsing the
//     output with a line-oriented regex would be fragile because commit
//     bodies legitimately contain blank lines; NUL delimiters are free
//     and unambiguous.
//   * We deliberately do not call `git interpret-trailers`. That helper
//     is strict about folded/unfolded whitespace, and we specifically
//     want to catch the sloppy variants ("co-authored-by" without the
//     dash, "Generated with" instead of "Generated-With:") that agents
//     emit in the wild.
//   * Feature vector per commit Finding: one dimension per detected
//     agent family plus a summary vector on a repo-level Finding.

use anyhow::{Context, Result};
use regex::RegexBuilder;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::finding::{Finding, FindingSet, Location, Severity};

/// Scanner name used in Finding tuples and feature keys.
pub const NAME: &str = "commit_trailers";

/// How many commits back we inspect. The goal is forensic utility, not
/// a full history rewrite detector, so "recent tail" is sufficient for
/// v0. A future version will lift this to the full history once the
/// classifier wants a full time series.
const MAX_COMMITS: usize = 5000;

/// Agent signature catalogue. Each entry is a case-insensitive substring
/// search over the commit body (subject + trailers + free-form text).
struct Signature {
    /// Substring to find (case-insensitive).
    needle: &'static str,
    /// Rule identifier reported on the Finding.
    rule: &'static str,
    /// Agent family, used as a feature-vector dimension.
    agent: &'static str,
}

const SIGNATURES: &[Signature] = &[
    // Claude Code ships this exact trailer in its default commit flow.
    Signature { needle: "co-authored-by: claude",       rule: "coauthor_claude",     agent: "claude"    },
    Signature { needle: "generated with [claude code]", rule: "generated_claude",    agent: "claude"    },
    Signature { needle: "generated with claude code",   rule: "generated_claude_alt",agent: "claude"    },
    Signature { needle: "noreply@anthropic.com",        rule: "anthropic_noreply",   agent: "claude"    },
    // GitHub Copilot (PR agent and CLI variants)
    Signature { needle: "co-authored-by: copilot",      rule: "coauthor_copilot",    agent: "copilot"   },
    Signature { needle: "copilot@users.noreply.github.com", rule: "copilot_email",   agent: "copilot"   },
    // OpenAI Codex CLI
    Signature { needle: "co-authored-by: codex",        rule: "coauthor_codex",      agent: "codex"     },
    Signature { needle: "generated with codex",         rule: "generated_codex",     agent: "codex"     },
    // Gemini CLI
    Signature { needle: "co-authored-by: gemini",       rule: "coauthor_gemini",     agent: "gemini"    },
    Signature { needle: "generated with gemini",        rule: "generated_gemini",    agent: "gemini"    },
    // Cursor
    Signature { needle: "generated with cursor",        rule: "generated_cursor",    agent: "cursor"    },
    Signature { needle: "co-authored-by: cursor",       rule: "coauthor_cursor",     agent: "cursor"    },
    // Aider
    Signature { needle: "aider: ",                      rule: "aider_prefix",        agent: "aider"     },
    Signature { needle: "aider (gpt-",                  rule: "aider_gpt_marker",    agent: "aider"     },
    // Windsurf / Cascade
    Signature { needle: "generated with windsurf",      rule: "generated_windsurf",  agent: "windsurf"  },
    // Generic bot actors — noisy but useful as a baseline rate
    Signature { needle: "dependabot[bot]",              rule: "dependabot_actor",    agent: "bot_other" },
    Signature { needle: "renovate[bot]",                rule: "renovate_actor",      agent: "bot_other" },
    Signature { needle: "github-actions[bot]",          rule: "gha_actor",           agent: "bot_other" },
];

/// Run the scanner against the git clone at `clone_path`.
pub fn run(clone_path: &Path, set: &mut FindingSet) -> Result<()> {
    // Short-circuit cleanly if this isn't a git repo (e.g. a bare tree
    // passed by mistake). We emit an Info finding so the absence is
    // visible in the report rather than silently producing nothing.
    if !clone_path.join(".git").exists() {
        set.push(
            Finding::new(
                NAME,
                "not_a_git_repo",
                Severity::Info,
                Location::Repo,
                "clone has no .git directory; skipping commit trailer scan",
            )
            .with_feature("commit_trailers.skipped", 1.0),
        );
        return Ok(());
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(clone_path)
        .arg("log")
        .arg(format!("--max-count={MAX_COMMITS}"))
        // NUL-delimited records: `<sha>\x1f<body>\x1e` where \x1f
        // separates fields within a record and \x1e ends the record.
        // These ASCII control characters are effectively never present
        // in real commit metadata.
        .arg("--format=%H%x1f%B%x1e")
        .output()
        .with_context(|| format!("running git log in {}", clone_path.display()))?;

    if !output.status.success() {
        // A non-fatal failure path: if `git log` refuses we emit an
        // Info finding and return. The whole investigation is still
        // useful without commit-trailer data.
        set.push(
            Finding::new(
                NAME,
                "git_log_failed",
                Severity::Info,
                Location::Repo,
                format!(
                    "git log failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            )
            .with_feature("commit_trailers.skipped", 1.0),
        );
        return Ok(());
    }

    // Pre-compile the case-insensitive patterns once. We use regex only
    // to get cheap case-insensitive substring search via `is_match`;
    // this is not a structural match.
    let compiled: Vec<_> = SIGNATURES
        .iter()
        .map(|sig| {
            RegexBuilder::new(&regex::escape(sig.needle))
                .case_insensitive(true)
                .build()
                .expect("static pattern compiles")
        })
        .collect();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut per_agent: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut commits_seen: u64 = 0;
    let mut commits_flagged: u64 = 0;

    for record in stdout.split('\x1e') {
        let record = record.trim_start_matches('\n');
        if record.is_empty() {
            continue;
        }
        let (sha, body) = match record.split_once('\x1f') {
            Some(parts) => parts,
            None => continue,
        };
        commits_seen += 1;

        let mut commit_agents: Vec<(&Signature, &'static str)> = Vec::new();
        for (sig, pat) in SIGNATURES.iter().zip(compiled.iter()) {
            if pat.is_match(body) {
                commit_agents.push((sig, sig.agent));
            }
        }
        if commit_agents.is_empty() {
            continue;
        }

        commits_flagged += 1;

        // One Finding per (commit, signature) hit. That keeps the
        // report grain fine enough for the classifier and for humans
        // who want to see *which* marker fired.
        for (sig, agent) in &commit_agents {
            *per_agent.entry(agent).or_insert(0) += 1;
            let finding = Finding::new(
                NAME,
                sig.rule,
                Severity::Strong,
                Location::Commit {
                    sha: sha.to_string(),
                },
                format!(
                    "{} signature matched in commit {}",
                    agent,
                    short_sha(sha)
                ),
            )
            .with_feature(&format!("commit_trailers.{agent}"), 1.0);
            set.push(finding);
        }
    }

    // Summary Finding: exposes the per-agent counts and the base-rate
    // denominator (commits_seen) in one place.
    let mut summary = Finding::new(
        NAME,
        "summary",
        if commits_flagged == 0 {
            Severity::Info
        } else {
            Severity::Notice
        },
        Location::Repo,
        format!(
            "commit_trailers: {commits_flagged}/{commits_seen} commits carry agent signatures"
        ),
    )
    .with_feature("commit_trailers.commits_seen", commits_seen as f64)
    .with_feature("commit_trailers.commits_flagged", commits_flagged as f64);
    for (agent, count) in &per_agent {
        summary = summary.with_feature(
            &format!("commit_trailers.{agent}_count"),
            *count as f64,
        );
    }
    set.push(summary);

    Ok(())
}

fn short_sha(sha: &str) -> &str {
    if sha.len() >= 12 { &sha[..12] } else { sha }
}
