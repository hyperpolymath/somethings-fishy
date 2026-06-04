// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// agent_files scanner.
//
// Detects the "paper trail" files that agentic tools drop into a repo:
// instructions, manifests, configuration. Presence alone is not evidence
// of harm; it is evidence of *which* agents had a working relationship
// with the repo, which is exactly what the autopsy framing cares about.
//
// The rule list is deliberately conservative and literal. Pattern-matched
// globs (e.g. "anything under .claude/") are represented as directory
// prefixes. We prefer over-matching a well-known directory to chasing
// every new vendor marketing decision about config file naming.
//
// Feature-vector convention (ADR 0002):
//
//   * Every emitted Finding carries `agent_files.<agent>=1.0` for the
//     agent family it matched, and `agent_files.size_bytes` for the
//     file size (a weak proxy for "was this edited or is it a stock
//     template").
//   * A synthetic summary Finding (rule = `summary`) carries the
//     aggregate vector: `agent_files.total` and one
//     `agent_files.<agent>_count` entry per observed family. The
//     summary Finding has Location::Repo so downstream consumers can
//     find it without iterating file-level findings.

use anyhow::Result;
use ignore::WalkBuilder;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::finding::{Finding, FindingSet, Location, Severity};

/// Scanner name used in Finding tuples and feature keys.
pub const NAME: &str = "agent_files";

/// One rule in the agent-files catalogue. Each rule maps a concrete
/// repo-relative path (file or directory) to the agent family it
/// indicates. Directories match any descendant.
struct Rule {
    /// Repo-relative path fragment. If it ends in `/`, treated as a
    /// directory prefix match; otherwise matched as an exact filename
    /// anywhere under the clone (case-sensitive).
    path: &'static str,
    /// Rule identifier emitted on the Finding.
    rule: &'static str,
    /// Agent family, used as a feature-vector dimension.
    agent: &'static str,
}

/// The full rule catalogue. Ordered roughly by how often each shows up
/// in the wild so early-exit scans stay cheap in the common case.
const RULES: &[Rule] = &[
    // Claude family
    Rule {
        path: "CLAUDE.md",
        rule: "claude_md",
        agent: "claude",
    },
    Rule {
        path: ".claude/",
        rule: "claude_dir",
        agent: "claude",
    },
    Rule {
        path: "0-AI-MANIFEST.a2ml",
        rule: "ai_manifest_a2ml",
        agent: "claude",
    },
    Rule {
        path: "AI.a2ml",
        rule: "ai_a2ml",
        agent: "claude",
    },
    Rule {
        path: "AI.md",
        rule: "ai_md",
        agent: "generic",
    },
    Rule {
        path: "AI.djot",
        rule: "ai_djot",
        agent: "generic",
    },
    // GitHub Copilot
    Rule {
        path: ".github/copilot-instructions.md",
        rule: "copilot_instructions",
        agent: "copilot",
    },
    // Cursor
    Rule {
        path: ".cursorrules",
        rule: "cursor_rules",
        agent: "cursor",
    },
    Rule {
        path: ".cursor/",
        rule: "cursor_dir",
        agent: "cursor",
    },
    // Aider
    Rule {
        path: ".aider.conf.yml",
        rule: "aider_conf",
        agent: "aider",
    },
    Rule {
        path: ".aider.chat.history.md",
        rule: "aider_history",
        agent: "aider",
    },
    // Gemini CLI
    Rule {
        path: "GEMINI.md",
        rule: "gemini_md",
        agent: "gemini",
    },
    Rule {
        path: ".gemini/",
        rule: "gemini_dir",
        agent: "gemini",
    },
    // OpenAI Codex CLI
    Rule {
        path: ".codex/",
        rule: "codex_dir",
        agent: "codex",
    },
    Rule {
        path: "CODEX.md",
        rule: "codex_md",
        agent: "codex",
    },
    // Windsurf
    Rule {
        path: ".windsurfrules",
        rule: "windsurf_rules",
        agent: "windsurf",
    },
    // Continue.dev
    Rule {
        path: ".continuerules",
        rule: "continue_rules",
        agent: "continue",
    },
    Rule {
        path: ".continue/",
        rule: "continue_dir",
        agent: "continue",
    },
    // Zed IDE (first-party AI integration)
    Rule {
        path: ".zed/",
        rule: "zed_dir",
        agent: "zed",
    },
    // Devin (Cognition AI)
    Rule {
        path: ".devin/",
        rule: "devin_dir",
        agent: "devin",
    },
    // GitHub Copilot prompt repository (newer surface)
    Rule {
        path: ".github/prompts/",
        rule: "copilot_prompts_dir",
        agent: "copilot",
    },
    // Generic agent manifest used by newer tooling
    Rule {
        path: "AGENTS.md",
        rule: "agents_md",
        agent: "generic",
    },
    Rule {
        path: "AGENT.md",
        rule: "agent_md",
        agent: "generic",
    },
];

/// Run the scanner against `clone_path` and push findings into `set`.
pub fn run(clone_path: &Path, set: &mut FindingSet) -> Result<()> {
    let mut per_agent: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut total: u32 = 0;

    // We walk once with the `ignore` crate so .gitignored trees and the
    // `.git/` directory itself are skipped by default. That keeps the
    // walk proportional to the working tree, not the entire clone
    // contents (git object database is large and irrelevant here).
    let walker = WalkBuilder::new(clone_path)
        .hidden(false) // dotfiles like .cursorrules must be visible
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        // Relative path is what we match rules against; absolute paths
        // embed the scene timestamp and defeat the test-retest guarantee.
        let rel = match path.strip_prefix(clone_path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy();

        for rule in RULES {
            if rule_matches(rule, &rel_str, entry.file_type().map(|t| t.is_dir())) {
                let size = file_size(path);
                let finding = Finding::new(
                    NAME,
                    rule.rule,
                    Severity::Notice,
                    Location::File {
                        path: PathBuf::from(rel.to_string_lossy().into_owned()),
                        line: None,
                    },
                    format!(
                        "{} file present ({}), {} bytes",
                        rule.agent, rule.rule, size
                    ),
                )
                .with_feature(&format!("agent_files.{}", rule.agent), 1.0)
                .with_feature("agent_files.size_bytes", size as f64);
                set.push(finding);
                *per_agent.entry(rule.agent).or_insert(0) += 1;
                total += 1;
                // A single path matches at most one rule: once we hit,
                // move on. The catalogue is ordered so the most specific
                // rule wins (e.g. `.claude/settings.json` is captured by
                // `.claude/`, not by a future generic `settings.json`).
                break;
            }
        }
    }

    // Synthetic summary Finding. Rule = "summary", Location = Repo, so
    // the report has a single well-known sink for the aggregate vector.
    let mut summary = Finding::new(
        NAME,
        "summary",
        if total == 0 {
            Severity::Info
        } else {
            Severity::Notice
        },
        Location::Repo,
        format!("agent_files scan found {total} matching paths"),
    )
    .with_feature("agent_files.total", total as f64);
    for (agent, count) in &per_agent {
        summary = summary.with_feature(&format!("agent_files.{agent}_count"), *count as f64);
    }
    set.push(summary);

    Ok(())
}

/// Does a rule fire for a given repo-relative path?
///
/// Directory rules (ending in `/`) fire when the rel path *starts with*
/// the rule path — this also catches the directory entry itself when
/// walking emits it. File rules fire when the rel path *equals* the rule
/// path (the common shallow case) or when the basename matches a
/// well-known loose-file rule placed at a subdirectory (rare in
/// practice, but trivially supported by the startswith / equals split).
fn rule_matches(rule: &Rule, rel: &str, is_dir: Option<bool>) -> bool {
    if let Some(dir_part) = rule.path.strip_suffix('/') {
        // Directory prefix match. Accept both `.claude` and `.claude/foo`.
        if rel == dir_part {
            return true;
        }
        if let Some(after) = rel.strip_prefix(dir_part) {
            return after.starts_with('/');
        }
        return false;
    }
    // File rule: exact equality only. Directories never match file rules.
    if is_dir == Some(true) {
        return false;
    }
    rel == rule.path
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}
