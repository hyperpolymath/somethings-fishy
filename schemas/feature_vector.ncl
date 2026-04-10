# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# Feature-vector schema for robofishy v0 scanner output.
#
# Every Finding emitted by a v0 scanner carries a scalar feature
# vector, per ADR 0002. This file is the machine-readable contract
# between the scanners (which *produce* features) and v1's classifier
# (which *consumes* them). It serves three jobs:
#
#   1. Pins the dimensions each scanner is allowed to populate, so a
#      scanner change that silently adds or drops a dimension will
#      surface as a schema violation rather than a mystery behaviour
#      shift months later.
#   2. Documents the meaning of each dimension in one place, rather
#      than forcing readers to grep the Rust source.
#   3. Gives v1's feature-extraction layer a stable set of canonical
#      names to hash into the classifier's input vector.
#
# Convention: dimension names are dot-delimited, prefixed by scanner
# name, lowercase, ASCII. Values are f64 in Rust, rendered as numbers
# in the A2ML report. Count-valued dimensions are integers; the
# emitter drops the decimal point in that case.
#
# This schema is not *enforced* at runtime in v0 — the scanners are
# the source of truth and the schema tracks them. When v1 adds a
# Nickel-based validation step, it will import this file directly.

let Scalar = Number in

let FeatureDimension = {
  # Canonical dimension key, exactly as it appears in A2ML reports.
  key | String,
  # One-line human-readable description.
  description | String,
  # Whether the value is a count (non-negative integer) or a general
  # scalar. v1's classifier may normalise counts differently from
  # general scalars (e.g. log-scaling counts).
  kind | [| 'Count, 'Scalar, 'Indicator |],
  # Which Finding type this dimension is expected to appear on:
  #   'PerItem     — on every finding the scanner emits
  #   'Summary     — only on the summary finding (Location::Repo)
  #   'PerItemOrSummary — may appear on either
  kind_of_finding | [| 'PerItem, 'Summary, 'PerItemOrSummary |],
} in

let dim = fun key desc kind kof => {
  key = key,
  description = desc,
  kind = kind,
  kind_of_finding = kof,
} in

let count = fun key desc kof => dim key desc 'Count kof in
let scalar = fun key desc kof => dim key desc 'Scalar kof in
let indicator = fun key desc kof => dim key desc 'Indicator kof in

{
  version = "0.1.0",

  scanners = {
    agent_files = {
      description = "Detects agent-addressed files (CLAUDE.md, .claude/, copilot-instructions.md, cursor, aider, gemini, codex, windsurf, continue, AGENTS.md).",
      dimensions = [
        # Per-family indicator (1.0 if the finding matched this family).
        indicator "agent_files.claude"   "Claude family file present" 'PerItem,
        indicator "agent_files.copilot"  "GitHub Copilot marker present" 'PerItem,
        indicator "agent_files.cursor"   "Cursor marker present" 'PerItem,
        indicator "agent_files.aider"    "Aider marker present" 'PerItem,
        indicator "agent_files.gemini"   "Gemini CLI marker present" 'PerItem,
        indicator "agent_files.codex"    "Codex CLI marker present" 'PerItem,
        indicator "agent_files.windsurf" "Windsurf marker present" 'PerItem,
        indicator "agent_files.continue" "Continue.dev marker present" 'PerItem,
        indicator "agent_files.generic"  "Generic AGENTS.md / AI.md marker present" 'PerItem,
        # Per-file attribute.
        scalar "agent_files.size_bytes" "File size in bytes (weak proxy for 'was this edited')" 'PerItem,
        # Summary aggregates.
        count "agent_files.total" "Total agent-file matches found in repo" 'Summary,
        count "agent_files.claude_count"   "Number of Claude-family matches" 'Summary,
        count "agent_files.copilot_count"  "Number of Copilot matches" 'Summary,
        count "agent_files.cursor_count"   "Number of Cursor matches" 'Summary,
        count "agent_files.aider_count"    "Number of Aider matches" 'Summary,
        count "agent_files.gemini_count"   "Number of Gemini matches" 'Summary,
        count "agent_files.codex_count"    "Number of Codex matches" 'Summary,
        count "agent_files.windsurf_count" "Number of Windsurf matches" 'Summary,
        count "agent_files.continue_count" "Number of Continue.dev matches" 'Summary,
        count "agent_files.generic_count"  "Number of generic agent-file matches" 'Summary,
      ],
    },

    commit_trailers = {
      description = "Bounded git log walk matching known agent trailers / bot actors.",
      dimensions = [
        indicator "commit_trailers.claude"    "Claude signature matched this commit" 'PerItem,
        indicator "commit_trailers.copilot"   "Copilot signature matched this commit" 'PerItem,
        indicator "commit_trailers.codex"     "Codex signature matched this commit" 'PerItem,
        indicator "commit_trailers.gemini"    "Gemini signature matched this commit" 'PerItem,
        indicator "commit_trailers.cursor"    "Cursor signature matched this commit" 'PerItem,
        indicator "commit_trailers.aider"     "Aider signature matched this commit" 'PerItem,
        indicator "commit_trailers.windsurf"  "Windsurf signature matched this commit" 'PerItem,
        indicator "commit_trailers.bot_other" "Dependabot/Renovate/GHA baseline bot" 'PerItem,
        # Summary aggregates.
        count "commit_trailers.commits_seen"      "Commits inspected in the bounded walk" 'Summary,
        count "commit_trailers.commits_flagged"   "Commits with at least one signature match" 'Summary,
        count "commit_trailers.claude_count"      "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.copilot_count"     "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.codex_count"       "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.gemini_count"      "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.cursor_count"      "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.aider_count"       "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.windsurf_count"    "Per-agent commit hit counts" 'Summary,
        count "commit_trailers.bot_other_count"   "Per-agent commit hit counts" 'Summary,
        indicator "commit_trailers.skipped"       "Scanner skipped (not a git repo or git log failed)" 'Summary,
      ],
    },

    banned_patterns = {
      description = "Aho-Corasick scan over the estate dangerous-patterns catalogue.",
      dimensions = [
        # Per-hit indicators. Keys match the Rule.feature field in the
        # Rust source 1:1; changing a key here means changing it there.
        indicator "banned_patterns.believe_me"            "Idris2 believe_me escape hatch" 'PerItem,
        indicator "banned_patterns.assert_total"          "Idris2 assert_total escape hatch" 'PerItem,
        indicator "banned_patterns.really_believe_me"     "Idris2 really_believe_me escape hatch" 'PerItem,
        indicator "banned_patterns.admitted"              "Coq/Rocq Admitted" 'PerItem,
        indicator "banned_patterns.admit"                 "Lean admit" 'PerItem,
        indicator "banned_patterns.sorry"                 "Lean sorry" 'PerItem,
        indicator "banned_patterns.unsafe_coerce"         "Haskell unsafeCoerce" 'PerItem,
        indicator "banned_patterns.obj_magic"             "OCaml Obj.magic" 'PerItem,
        indicator "banned_patterns.ts_ignore"             "TypeScript @ts-ignore" 'PerItem,
        indicator "banned_patterns.ts_nocheck"            "TypeScript @ts-nocheck" 'PerItem,
        indicator "banned_patterns.ts_expect_error"       "TypeScript @ts-expect-error" 'PerItem,
        indicator "banned_patterns.py_type_ignore"        "Python # type: ignore" 'PerItem,
        indicator "banned_patterns.py_noqa"               "Python # noqa" 'PerItem,
        indicator "banned_patterns.rust_transmute"        "Rust std::mem::transmute" 'PerItem,
        indicator "banned_patterns.rust_unwrap_unchecked" "Rust unwrap_unchecked" 'PerItem,
        indicator "banned_patterns.eval_call"             "Dynamic eval() call" 'PerItem,
        indicator "banned_patterns.exec_call"             "Dynamic exec() call" 'PerItem,
        indicator "banned_patterns.todo_claude"           "TODO(claude) comment" 'PerItem,
        indicator "banned_patterns.todo_copilot"          "TODO(copilot) comment" 'PerItem,
        indicator "banned_patterns.xxx_ai"                "XXX AI: comment" 'PerItem,
        # Summary aggregates.
        count "banned_patterns.total"         "Total banned-pattern hits across all files" 'Summary,
        count "banned_patterns.files_scanned" "Text files actually scanned" 'Summary,
        # Plus per-pattern `<feature>_count` summary keys, one per
        # indicator above. Not re-listed individually; they mirror the
        # per-item indicators with a `_count` suffix.
      ],
    },

    panic_attack = {
      description = "Wraps `panic-attack assail --output-format json` and lifts its statistics block into features.",
      dimensions = [
        indicator "panic_attack.invoked"     "panic-attack was actually run (vs. skipped or unavailable)" 'Summary,
        indicator "panic_attack.skipped"     "Scanner skipped by caller" 'Summary,
        indicator "panic_attack.unavailable" "panic-attack binary not on PATH" 'Summary,
        indicator "panic_attack.parse_failed" "panic-attack ran but its report could not be parsed" 'Summary,
        indicator "panic_attack.flagged"     "panic-attack exit code was nonzero" 'Summary,
        scalar "panic_attack.exit_code"              "Process exit code from panic-attack" 'Summary,
        scalar "panic_attack.stdout_bytes"           "stdout volume (bytes)" 'Summary,
        scalar "panic_attack.stderr_bytes"           "stderr volume (bytes)" 'Summary,
        count "panic_attack.weak_points"             "panic-attack weak_points[] length" 'Summary,
        count "panic_attack.total_lines"             "statistics.total_lines" 'Summary,
        count "panic_attack.unsafe_blocks"           "statistics.unsafe_blocks" 'Summary,
        count "panic_attack.panic_sites"             "statistics.panic_sites" 'Summary,
        count "panic_attack.unwrap_calls"            "statistics.unwrap_calls" 'Summary,
        count "panic_attack.allocation_sites"        "statistics.allocation_sites" 'Summary,
        count "panic_attack.io_operations"           "statistics.io_operations" 'Summary,
        count "panic_attack.threading_constructs"    "statistics.threading_constructs" 'Summary,
      ],
    },
  },

  # Cross-cutting dimensions that any scanner may emit on its
  # "scanner_error" Info finding (see scan.rs::wrap).
  scanner_error = {
    description = "Emitted by the scan.rs orchestrator when a scanner returns Err.",
    dimensions = [
      indicator "<scanner>.error" "1.0 when the scanner errored, e.g. `agent_files.error`" 'PerItem,
    ],
  },
}
