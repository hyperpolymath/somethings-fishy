#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# robofishy end-to-end tests: build → scan a synthetic crime scene →
# verify findings, isolation invariants, and test-retest stability.
#
# Usage:
#   bash tests/e2e.sh
#   just e2e
#
# Requires: cargo (plus Alire/GNAT for the safety kernel), git.
# The release binary is built if absent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
SKIP=0

# ─── Colour helpers ──────────────────────────────────────────────────
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# ─── Assertion helpers ───────────────────────────────────────────────

# check <label> <expected-substring> <actual>
check() {
    local name="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        green "  PASS: $name"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $name (expected '$expected', got '${actual:0:120}')"
        FAIL=$((FAIL + 1))
    fi
}

# check_eq <label> <expected> <actual>
check_eq() {
    local name="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        green "  PASS: $name"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $name (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

skip_test() {
    yellow "  SKIP: $1 ($2)"
    SKIP=$((SKIP + 1))
}

echo "═══════════════════════════════════════════════════════════════"
echo "  robofishy — End-to-End Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Preflight ───────────────────────────────────────────────────────
bold "Preflight checks"

command -v git >/dev/null 2>&1 || { red "git not found"; exit 1; }

BINARY="$PROJECT_DIR/target/release/robofishy"
if [ ! -f "$BINARY" ]; then
    yellow "  Binary not found — building release profile"
    (cd "$PROJECT_DIR" && cargo build --release)
fi
green "  Binary: $BINARY"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
SCENES="$WORKDIR/scenes"
echo ""

# ─── Section 1: CLI basics ───────────────────────────────────────────
bold "Section 1: CLI basics"

OUTPUT=$("$BINARY" --help 2>&1)
check "help flag works" "Usage" "$OUTPUT"

OUTPUT=$("$BINARY" scan --help 2>&1)
check "scan help mentions scene root" "scene-root" "$OUTPUT"

set +e
"$BINARY" scan 2>/dev/null
NOARG_STATUS=$?
set -e
if [ "$NOARG_STATUS" -ne 0 ]; then
    green "  PASS: scan without target exits non-zero"
    PASS=$((PASS + 1))
else
    red "  FAIL: scan without target exited 0"
    FAIL=$((FAIL + 1))
fi
echo ""

# ─── Section 2: synthetic crime scene ────────────────────────────────
bold "Section 2: full pipeline on a synthetic subject"

SUBJECT="$WORKDIR/subject"
mkdir -p "$SUBJECT"
git -C "$SUBJECT" init -q -b main
git -C "$SUBJECT" config user.email "e2e@example.invalid"
git -C "$SUBJECT" config user.name "E2E Fixture"
# Agent-addressed file (agent_files scanner)
printf '# Instructions for the agent\n' > "$SUBJECT/CLAUDE.md"
# Ordinary source file
printf 'fn main() {}\n' > "$SUBJECT/main.rs"
git -C "$SUBJECT" add -A
git -C "$SUBJECT" commit -q -m "feat: initial

Co-Authored-By: Claude <noreply@anthropic.com>"

REPORT_PATH=$("$BINARY" scan --scene-root "$SCENES" --skip-panic-attack "$SUBJECT" 2>"$WORKDIR/scan.log")
check "scan prints report path" "report.a2ml" "$REPORT_PATH"
check "report file exists" "report.a2ml" "$(ls "$(dirname "$REPORT_PATH")")"

REPORT=$(cat "$REPORT_PATH")
check "report is robofishy A2ML" "robofishy-report" "$REPORT"
check "agent file detected" "CLAUDE.md" "$REPORT"
check "bot commit trailer detected" "commit_trailers" "$REPORT"
check "scanner pipeline log line present" "finding(s) across" "$(cat "$WORKDIR/scan.log")"
echo ""

# ─── Section 3: isolation invariants ─────────────────────────────────
bold "Section 3: isolation invariants (touch nothing)"

check_eq "subject working tree untouched" "" "$(git -C "$SUBJECT" status --porcelain)"
SUBJECT_FILES=$(find "$SUBJECT" -type f -not -path '*/.git/*' | wc -l | tr -d ' ')
check_eq "no files added to subject" "2" "$SUBJECT_FILES"
CLONE_DIR="$(dirname "$REPORT_PATH")/target"
check "clone lives inside the scene" "$SCENES" "$CLONE_DIR"
echo ""

# ─── Section 4: test-retest reliability ──────────────────────────────
bold "Section 4: test-retest reliability (stable finding IDs)"

sleep 1  # ensure a distinct timestamped scene directory
REPORT_PATH2=$("$BINARY" scan --scene-root "$SCENES" --skip-panic-attack "$SUBJECT" 2>/dev/null)
IDS1=$(grep -o '(id "[0-9a-f]*")' "$REPORT_PATH" | sort)
IDS2=$(grep -o '(id "[0-9a-f]*")' "$REPORT_PATH2" | sort)
check_eq "finding IDs identical across runs" "$IDS1" "$IDS2"
ID_COUNT=$(echo "$IDS1" | grep -c id || true)
if [ "$ID_COUNT" -gt 0 ]; then
    green "  PASS: report carries $ID_COUNT content-addressed finding IDs"
    PASS=$((PASS + 1))
else
    red "  FAIL: no finding IDs found in report"
    FAIL=$((FAIL + 1))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo "═══════════════════════════════════════════════════════════════"
printf "  Results: "
green "PASS=$PASS" | tr -d '\n'
echo -n "  "
if [ "$FAIL" -gt 0 ]; then red "FAIL=$FAIL" | tr -d '\n'; else echo -n "FAIL=0"; fi
echo -n "  "
if [ "$SKIP" -gt 0 ]; then yellow "SKIP=$SKIP"; else echo "SKIP=0"; fi
echo "═══════════════════════════════════════════════════════════════"

exit "$FAIL"
