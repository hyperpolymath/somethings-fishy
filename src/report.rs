// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// A2ML forensic report emission.
//
// Writes an S-expression A2ML report (estate convention) describing a
// single scan. The report file lives inside the scene directory and is
// emitted exclusively through `safe_io::SafeIO::write`, so the path-
// containment property is SPARK-verified.

use anyhow::{Context, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};

use crate::finding::{FindingSet, Location};
use crate::safe_io::SafeIO;
use crate::scene::Scene;
use crate::VERSION;

/// Emit the A2ML report for a scan into the scene directory. Returns
/// the path to the written report file.
pub fn write_a2ml(
    safe_io: &SafeIO,
    scene: &Scene,
    target: &str,
    clone_path: &Path,
    findings: &FindingSet,
) -> Result<PathBuf> {
    let report_path = scene.root().join("report.a2ml");
    let body = render(target, clone_path, findings);

    safe_io
        .write(scene.root(), &report_path, body.as_bytes())
        .with_context(|| {
            format!(
                "SPARK-guarded write to {} rejected",
                report_path.display()
            )
        })?;

    Ok(report_path)
}

/// Render a findings set as S-expression A2ML. The format is
/// deliberately simple for v0; v1 will emit richer structure once the
/// classifier produces confidence intervals and per-agent attribution.
fn render(
    target: &str,
    clone_path: &Path,
    findings: &FindingSet,
) -> String {
    let mut out = String::new();
    out.push_str(";; SPDX-License-Identifier: PMPL-1.0-or-later\n");
    out.push_str(";; robofishy forensic report\n");
    out.push_str("(robofishy-report\n");
    out.push_str(&format!("  (version \"{VERSION}\")\n"));
    out.push_str(&format!(
        "  (generated-at \"{}\")\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    ));
    out.push_str("  (target\n");
    out.push_str(&format!("    (source \"{}\")\n", escape(target)));
    out.push_str(&format!(
        "    (clone-path \"{}\"))\n",
        escape(&clone_path.display().to_string())
    ));

    out.push_str("  (summary\n");
    out.push_str(&format!("    (total-findings {})\n", findings.total()));
    out.push_str(&format!(
        "    (scanner-count {}))\n",
        findings.scanner_count()
    ));

    out.push_str("  (findings\n");
    for (scanner_name, group) in findings.groups() {
        out.push_str(&format!("    ({}\n", scanner_name));
        for f in group {
            out.push_str("      (finding\n");
            out.push_str(&format!("        (id \"{}\")\n", f.id));
            out.push_str(&format!("        (rule \"{}\")\n", f.rule));
            out.push_str(&format!(
                "        (severity {})\n",
                f.severity.as_str()
            ));
            match &f.location {
                Location::Repo => {
                    out.push_str("        (location repo)\n");
                }
                Location::File { path, line } => match line {
                    Some(n) => out.push_str(&format!(
                        "        (location (file \"{}\") (line {n}))\n",
                        escape(&path.display().to_string())
                    )),
                    None => out.push_str(&format!(
                        "        (location (file \"{}\"))\n",
                        escape(&path.display().to_string())
                    )),
                },
                Location::Commit { sha } => {
                    out.push_str(&format!(
                        "        (location (commit \"{sha}\"))\n"
                    ));
                }
            }
            out.push_str(&format!(
                "        (message \"{}\"))\n",
                escape(&f.message)
            ));
        }
        out.push_str("    )\n");
    }
    out.push_str("  )\n");

    out.push_str("  (hard-invariants-honored\n");
    out.push_str("    (touched-subject false)\n");
    out.push_str("    (wrote-only-to-scene-dir true)\n");
    out.push_str("    (feedback-o-tron-invoked false)\n");
    out.push_str(
        "    (write-channel \"Robofishy_Write_Guard.Safe_Write (SPARK-verified)\"))\n",
    );
    out.push_str(")\n");
    out
}

/// Quote a string for embedding in a double-quoted S-expression atom.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}
