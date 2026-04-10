// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// robofishy — agent-autopsy forensic triage tool (v0 prototype)
//
// This binary is the only user-facing entry point. Its job is to parse a
// scan request, delegate to the library, and print a short human-readable
// summary pointing at the scene directory where the full A2ML report lives.
//
// Hard invariants (see ROADMAP.adoc and docs/decisions/0001, 0002):
//
//   * The tool never writes to the subject. The subject is cloned into an
//     isolation area and only the clone is touched.
//   * The tool itself has no side-effect channel other than the scene
//     directory. Any proposal-to-the-world goes through feedback-o-tron,
//     which v0 does not invoke.
//   * Panic-attack is carried as a subprocess, not reimplemented.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use robofishy::{report, safe_io, scan, scene};

#[derive(Parser, Debug)]
#[command(
    name = "robofishy",
    version,
    about = "Agent-autopsy forensic triage — reverse-constructs which agents edited a repo",
    long_about = "Clones a target into an isolation area and runs read-only \
                  forensic scanners. Never mutates the subject."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a target and emit an A2ML forensic report into a scene directory.
    Scan {
        /// Target to scan: a git URL, or a local filesystem path to an
        /// existing git repository.
        target: String,

        /// Override the default scene root
        /// (`/mnt/eclipse/robofishy-scenes/`).
        #[arg(long, value_name = "DIR")]
        scene_root: Option<PathBuf>,

        /// Skip the panic-attack subprocess invocation. Useful in
        /// environments where `panic-attack` is not on PATH.
        #[arg(long)]
        skip_panic_attack: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            target,
            scene_root,
            skip_panic_attack,
        } => run_scan(&target, scene_root, skip_panic_attack),
    }
}

fn run_scan(target: &str, scene_root: Option<PathBuf>, skip_panic_attack: bool) -> Result<()> {
    // Initialise the SPARK-verified safety kernel. This runs GNAT
    // elaboration and gives us the single write channel for the
    // remainder of the run. Dropped at end of scope, which releases
    // the Ada runtime.
    let safe_io = safe_io::SafeIO::init();

    // Create a fresh scene directory under the isolation root. Everything
    // this scan produces lives inside it; nothing is written anywhere else.
    let scene = scene::Scene::create(target, scene_root.as_deref())
        .context("failed to create scene directory")?;

    eprintln!("robofishy: scene created at {}", scene.root().display());

    // Clone the target into the scene's `target/` subdirectory. This is the
    // single operation that touches the outside world (network + local
    // filesystem inside the scene) and it is strictly read-once.
    let clone_path = scene.clone_target(target).context("clone failed")?;
    eprintln!("robofishy: target cloned to {}", clone_path.display());

    // Run the v0 scanner pipeline. Scanners only read; they produce Finding
    // values. The orchestrator collects them into a FindingSet.
    let findings = scan::run_all(&clone_path, scan::Options { skip_panic_attack })
        .context("scanner pipeline failed")?;

    eprintln!(
        "robofishy: {} finding(s) across {} scanner(s)",
        findings.total(),
        findings.scanner_count()
    );

    // Emit the A2ML report into the scene directory through the
    // SPARK-verified write channel. This is the only outbound artefact
    // of a v0 run.
    let report_path = report::write_a2ml(&safe_io, &scene, target, &clone_path, &findings)
        .context("report emission failed")?;

    println!("{}", report_path.display());
    Ok(())
}
