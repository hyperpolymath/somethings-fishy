// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// Git subprocess wrapper.
//
// v0 stub: shells out to `git clone` to materialise the target inside
// the scene directory. Accepts either a remote URL or a local path;
// in both cases the operation is a full clone (independent working
// tree) so the subject is never touched.

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

/// Clone `target` into `dest`. Fails if the destination already exists.
///
/// This function does **not** route through `safe_io` because it
/// invokes an external `git` process whose writes are entirely inside
/// `dest` (git's own behaviour). The SPARK guard applies to writes
/// originating from *this* crate's code; external subprocesses are
/// governed by their contract, not by SPARK.
///
/// The scene layer is responsible for ensuring `dest` lies strictly
/// inside the scene root before this function is called.
pub fn git_clone(target: &str, dest: &Path) -> Result<()> {
    let status = Command::new("git")
        .arg("clone")
        .arg("--quiet")
        .arg(target)
        .arg(dest)
        .status()
        .with_context(|| format!("spawning `git clone {target}`"))?;

    if !status.success() {
        return Err(anyhow!(
            "`git clone {target} {}` failed with {status}",
            dest.display()
        ));
    }
    Ok(())
}
