// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Isolation-directory lifecycle.
//!
//! A [`Scene`] owns a single investigation's isolation area: the clone
//! of the target, the emitted report, any evidence artefacts, and (in
//! later versions) a per-investigation VeriSimDB store. Nothing ever
//! lives outside a scene directory.

// Scene directory lifecycle.
//
// A "scene" is the isolation area for one investigation. It owns the clone
// of the target, the emitted report, any evidence artefacts, and in later
// versions the VeriSimDB per-investigation store. Nothing ever lives
// outside a scene directory — that is the mechanism by which the "touch
// nothing" invariant is enforced.
//
// Default scene root is `/mnt/eclipse/robofishy-scenes/`. The path is
// configurable via `--scene-root` but never defaults to anywhere under
// `/var/mnt/eclipse/repos/`; mixing scenes with real repos would blur the
// isolation boundary.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};

use crate::clone;

/// Default scene root, on the Eclipse drive, outside the repos tree.
const DEFAULT_SCENE_ROOT: &str = "/mnt/eclipse/robofishy-scenes";

/// An isolation directory owning one investigation.
#[derive(Debug)]
pub struct Scene {
    root: PathBuf,
}

impl Scene {
    /// Create a fresh scene directory under the (optionally overridden)
    /// scene root. Naming is `<UTC-ISO-timestamp>-<target-slug>` so that
    /// scenes sort chronologically and name-collide trivially never
    /// happens.
    pub fn create(target: &str, scene_root: Option<&Path>) -> Result<Self> {
        let root_base = match scene_root {
            Some(p) => p.to_path_buf(),
            None => PathBuf::from(DEFAULT_SCENE_ROOT),
        };

        // Refuse to create a scene inside `/var/mnt/eclipse/repos/`. This
        // guard is cheap and catches the one class of misconfiguration
        // that would undermine the isolation invariant.
        let canonical = root_base
            .canonicalize()
            .unwrap_or_else(|_| root_base.clone());
        if canonical.starts_with("/var/mnt/eclipse/repos")
            || canonical.starts_with("/mnt/eclipse/repos")
        {
            return Err(anyhow!(
                "refusing to place a scene inside the repos tree: {}",
                canonical.display()
            ));
        }

        std::fs::create_dir_all(&root_base)
            .with_context(|| format!("creating scene root {}", root_base.display()))?;

        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let slug = slugify(target);
        let scene_dir = root_base.join(format!("{stamp}-{slug}"));

        std::fs::create_dir_all(&scene_dir)
            .with_context(|| format!("creating scene directory {}", scene_dir.display()))?;

        Ok(Self { root: scene_dir })
    }

    /// The scene's filesystem root. All emitted artefacts live under here.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path to the cloned target inside this scene.
    pub fn target_path(&self) -> PathBuf {
        self.root.join("target")
    }

    /// Clone the target into this scene and return the clone path.
    ///
    /// Accepts either a git URL or a local filesystem path. In both cases
    /// a full `git clone` is performed — cloning a local path produces an
    /// independent working tree that can be inspected without ever
    /// touching the original. This is load-bearing for the "touch nothing"
    /// invariant and is not an optimisation opportunity.
    pub fn clone_target(&self, target: &str) -> Result<PathBuf> {
        let dest = self.target_path();
        clone::git_clone(target, &dest)?;
        Ok(dest)
    }
}

/// Turn an arbitrary target string into something filesystem-safe. Not
/// required to be reversible; only required to be deterministic and short.
fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    // Collapse runs of dashes.
    let mut collapsed = String::with_capacity(out.len());
    let mut last_dash = false;
    for ch in out.chars() {
        if ch == '-' {
            if !last_dash {
                collapsed.push(ch);
            }
            last_dash = true;
        } else {
            collapsed.push(ch);
            last_dash = false;
        }
    }
    let trimmed = collapsed.trim_matches('-');
    // Cap length so timestamps still dominate sort order.
    let max = 48;
    if trimmed.len() > max {
        trimmed[..max].to_string()
    } else {
        trimmed.to_string()
    }
}
