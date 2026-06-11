// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Cargo build script — orchestrates the Ada/SPARK safety kernel build
// and wires its static library into the Rust crate's link step.
//
// Responsibilities:
//
//   1. Re-run `alr build` inside `safety_kernel/` whenever any Ada source
//      changes, producing a fresh `safety_kernel/lib/libSafety_Kernel.a`.
//      (gnatprove proof discharge is not re-run here — that is a separate
//      CI step. v0's build.rs is about linkage, not verification.)
//
//   2. Locate the GNAT runtime's `adalib` directory via
//      `alr exec -- gcc -print-file-name=adalib`. The path contains an
//      Alire-toolchain-specific hash that we do not hardcode.
//
//   3. Emit `cargo:rustc-link-search` / `cargo:rustc-link-lib` directives
//      so the final `robofishy` binary links against the SPARK-verified
//      archive plus the GNAT runtime support libraries.
//
// Link order matters on Linux static-link: the standalone archive first,
// then the GNAT runtime, then system libraries.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir: PathBuf = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR unset")
        .into();

    let safety_kernel_dir = manifest_dir.join("safety_kernel");
    let safety_kernel_lib = safety_kernel_dir.join("lib");

    // Re-run this build script whenever the Ada sources or the GPR file
    // change. Cargo tracks dependencies via these emitted paths.
    println!("cargo:rerun-if-changed=safety_kernel/safety_kernel.gpr");
    for entry in walk_ada_sources(&safety_kernel_dir.join("src")) {
        println!("cargo:rerun-if-changed={}", entry.display());
    }

    // Step 1: build the safety kernel via Alire. The user's interactive
    // shell has already done this during development, but build.rs must
    // not assume that.
    let alr_status = Command::new("alr")
        .args(["-n", "build"])
        .current_dir(&safety_kernel_dir)
        .status()
        .expect("failed to invoke `alr build`; is Alire installed?");

    if !alr_status.success() {
        panic!(
            "`alr build` in {} failed with status {}",
            safety_kernel_dir.display(),
            alr_status
        );
    }

    // Step 2: locate the GNAT runtime's adalib directory. We ask gcc via
    // the Alire-managed toolchain so the path is correct for whichever
    // pinned GNAT version Alire is using.
    let adalib_output = Command::new("alr")
        .args(["exec", "--", "gcc", "-print-file-name=adalib"])
        .current_dir(&safety_kernel_dir)
        .output()
        .expect("failed to invoke `alr exec gcc -print-file-name=adalib`");

    if !adalib_output.status.success() {
        panic!(
            "gcc -print-file-name=adalib failed: {}",
            String::from_utf8_lossy(&adalib_output.stderr)
        );
    }

    let adalib_path = String::from_utf8(adalib_output.stdout)
        .expect("adalib path was not valid UTF-8")
        .trim()
        .to_string();

    // Step 3: emit cargo link directives.
    //
    // The safety kernel is built with `Library_Standalone => "encapsulated"`,
    // which means libSafety_Kernel.a bundles everything it needs from the
    // Ada runtime — so in principle we should not need `-lgnat`. In
    // practice Linux static linking still wants the GNAT runtime archive
    // alongside for symbols the encapsulation doesn't cover (thread-local
    // support, some exception handling paths), so we add it defensively.
    println!(
        "cargo:rustc-link-search=native={}",
        safety_kernel_lib.display()
    );
    println!("cargo:rustc-link-search=native={adalib_path}");
    println!("cargo:rustc-link-lib=static=Safety_Kernel");
    println!("cargo:rustc-link-lib=static=gnat");

    // System libraries GNAT binds to. These are almost universally needed
    // when linking any Ada program, even a trivial one.
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}

fn walk_ada_sources(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "ads" || ext == "adb" {
                    out.push(path);
                }
            }
        }
    }
    out
}
