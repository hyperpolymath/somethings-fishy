// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// SPARK guard rejection test.
//
// This is a proof-of-life for the safety invariant itself, not just the
// build chain. It constructs a temporary scene root, confirms that a
// write *inside* it is accepted by the Ada kernel, and then confirms
// that a write *outside* it is rejected.
//
// The rejection is the important half: it demonstrates that the Rust
// FFI wrapper cannot bypass the SPARK-proven Is_Inside check even when
// asked nicely.
//
// Cargo runs each integration test file as its own binary, so GNAT
// elaboration happens exactly once in this process.

use robofishy::safe_io::{SafeIO, SafeWriteError};
use std::fs;
use std::path::PathBuf;

fn temp_scene_root() -> PathBuf {
    let mut root = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    root.push(format!("robofishy-test-{pid}-{nanos}"));
    fs::create_dir_all(&root).expect("failed to create temp scene root");
    root
}

#[test]
fn write_inside_scene_root_is_accepted() {
    let safe_io = SafeIO::init();
    let scene_root = temp_scene_root();
    let target = scene_root.join("report.a2ml");

    let result = safe_io.write(
        &scene_root,
        &target,
        b"(test-report (ok true))\n",
    );

    assert!(
        result.is_ok(),
        "write inside scene root was unexpectedly rejected: {result:?}"
    );

    let contents = fs::read_to_string(&target)
        .expect("written file should be readable");
    assert_eq!(contents, "(test-report (ok true))\n");

    let _ = fs::remove_dir_all(&scene_root);
}

#[test]
fn write_outside_scene_root_is_rejected() {
    let safe_io = SafeIO::init();
    let scene_root = temp_scene_root();

    // An attacker-controlled target in /tmp, deliberately outside the
    // scene root. The SPARK-proven Is_Inside check must reject this.
    let evil_target = std::env::temp_dir().join(format!(
        "robofishy-evil-{}.a2ml",
        std::process::id()
    ));
    // Make sure no pre-existing file shows up as a false positive.
    let _ = fs::remove_file(&evil_target);

    let result = safe_io.write(
        &scene_root,
        &evil_target,
        b"(should-never-be-written)\n",
    );

    assert!(
        matches!(result, Err(SafeWriteError::Rejected)),
        "write OUTSIDE scene root was unexpectedly accepted: {result:?}"
    );

    // The rejected write must not have produced a file.
    assert!(
        !evil_target.exists(),
        "rejected write nevertheless produced a file at {}",
        evil_target.display()
    );

    let _ = fs::remove_dir_all(&scene_root);
}

#[test]
fn prefix_confusion_attack_is_rejected() {
    // The classic "prefix-confusion" attack: if Is_Inside only did a
    // naive starts-with check, a scene root of "/tmp/robofishy-foo"
    // would appear to contain "/tmp/robofishy-foobar/evil". The SPARK
    // kernel requires the prefix to be followed either by nothing or
    // by a path separator, which blocks this.

    let safe_io = SafeIO::init();
    let base = std::env::temp_dir().join(format!(
        "robofishy-prefix-{}",
        std::process::id()
    ));
    let scene_root = base.with_extension("foo");
    let sibling = base.with_extension("foobar");
    fs::create_dir_all(&scene_root)
        .expect("failed to create scene root");
    fs::create_dir_all(&sibling)
        .expect("failed to create sibling dir");
    let evil_target = sibling.join("evil.a2ml");
    let _ = fs::remove_file(&evil_target);

    let result = safe_io.write(
        &scene_root,
        &evil_target,
        b"(prefix-confusion)\n",
    );

    assert!(
        matches!(result, Err(SafeWriteError::Rejected)),
        "prefix-confusion attack was unexpectedly accepted: {result:?}"
    );
    assert!(!evil_target.exists());

    let _ = fs::remove_dir_all(&scene_root);
    let _ = fs::remove_dir_all(&sibling);
}
