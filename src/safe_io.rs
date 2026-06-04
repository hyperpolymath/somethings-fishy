// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// SPARK-verified safe I/O surface.
//
// Every filesystem write in the robofishy crate routes through this
// module. The implementation calls into the Ada `safety_kernel` static
// library whose `Robofishy_Write_Guard.Safe_Write` subprogram is
// formally proved (by gnatprove) to satisfy:
//
//     if Success then Is_Inside(Scene_Root, Target)
//
// i.e., a successful write implies the target path lies strictly inside
// the scene root. A failed write guarantees that either the write never
// reached the filesystem or the target path is untrusted — the caller
// must treat it as "do not rely on this path".
//
// The Ada side requires one-time elaboration (`Safety_Kernelinit`) before
// any call; we perform that in `SafeIO::init()` and unwind in `Drop`.
// Rust's ownership model gives us a natural lifetime for this resource:
// one `SafeIO` per process, held for the duration of a scan.

use std::ffi::c_void;
use std::os::raw::{c_int, c_ulong};
use std::path::Path;

// ---------------------------------------------------------------------
// extern "C" declarations matching safety_kernel's exported symbols.
// ---------------------------------------------------------------------

extern "C" {
    // GNAT elaboration/finalization entry points for a standalone
    // library built with `Library_Standalone => "encapsulated"` and
    // `Library_Auto_Init => "false"`. The capitalization matches the
    // symbol GNAT actually emits (`Safety_Kernelinit`).
    #[link_name = "Safety_Kernelinit"]
    fn safety_kernel_init();

    #[link_name = "Safety_Kernelfinal"]
    fn safety_kernel_final();

    // The C-ABI export from `Robofishy_C_API`. Returns 1 on success,
    // 0 on any failure (bounds violation, path-outside-scene rejection,
    // or Stream_IO error). All pointers are borrowed for the duration
    // of the call; the Ada side copies into Ada-managed memory before
    // invoking the SPARK-verified core.
    fn robofishy_safe_write(
        scene_root_ptr: *const c_void,
        scene_root_len: c_ulong,
        target_ptr: *const c_void,
        target_len: c_ulong,
        payload_ptr: *const c_void,
        payload_len: c_ulong,
    ) -> c_int;
}

// ---------------------------------------------------------------------
// Safe Rust wrapper.
// ---------------------------------------------------------------------

/// Handle to the initialised Ada safety kernel. Construct once per
/// process; drop releases the Ada runtime.
#[derive(Debug)]
pub struct SafeIO {
    // Prevent direct construction from outside this module — callers
    // must go through `init`.
    _private: (),
}

/// Errors that the safe write path can produce.
#[derive(Debug, thiserror::Error)]
pub enum SafeWriteError {
    /// The target path, scene root, or payload exceeded the static
    /// bounds enforced by the safety kernel (4 KiB path, 16 MiB
    /// payload).
    #[error("argument exceeds safety kernel bounds")]
    BoundsExceeded,

    /// A path contained a NUL byte or was otherwise unrepresentable as
    /// a byte slice for the FFI boundary.
    #[error("path is not representable as bytes")]
    PathNotRepresentable,

    /// The safety kernel returned 0 — either the path was not inside
    /// the scene root, or the underlying I/O failed. In either case
    /// the caller must not trust the target path.
    #[error("safety kernel rejected or failed the write")]
    Rejected,
}

impl SafeIO {
    /// Initialise the Ada safety kernel. Must be called exactly once
    /// per process, before any [`SafeIO::write`] call.
    pub fn init() -> Self {
        // SAFETY: `safety_kernel_init` is the GNAT-emitted elaboration
        // wrapper. It is idempotent enough that a second call is a
        // no-op, but we rely on callers to construct `SafeIO` only
        // once per process lifetime.
        unsafe { safety_kernel_init() };
        SafeIO { _private: () }
    }

    /// Write `payload` to `target` iff `target` is strictly inside
    /// `scene_root`. The check is performed and formally verified by
    /// the Ada safety kernel; this Rust wrapper is thin glue.
    pub fn write(
        &self,
        scene_root: &Path,
        target: &Path,
        payload: &[u8],
    ) -> Result<(), SafeWriteError> {
        let scene_root_bytes = path_as_bytes(scene_root)?;
        let target_bytes = path_as_bytes(target)?;

        // The safety kernel's static bounds. We check them here to
        // convert a quiet "return 0" into a typed error, which is
        // friendlier for callers that want to handle the two failure
        // modes distinctly.
        const MAX_PATH: usize = 4096;
        const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
        if scene_root_bytes.len() > MAX_PATH
            || target_bytes.len() > MAX_PATH
            || payload.len() > MAX_PAYLOAD
        {
            return Err(SafeWriteError::BoundsExceeded);
        }

        // SAFETY: All three pointer-length pairs refer to borrowed Rust
        // slices that outlive the call. The Ada side copies their
        // contents into Ada-managed memory before invoking the
        // SPARK-verified core; it does not retain the pointers.
        let rc = unsafe {
            robofishy_safe_write(
                scene_root_bytes.as_ptr() as *const c_void,
                scene_root_bytes.len() as c_ulong,
                target_bytes.as_ptr() as *const c_void,
                target_bytes.len() as c_ulong,
                payload.as_ptr() as *const c_void,
                payload.len() as c_ulong,
            )
        };

        if rc == 1 {
            Ok(())
        } else {
            Err(SafeWriteError::Rejected)
        }
    }
}

impl Drop for SafeIO {
    fn drop(&mut self) {
        // SAFETY: symmetric to `init`; called once per `SafeIO`.
        unsafe { safety_kernel_final() };
    }
}

/// Convert a `Path` to a borrowed byte slice.
///
/// On Unix we can go through `OsStrExt::as_bytes` directly. The Ada
/// side treats incoming bytes as opaque — it does not interpret them
/// as UTF-8 — so this zero-copy conversion is lossless.
#[cfg(unix)]
fn path_as_bytes(path: &Path) -> Result<&[u8], SafeWriteError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn path_as_bytes(_path: &Path) -> Result<&[u8], SafeWriteError> {
    // v0 targets Linux only (the scene root lives on /mnt/eclipse).
    // Windows support would need wide-char conversion here.
    Err(SafeWriteError::PathNotRepresentable)
}
