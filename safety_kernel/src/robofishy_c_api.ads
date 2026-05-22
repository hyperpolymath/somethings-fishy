--  SPDX-License-Identifier: MPL-2.0
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy_C_API — C-ABI export surface for the safety kernel.
--
--  Exposes Robofishy_Write_Guard.Safe_Write as a plain C function with
--  (char*, size_t) pointer-length pairs in place of Ada Strings, so Rust
--  (and any other C-FFI caller) can reach the proved write-path guard.
--
--  Return convention: the exported function returns 1 on success and 0
--  on any failure (bounds violation, path-outside-scene-root rejection,
--  or Stream_IO error). Callers must treat a non-1 return as "the file
--  may or may not exist; the target path is untrusted".
--
--  This package is the FFI boundary and is therefore entirely
--  SPARK_Mode => Off — the pointer arithmetic needed to translate C
--  strings into Ada Strings is outside the SPARK subset. The safety
--  argument is unchanged: this package is trusted glue, and the moment
--  it hands control to Safe_Write the proof obligations take over.

with Interfaces.C;
with System;

package Robofishy_C_API with SPARK_Mode => Off is

   function Safe_Write
     (Scene_Root_Ptr : System.Address;
      Scene_Root_Len : Interfaces.C.size_t;
      Target_Ptr     : System.Address;
      Target_Len     : Interfaces.C.size_t;
      Payload_Ptr    : System.Address;
      Payload_Len    : Interfaces.C.size_t) return Interfaces.C.int
   with
     Export        => True,
     Convention    => C,
     External_Name => "robofishy_safe_write";

end Robofishy_C_API;
