--  SPDX-License-Identifier: PMPL-1.0-or-later
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy_IO — unchecked filesystem I/O primitives.
--
--  The spec is SPARK-visible (no SPARK_Mode aspect, defaults to On in a
--  SPARK context) so SPARK-mode callers can call Write_Bytes and have
--  calls verified against its contract. The *body* is hidden behind
--  SPARK_Mode => Off so the Stream_IO implementation does not have to
--  be in the SPARK subset.
--
--  Nothing in this package should ever be called from Rust or Zig
--  directly. The only sanctioned route is from
--  Robofishy_Write_Guard.Safe_Write, which has already proved that the
--  target path is inside the scene root before calling Write_Bytes.

package Robofishy_IO with SPARK_Mode => On is

   --  Write Payload to Target. On return, Success is True if and only if
   --  the file was created and the entire payload was written without
   --  exception. No path validation is performed here; that is the
   --  caller's responsibility and is enforced by Safe_Write.
   procedure Write_Bytes
     (Target  : String;
      Payload : String;
      Success : out Boolean)
   with Global => null;

end Robofishy_IO;
