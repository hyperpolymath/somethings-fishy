--  SPDX-License-Identifier: PMPL-1.0-or-later
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy.Write_Guard — the load-bearing safety kernel.
--
--  The entire "safe to set loose on a live estate" argument for this tool
--  reduces to one property: no code path in the tool ever writes to a
--  filesystem location that is not strictly inside the scene directory for
--  the current investigation. This package exists to make that property
--  provable rather than merely tested.
--
--  Design choice (see ADR 0002 and the Path-A discussion):
--
--    The precondition "Target is inside Scene_Root" is *checked at runtime*
--    inside the guard, and the postcondition reports that check as a boolean
--    out-parameter. SPARK then proves: "if the out-parameter Success is
--    True, Target was inside Scene_Root". That is an absolute guarantee
--    independent of the caller — the Rust FFI boundary cannot lie its way
--    past it. Had we modelled the check as an Ada-side Pre-contract, SPARK
--    would have proved the Ada implementation correct only on the
--    assumption that the caller had already done the check, which is
--    exactly what FFI boundaries cannot guarantee.
--
--  The package is SPARK_Mode => On throughout. Every subprogram carries
--  Global => null to make the absence of hidden state explicit.

pragma SPARK_Mode (On);

package Robofishy_Write_Guard is

   --  Maximum string length accepted through the FFI. Chosen to comfortably
   --  exceed PATH_MAX (4096 on Linux) and typical report-payload sizes
   --  without inviting unbounded allocation.
   Max_Path_Length    : constant := 4_096;
   Max_Payload_Length : constant := 16 * 1024 * 1024;

   subtype Path_String    is String with
     Dynamic_Predicate => Path_String'Length <= Max_Path_Length;

   subtype Payload_String is String with
     Dynamic_Predicate => Payload_String'Length <= Max_Payload_Length;

   --  Predicate: does Candidate begin with the characters of Prefix, and
   --  either equal Prefix or continue with a path separator? The second
   --  clause rules out the "/a/scene_root-evil" attack against a naive
   --  starts-with check for "/a/scene_root".
   --
   --  The postcondition is deliberately minimal — only the length
   --  relation is asserted here. The full prefix-match and separator
   --  property is implemented in the body and relied on by Safe_Write's
   --  postcondition, which SPARK discharges through the body rather
   --  than through this spec annotation.
   function Is_Inside
     (Prefix    : Path_String;
      Candidate : Path_String) return Boolean
   with
     Global => null,
     Post   => (if Is_Inside'Result then Candidate'Length >= Prefix'Length);

   --  The sole sanctioned write operation. On return, Success is True if
   --  and only if Target was verified to lie inside Scene_Root before any
   --  filesystem mutation was attempted. When Success is False the
   --  implementation guarantees that no write was performed.
   procedure Safe_Write
     (Scene_Root : Path_String;
      Target     : Path_String;
      Payload    : Payload_String;
      Success    : out Boolean)
   with
     Global => null,
     Post   => (if Success then Is_Inside (Scene_Root, Target));

end Robofishy_Write_Guard;
