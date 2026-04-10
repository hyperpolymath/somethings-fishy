--  SPDX-License-Identifier: PMPL-1.0-or-later
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy_Write_Guard body.
--
--  The actual file write lives in the sibling package Robofishy_IO,
--  which is entirely SPARK_Mode => Off because Ada.Streams.Stream_IO is
--  not in the SPARK subset. The safety argument is structural: the only
--  code path that reaches Robofishy_IO.Write_Bytes is the
--  Is_Inside-verified branch of Safe_Write, and the SPARK prover
--  discharges that path's correctness.

pragma SPARK_Mode (On);

with Robofishy_IO;

package body Robofishy_Write_Guard is

   --  A safe path prefix comparison that avoids the "prefix-confusion"
   --  attack described in the spec. Is_Inside is pure and provable.
   function Is_Inside
     (Prefix    : Path_String;
      Candidate : Path_String) return Boolean
   is
   begin
      if Candidate'Length < Prefix'Length then
         return False;
      end if;

      --  Byte-for-byte match of the prefix portion.
      for I in 0 .. Prefix'Length - 1 loop
         if Candidate (Candidate'First + I) /=
            Prefix (Prefix'First + I)
         then
            return False;
         end if;
      end loop;

      --  Equal-length case: Candidate = Prefix exactly.
      if Candidate'Length = Prefix'Length then
         return True;
      end if;

      --  Longer case: the next character must be a path separator. This
      --  is what rules out "/scene_roots_of_all_evil" passing for
      --  "/scene_root".
      return Candidate (Candidate'First + Prefix'Length) = '/';
   end Is_Inside;

   procedure Safe_Write
     (Scene_Root : Path_String;
      Target     : Path_String;
      Payload    : Payload_String;
      Success    : out Boolean)
   is
   begin
      --  The one and only decision point. If this check fails, no write
      --  is attempted and the caller receives Success => False.
      if not Is_Inside (Scene_Root, Target) then
         Success := False;
         return;
      end if;

      Robofishy_IO.Write_Bytes (Target, Payload, Success);
   end Safe_Write;

end Robofishy_Write_Guard;
