--  SPDX-License-Identifier: PMPL-1.0-or-later
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy_C_API body — conversion glue between C pointer-length
--  pairs and the Ada Strings consumed by Safe_Write.
--
--  The conversion uses an Unchecked_Conversion from a C pointer-plus-
--  length pair to an Ada String. This is outside the SPARK subset and
--  therefore this whole package is SPARK_Mode => Off (declared on the
--  spec). Once Safe_Write is called, the proof obligations take over
--  and the "no write escapes scene root" property holds.

with Ada.Unchecked_Conversion;
with Interfaces.C;
with Robofishy_Write_Guard;

package body Robofishy_C_API is

   use Interfaces.C;
   use Robofishy_Write_Guard;

   --  Convert a raw C (ptr, len) into an Ada String. The caller must
   --  guarantee that the memory at Ptr is readable for at least Len
   --  bytes — that is a standard C-FFI precondition, not something we
   --  can check from here.
   function To_String
     (Ptr : System.Address;
      Len : size_t) return String
   is
      subtype Fixed_String is String (1 .. Natural (Len));
      type Fixed_String_Ptr is access all Fixed_String;
      function Convert is new Ada.Unchecked_Conversion
        (Source => System.Address, Target => Fixed_String_Ptr);
      P : constant Fixed_String_Ptr := Convert (Ptr);
   begin
      if Len = 0 or else P = null then
         return "";
      end if;
      return P.all;
   end To_String;

   function Safe_Write
     (Scene_Root_Ptr : System.Address;
      Scene_Root_Len : size_t;
      Target_Ptr     : System.Address;
      Target_Len     : size_t;
      Payload_Ptr    : System.Address;
      Payload_Len    : size_t) return int
   is
   begin
      --  Reject out-of-bounds input lengths before we even touch memory.
      --  Safe_Write's Path_String / Payload_String subtypes carry
      --  Dynamic_Predicates for their maximum lengths; we enforce those
      --  ourselves here so violations produce a clean "return 0" rather
      --  than a raised exception at the SPARK boundary.
      if Scene_Root_Len > size_t (Max_Path_Length)
         or else Target_Len > size_t (Max_Path_Length)
         or else Payload_Len > size_t (Max_Payload_Length)
      then
         return 0;
      end if;

      declare
         Scene_Root : constant String :=
           To_String (Scene_Root_Ptr, Scene_Root_Len);
         Target     : constant String :=
           To_String (Target_Ptr, Target_Len);
         Payload    : constant String :=
           To_String (Payload_Ptr, Payload_Len);
         Success    : Boolean;
      begin
         Safe_Write
           (Scene_Root => Scene_Root,
            Target     => Target,
            Payload    => Payload,
            Success    => Success);
         return (if Success then 1 else 0);
      exception
         when others =>
            return 0;
      end;
   end Safe_Write;

end Robofishy_C_API;
