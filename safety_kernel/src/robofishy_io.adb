--  SPDX-License-Identifier: MPL-2.0
--  Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
--
--  Robofishy_IO body. The `with SPARK_Mode => Off` aspect applied to
--  the package body hides the entire implementation from SPARK proof
--  while the spec remains SPARK-visible — the canonical "trusted
--  contract" pattern.

with Ada.Streams;
with Ada.Streams.Stream_IO;

package body Robofishy_IO with SPARK_Mode => Off is

   procedure Write_Bytes
     (Target  : String;
      Payload : String;
      Success : out Boolean)
   is
      use Ada.Streams;
      use Ada.Streams.Stream_IO;
      File : File_Type;
   begin
      Create (File, Out_File, Target);
      declare
         Buffer : Stream_Element_Array (1 .. Payload'Length);
         for Buffer'Address use Payload'Address;
         pragma Import (Ada, Buffer);
      begin
         Write (File, Buffer);
      end;
      Close (File);
      Success := True;
   exception
      when others =>
         --  On any I/O failure the file may be partially written;
         --  Success => False tells the caller not to trust the target.
         Success := False;
   end Write_Bytes;

end Robofishy_IO;
