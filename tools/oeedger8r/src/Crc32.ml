(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

(** This file implements the Cyclic Redundancy Check 32-bit (CRC-32)
    algorithm used in the ISO 3309 standard. The implemenation is based
    on the RFC 1952 section 8. *)

let crc_table_computed = ref 0;;

let table = Array.make 256 0;;

let crc32 (buf : string) =
  if !crc_table_computed = 0 then
    (** Initialize table. *)
    for n = 0 to 255 do
      let c = ref n in
      for k = 0 to 7 do
      if (!c land 1) = 1 then
        c := 0xedb88320 lxor (!c lsr 1)
      else
        c := !c lsr 1
      done;
      table.(n) <- !c
    done;
    crc_table_computed := 1;

  let crc = 0 in
  let c = ref (crc lxor 0xffffffff) in
  let len = String.length buf in
  for n = 0 to (len - 1) do
    let char = String.get buf n in
    let code = Char.code char in
    let index = (!c lxor code) land 0xff in
    c := table.(index) lxor (!c lsr 8)
  done;
  c := !c lxor 0xffffffff;
  !c;;
