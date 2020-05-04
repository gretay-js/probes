(** Memory map of a running process *)
exception Error of string

(* CR-someday gyorsh: provide as a separate little library or as part of a
   suitable colleciton of utilities. *)

(** Partial information about a segment *)
type entry =
  { start : int64;  (** start address of the segment *)
    finish : int64;  (** size of the segment *)
    perm : string;  (** permissions of the segment, in format "wrxp" *)
    offset : int64
        (** offset into the object file where the section corresponding to
            this segment resides *)
  }

(** Partial information about an object file *)
type t =
  { text : entry;
    data : entry
  }

val read : pid:int -> filename:string -> t
(** [read pid filename] reads memory map of a running process from
    /proc/pid/maps and extracts information relavant to the object file
    [filename]. Requires permissions to read maps, such as calling this
    function from pid itself or a process attached to pid using ptrace, and
    pid should be stopped (or memory map might be modified by the OS during
    reading). *)

val verbose : bool ref
(** Control debug printing. *)
