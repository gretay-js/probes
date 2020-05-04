exception Error of string

let verbose = ref false

type entry =
  { start : int64;
    finish : int64;
    perm : string;
    offset : int64
  }

type t =
  { text : entry;
    data : entry
  }

let chop_suffix s ~suffix =
  let len = String.length s in
  let len_suffix = String.length suffix in
  let start_suffix = len - len_suffix in
  if len < len_suffix then None
  else
    let t = String.sub s start_suffix len_suffix in
    if !verbose then Printf.printf "%s\nname:%s\n" s t;
    if String.equal t suffix then (
      let res = String.sub s 0 start_suffix in
      if !verbose then Printf.printf "res:%s\n" res;
      Some res )
    else None

let read ~pid ~filename =
  let map = "/proc/" ^ string_of_int pid ^ "/maps" in
  let oc = open_in map in
  let text = ref None in
  let data = ref None in
  let parse line =
    let fail s =
      raise
        (Failure
           (Printf.sprintf "Unexpectedd format of %s:\n%s\nCannot parse %s\n"
              map line s))
    in
    let update p e =
      match !p with
      | None -> p := Some e
      | Some _ ->
          raise
            (Error
               (Printf.sprintf
                  "Unexpected format of %s: duplicate segment for %s\n%s\n"
                  map filename line))
    in
    (* parse lines in the format: start-end rwxp offset xx:yy fd name *)
    if !verbose then Printf.printf "[mmap] %s\n" line;
    match chop_suffix line ~suffix:filename with
    | None -> ()
    | Some s -> (
        match String.trim s |> String.split_on_char ' ' with
        | [range; perm; offset; _; _] -> (
            let to_int64 s =
              try Int64.of_string ("0x" ^ s) with _ -> fail s
            in
            match String.split_on_char '-' range with
            | [start; finish] -> (
                let entry =
                  { start = to_int64 start;
                    finish = to_int64 finish;
                    offset = to_int64 offset;
                    perm
                  }
                in
                if not (String.length perm = 4) then fail perm;
                match perm with
                | "r-xp" -> update text entry
                | "rw-p" -> update data entry
                | _ -> () )
            | _ -> fail range )
        | _ -> fail s )
  in
  ( try
      while true do
        parse (input_line oc)
      done
    with
  | End_of_file -> close_in oc
  | e ->
      close_in oc;
      raise e );
  match (!text, !data) with
  | Some text, Some data -> { text; data }
  | None, _ ->
      raise
        (Error
           (Printf.sprintf
              "Unexpected format of %s: missing executable segment start"
              map))
  | _, None ->
      raise
        (Error
           (Printf.sprintf
              "Unexpected format of %s: missing write segment start" map))
