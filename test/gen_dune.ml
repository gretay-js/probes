(* CR-someday gyorsh:
   To build a simple t.ml test file in two ways,
   with different flags passed to ocamlopt,
   we generate (rule (copy t.ml t_no_probes.ml))
   to work around dune's error message
   "each module cannot appear in more than one "modules" field -
   it must belong to a single library or executable".
   This means duplicating all the rules that depend on it.
   It should be possible with context or env or profile but how?
   Copying may be the only way as the .expected files are different,
   depending on the flags.
*)
let emit_test m ~runner ~with_probes =
  let ocamlopt_flags =
    let f = m ^ ".ocamlopt_flags" in
    let extra_flags =
      List.concat
        [
          if Sys.file_exists f then Stdio.In_channel.read_lines f else [];
          if with_probes then [] else ["-no-probes"];
        ]
    in
    match extra_flags with
    | [] -> ""
    | _ -> Printf.sprintf "\n (ocamlopt_flags (:standard %s))"
             (String.concat " " extra_flags)
  in
  let base = if with_probes then m else m^"_no_probes" in
  let copy_rule =
    if with_probes then ""
    else Printf.sprintf "\n(rule (copy %s.ml %s.ml))\n" m base
  in
  Printf.printf
{|
;;;; Test %s.ml with%s probes
%s
(executable
 (name %s)%s
 (modules %s)
 (libraries str))

(rule
 (action
   (with-outputs-to %s.output
     (run %s %%{dep:%s.exe}))))

(rule
 (alias runtest)
 (action (diff %s.expected %s.output)))
|}
  m (if with_probes then "" else "out")
  copy_rule
  base ocamlopt_flags base base runner base base base

let () =
  let runner = Sys.argv.(1) in
  let progs = Array.sub Sys.argv 2 ((Array.length Sys.argv) - 2) in
  (* Sort to ensure that the output does not depend on the order
     in which the files are listed in the directory. *)
  Array.sort String.compare progs;
  Array.iter (fun file ->
    match Filename.chop_suffix_opt file ~suffix:".ml" with
    | None -> ()
    | Some m ->
      emit_test m ~runner ~with_probes:true;
      emit_test m ~runner ~with_probes:false)
    progs
