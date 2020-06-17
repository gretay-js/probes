let emit_test prog =
  match Filename.chop_suffix_opt prog ~suffix:".ml" with
  | None -> failwith (Printf.sprintf "Unrecognized file format: %s" prog)
  | Some base ->
    let ocamlopt_flags =
      let f = base ^ ".ocamlopt_flags" in
      if Sys.file_exists f then
        Stdio.In_channel.read_lines f |> String.concat " "
        |> Printf.sprintf "\n (ocamlopt_flags (:standard %s))"
      else ""
    in
    let exit_codes =
      let f = base ^ ".exit_codes" in
      if Sys.file_exists f then
        Stdio.In_channel.read_lines f |> String.concat " "
      else
        "0"
    in
    Printf.printf
{|

(executable
 (name %s)%s
 (modules %s))

(rule
 (deps %s.exe)
 (action
   (with-outputs-to %s.output
   (with-accepted-exit-codes %s
     (run probes trace -prog %%{dep:%s.exe})))))

(rule
 (alias runtest)
 (action (diff %s.expected %s.output)))
|}
    base ocamlopt_flags base base base exit_codes base base base


(* if should_fail then
 *     Printf.sprintf {|(with-accepted-exit-codes 1
 *        (run %s))|}
 *       cmd_string *)

let () =
  Array.iteri (fun i file -> if i > 0 then emit_test file) Sys.argv
