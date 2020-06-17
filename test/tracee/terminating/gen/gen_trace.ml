let emit_test prog =
  match Filename.chop_suffix_opt prog ~suffix:".ml" with
  | None -> failwith (Printf.sprintf "Unrecognized file format: %s" prog)
  | Some base ->

    let ocamlopt_flags =
      let f = base ^ ".ocamlopt_flags" in
      if Sys.file_exists f then
        Stdio.In_channel.read_lines f |> String.concat " "
      else ""
    in
    Printf.printf
{|

(executable
 (name %s)
 (ocamlopt_flags (:standard %s))
 (modules %s))

(rule
 (deps %s.exe)
 (action
   (with-outputs-to %s.output
     (run %%{bin:probes.exe} trace -prog %%{dep:%s.exe}))))

(rule
 (alias runtest)
 (action (diff %s.expected %s.output)))
|}
    base ocamlopt_flags base base base base base base

let () =
  Array.iteri (fun i file -> if i > 0 then emit_test file) Sys.argv
