let bt n =
  Printexc.get_callstack 9999
  |> Printexc.raw_backtrace_to_string
  (* Inlining depends on the optimization settings such as flambda *)
  |> Str.global_replace (Str.regexp_string " (inlined)") ""
  |> Printf.printf "%d:\n%s" n

let () =
  let rec loop n =
    if n = 0 then
      [%probe "backtrace" (bt 0)]
    else begin
      loop (n - 1);
      bt n
    end
  in
  loop 10

