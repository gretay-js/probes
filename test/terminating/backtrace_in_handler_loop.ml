let bt n =
  Printf.printf "%d:\n" n;
  Printexc.print_raw_backtrace stdout (Printexc.get_callstack 9999)

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

