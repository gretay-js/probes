open Core
module P = Probes_lib

let info ~pid ~bpf =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t pid ~check_prog:false;
  Array.iter (P.get_probe_states t) ~f:(fun p ->
      printf "%s %s\n" p.name (if p.enabled then "enabled" else "disabled"));
  P.detach t

let actions = P.All P.Enable

let attach ~pid ~bpf =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t pid ~check_prog:false;
  P.update t ~actions;
  P.detach t;
  ()

let trace ~prog ~args ~bpf =
  let t = P.create ~prog ~bpf in
  P.start t ~prog ~args ~check_prog:false;
  P.update t ~actions;
  P.detach t;
  ()
