open Core
module P = Probes_lib

let info ~pid ~bpf =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t pid ~check_prog:false;
  Array.iter (P.get_probe_states t) ~f:(fun p ->
      printf "%s %s\n" p.name (if p.enabled then "enabled" else "disabled"));
  P.detach t

let attach_fast ~pid ~bpf ~enable =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach_and_set_all t pid ~enable;
  ()

let trace_fast ~prog ~args ~bpf =
  let t = P.create ~prog ~bpf in
  P.trace_all t ~prog ~args;
  ()

let trace = trace_fast

let attach = attach_fast
