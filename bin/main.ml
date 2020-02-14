module P = Probe_lib

let actions = All Enable

let attach ~pid ~bpf =
  let t = P.create ~p ~bpf in
  P.attach t ~pid;
  P.update t ~actions;
  P.detach t;
  ()

let trace ~prog ~args ~bpf =
  let t = P.create ~prog ~bpf in
  P.start t (prog :: args) ~check:false;
  P.update t ~actions;
  P.detach t;
  ()

let list ~prog =
  let t = P.create ~prog in
  P.get_probes t |> Array.map first

let list ~pid =
  let t = P.create ~prog in
  P.get_probes t |> Array.map first
