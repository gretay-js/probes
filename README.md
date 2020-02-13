# User-space statically-defined tracing probes for OCaml

Experimental

## Installation using OPAM

Requires special compler version, currently based off of janestreet
ocaml tag 4.09.0-1.

```
opam switch create fdo409 --empty
opam pin add ocaml-variants https://github.com/gretay-js/ocaml.git#probes-409
opam pin add ocaml-migrate-parsetree https://github.com/gretay-js/ocaml-migrate-parsetree.git#409
opam pin add probes https://github.com/gretay-js/probes.git
```
