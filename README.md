# User-space statically-defined tracing probes for OCaml

Experimental

## Installation using OPAM

Requires special compler version, currently based off of janestreet
ocaml tag 4.09.0-4.

requires shexp v0.14-preview.122.11+261 or later

```
opam switch create probes-409js --empty
opam pin add ocaml-variants https://github.com/gretay-js/ocaml.git#probes-409-4
opam pin add ocaml-migrate-parsetree https://github.com/gretay-js/ocaml-migrate-parsetree.git#409
opam pin add shexp https://github.com/janestreet/shexp.git
opam pin add probes https://github.com/gretay-js/probes.git
```

##  Basic usage
```
dune build test/tracee/test.exe
probes trace -prog _build/default/test/tracee/test.exe && sleep 1 && pkill test.exe
```

Assuming that `test.exe` is running somewhere in the background:
```
probes attach -prog `pgrep test.exe` --enable-all
probes info -prog `pgrep test.exe`
probes attach -prog `pgrep test.exe` --disable fooia
probes info -prog `pgrep test.exe`
```
