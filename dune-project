(lang dune 2.0)
(formatting (enabled_for dune ocaml reason))
(name probes)
(version 0.0.1)

(license MIT)
(maintainers "Greta Yorsh <gyorsh@janestreet.com>")
(authors "Jane Street Group, LLC <opensource@janestreet.com>")
(source (github gretay-js/ocamlfdo))

(package
 (name probes-lib)
 (synopsis "USDT probes for OCaml: library")
 (description "
 User-space statically-defined tracing probes for OCaml.
Experimental.
Copyright (c) 2019 Jane Street Group LLC.
")
 (depends
  (ocaml (>= 4.09))
  (dune (>= 1.8))
 )
)

(package
 (name probes)
 (synopsis "USDT probes for OCaml: command line tool")
 (description "
 User-space statically-defined tracing probes for OCaml.
Experimental.
Copyright (c) 2019 Jane Street Group LLC.
")

 (depends
  (ocaml (>= 4.09))
  (dune (>= 1.8))
  dune-build-info
  probes-lib
  core
  ppx_jane
 )
)



(generate_opam_files true)
