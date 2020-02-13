(lang dune 1.10)
(using fmt 1.1)
(name probes)
(version 0.0.1)

(license MIT)
(maintainers "Greta Yorsh <gyorsh@janestreet.com>")
(authors "Jane Street Group, LLC <opensource@janestreet.com>")
(source (github gretay-js/ocamlfdo))

(package
 (name probes)
 (synopsis "USDT probes for OCaml")
 (description "
 User-space statically-defined tracing probes for OCaml.
Experimental.
Copyright (c) 2019 Jane Street Group LLC.
")

 (depends
  (ocaml (>= 4.09))
  (dune (>= 1.8))
  core
  ppx_jane
  shexp
 )
)

(generate_opam_files true)
