(executable
 (name test)
 (modules test))

(rule
 (action
   (with-outputs-to test.output
     (run %{dep:gen/test_attach.exe} %{dep:test.exe}))))

(rule
 (alias runtest)
 (action (diff test.expected test.output)))
