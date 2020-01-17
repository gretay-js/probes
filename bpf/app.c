#include <stdio.h>
#include <unistd.h>
#include <sys/sdt.h>

int foo (int x, int y) {
  DTRACE_PROBE2(app, foo, x, y);
  return (x + y);
}

int main() {
  const int N = 20;
  DTRACE_PROBE1(app, begin, N);
  for(int i=0; i<N; ++i) {
    printf("%d\n", i);
    DTRACE_PROBE1(app, loop, i);
  }
  foo (17,33);
  return 0;
}
