#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>


#define __USE_GNU 1
#define __USE_BSD 1
/* Remember the effective and real UIDs. */

static uid_t euid, ruid;

int seteuid(uid_t uid);

/* Restore the effective UID to its original value. */

void uid_up (void)
{
  int status;

  status = seteuid (euid);
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid up to %d.\n", euid);
    exit (status);
  } else {
    fprintf (stderr, "Set uid up to %d.\n", euid);
  }
}


/* Set the effective UID to the real UID. */

void uid_down (void)
{
  int status;

  status = seteuid (ruid);
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid down to %d.\n", ruid);
    exit (status);
  } else {
    fprintf (stderr, "Set uid down to %d.\n", ruid);
  }
}

void uid_init (void)
{
  /* Remember the real and effective user IDs.  */
  ruid = getuid ();
  euid = geteuid ();
  fprintf (stdout, "ruid=%d,euid=%d\n", ruid, euid);
  uid_down ();
}
