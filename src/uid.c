#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>


#define __USE_GNU 1
#define __USE_BSD 1
/* Remember the effective and real UIDs. */

static uid_t euid, ruid;


/* Restore the effective UID to its original value. */

void uid_up (void)
{
  int status;

  status = setuid (euid);
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid up to %d.\n", euid);
    exit (status);
  }
}


/* Set the effective UID to the real UID. */

void uid_down (void)
{
  int status;

  status = setuid (ruid);
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid down to %d.\n", ruid);
    exit (status);
  }
}

void uid_init (void)
{
  /* Remember the real and effective user IDs.  */
  ruid = getuid ();
  euid = geteuid ();
  uid_down ();
}
