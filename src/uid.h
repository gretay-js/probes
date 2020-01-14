/* Restore the effective UID to its original value. */
void uid_up (void);

/* Set the effective UID to the real UID. */
void uid_down (void);

/* Remember the real and effective user IDs.  */
void uid_init (void);
