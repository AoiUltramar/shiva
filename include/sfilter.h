#ifndef SHIVA_SFILTER_H
#define SHIVA_SFILTER_H

/*
 * Install the seccomp filter that closes the holes Landlock leaves open.
 * Requires PR_SET_NO_NEW_PRIVS (set by shiva_llock_target). Returns 0 on success.
 */
int shiva_seccomp_install(void);

#endif
