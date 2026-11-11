#ifndef SHIVA_FAKEHOME_H
#define SHIVA_FAKEHOME_H

/*
 * The fake home: a throwaway directory the target gets as $HOME. It is the
 * only place the target may write, and it is seeded with decoy credentials
 * so that a program that goes looking for secrets finds something, keeps
 * going, and shows what it is after.
 *
 * Everything here runs in the parent, outside the cage.
 */
struct shiva_home;

/* Create the directory, plant the decoys and start watching. NULL on error. */
struct shiva_home *shiva_home_create(void);

/* Absolute path of the fake home. */
const char *shiva_home_path(const struct shiva_home *h);

/*
 * Create an empty file at REL inside the home, with the directories leading
 * to it, as part of what is planted. Returns its absolute path (owned by H),
 * or NULL on error. mntns.c mounts the target on it.
 */
const char *shiva_home_add_file(struct shiva_home *h, const char *rel);

/* File descriptor to poll() for POLLIN, or -1 if watching is not possible. */
int shiva_home_fd(const struct shiva_home *h);

/* Read the pending events. Call when the descriptor is readable. */
void shiva_home_drain(struct shiva_home *h);

/*
 * Print what the target did in its home. Call once, after every caged
 * process is dead. Returns the number of findings.
 */
int shiva_home_report(struct shiva_home *h);

/* Delete the fake home and free H. Safe to call with NULL. */
void shiva_home_destroy(struct shiva_home *h);

#endif
