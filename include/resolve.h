#ifndef SHIVA_RESOLVE_H
#define SHIVA_RESOLVE_H

/*
 * Find the file that would run for NAME, the way the shell does.
 * Returns a malloc'd path the caller must free, or NULL if not found.
 */
char *shiva_resolve(const char *name);

#endif
