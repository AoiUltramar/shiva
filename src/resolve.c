#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "resolve.h"

/* A program is a regular file we are allowed to execute. */
static int is_program(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
	       access(path, X_OK) == 0;
}

char *shiva_resolve(const char *name)
{
	const char *path_env;
	char *dirs, *dir, *saveptr, *candidate;

	/* "./bin" or "/usr/bin/ls": used as given, like execvp does */
	if (strchr(name, '/'))
		return is_program(name) ? strdup(name) : NULL;

	path_env = getenv("PATH");
	if (!path_env || !*path_env)
		path_env = "/usr/local/bin:/usr/bin:/bin";

	/* strtok_r modifies the string, so work on a copy */
	dirs = strdup(path_env);
	if (!dirs)
		return NULL;

	for (dir = strtok_r(dirs, ":", &saveptr); dir;
	     dir = strtok_r(NULL, ":", &saveptr)) {
		/* "dir" + "/" + "name" + '\0' */
		candidate = malloc(strlen(dir) + strlen(name) + 2);
		if (!candidate)
			break;
		sprintf(candidate, "%s/%s", dir, name);

		if (is_program(candidate)) {
			free(dirs);
			return candidate;
		}
		free(candidate);
	}

	free(dirs);
	return NULL;
}
