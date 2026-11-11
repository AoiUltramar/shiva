#ifndef SHIVA_LLOCK_H
#define SHIVA_LLOCK_H
#include <stdint.h>
struct path_rule {
	const char *path;
	uint64_t access;
};

/*
 * Cage the calling process. SHIVA_HOME is the one directory the target may
 * write to (see fakehome.h), or NULL for none.
 */
int shiva_llock_target(const char *shiva_target, const char *shiva_home, int abi);
int shiva_llock_abi(int shiva_allow_degraded);

#endif
