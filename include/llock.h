#ifndef SHIVA_LLOCK_H
#define SHIVA_LLOCK_H
#include <stdint.h>
struct path_rule {
	const char *path;
	uint64_t access;
};

int shiva_llock_target(const char *shiva_target, int abi);
int shiva_llock_abi(int shiva_allow_degraded);

#endif
