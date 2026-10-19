#ifndef SHIVA_CLI_H
#define SHIVA_CLI_H

struct config{
	int shiva_timeout;
	int shiva_allow_degraded;
	char **target_argv;
};

void usage(void);
int parser(int argc, char **argv, struct config *shiva_config);

#endif
