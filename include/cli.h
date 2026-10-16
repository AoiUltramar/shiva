#ifndef SHIVA_CLI_H
#define SHIVA_CLI_H

struct config{
	int shiva_timeout;
	char * shiva_target;
};

void usage(void);
int parser(int argc, char **argv, struct config *shiva_config);

#endif
