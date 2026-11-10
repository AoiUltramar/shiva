#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "cli.h"

/* Longest timeout that still fits in poll()'s int milliseconds (about 24 days) */
#define SHIVA_TIMEOUT_MAX (INT_MAX / 1000)

static int parse_timeout(const char *arg, int *out)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno || end == arg || *end || val <= 0 || val > SHIVA_TIMEOUT_MAX)
		return -1;
	*out = (int)val;
	return 0;
}

int parser(int argc, char **argv, struct config *shiva_config){

	int opt;
	int run = 0;

	static const struct option longopts[] = {
		{"timeout", required_argument, NULL, 't'},
		{"allow-degraded", no_argument, NULL, 'a'},
		{"help",    no_argument,       NULL, 'h'},
		{"run",     no_argument,       NULL, 'r'},
		{0}
	};

	/* defaults */
	shiva_config->shiva_timeout = 10;
	shiva_config->shiva_allow_degraded = 0;
	shiva_config->target_argv = NULL;

	/* '+' stops at the first non-option, so the target's own flags are left alone */
	while((opt = getopt_long(argc, argv, "+t:ahr", longopts, NULL)) != -1){
		switch(opt){
			case 't':
				if (parse_timeout(optarg, &shiva_config->shiva_timeout)) {
					fprintf(stderr, "shiva: invalid timeout '%s' "
						"(whole seconds, 1 to %d)\n",
						optarg, SHIVA_TIMEOUT_MAX);
					return 2;
				}
				break;
			case 'a':
				shiva_config->shiva_allow_degraded = 1;
				break;
			case 'r':
				run = 1;
				break;
			case 'h':
				usage();
				exit(0);
			default:
				usage();
				return 2;
		}
	}

	if (!run) {
		fprintf(stderr, "shiva: no mode given (use -r)\n");
		usage();
		return 2;
	}

	if (optind >= argc) {
		fprintf(stderr, "shiva: no program to run\n");
		usage();
		return 2;
	}

	/* argv[argc] is NULL, so this is a ready-made list for execvp */
	shiva_config->target_argv = &argv[optind];

	return 0;
}

void usage(void){
	fprintf(stderr, "usage: shiva -r [-t SECS] [-a] PROGRAM [ARGS...]\n"
			"  -r, --run             run PROGRAM inside the cage\n"
			"  -t, --timeout SECS    kill PROGRAM after SECS seconds (default 10)\n"
			"  -a, --allow-degraded  run even if the kernel cannot enforce the full cage\n"
			"  -h, --help            show this help\n");
}
