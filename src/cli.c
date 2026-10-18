#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "cli.h"

int parser(int argc, char **argv, struct config *shiva_config){

	int opt;
	int run = 0;

	static const struct option longopts[] = {
		{"timeout", required_argument, NULL, 't'},
		{"help",    no_argument,       NULL, 'h'},
		{"run",     no_argument,       NULL, 'r'},
		{0}
	};

	/* defaults */
	shiva_config->shiva_timeout = 10;
	shiva_config->target_argv = NULL;

	/* '+' stops at the first non-option, so the target's own flags are left alone */
	while((opt = getopt_long(argc, argv, "+t:hr", longopts, NULL)) != -1){
		switch(opt){
			case 't':
				shiva_config->shiva_timeout = atoi(optarg);
				if (shiva_config->shiva_timeout <= 0) {
					fprintf(stderr, "shiva: invalid timeout '%s'\n", optarg);
					return 2;
				}
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
	fprintf(stderr, "usage: shiva -r [-t SECS] PROGRAM [ARGS...]\n"
			"  -r, --run           run PROGRAM inside the cage\n"
			"  -t, --timeout SECS  kill PROGRAM after SECS seconds (default 10)\n"
			"  -h, --help          show this help\n");
}
