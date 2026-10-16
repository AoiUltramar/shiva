#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "cli.h"


int parser(int argc, char **argv, struct config *shiva_config){

	int opt;

	static const struct option longopts[] = {
		{"timeout", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{"run", required_argument, NULL, 'r'},
		{0}
	};

	while((opt = getopt_long(argc, argv, "+t:hr:", longopts, NULL)) != -1){
		switch(opt){
			case 't': shiva_config->shiva_timeout = atoi(optarg); break;
			case 'r': shiva_config->shiva_target = optarg; break;
			case 'h': usage(); break;
			default: usage(); break;
			
		}
	}

	return 0;

}

void usage(){
	fprintf(stderr, "usage: shiva run [--timeout SECS] [--json] -- PROGRAM [ARGS...]\n");
}


