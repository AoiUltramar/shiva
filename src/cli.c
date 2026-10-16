#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "cli.h"


void parser(int argc, char **argv){

	int timeout = 10, opt;
	char *target = NULL;

	static const struct option longopts[] = {
		{"timeout", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{"run", required_argument, NULL, 'r'},
		{0}
	};

	while((opt = getopt_long(argc, argv, "+t:hr:", longopts, NULL)) != -1){
		switch(opt){
			case 't': timeout = atoi(optarg); break;
			case 'r': target = optarg; break;
			case 'h': usage(); break;
			default: usage(); break;
			
		}
	}

}

void usage(){
	fprintf(stderr, "usage: shiva run [--timeout SECS] [--json] -- PROGRAM [ARGS...]\n");
}


