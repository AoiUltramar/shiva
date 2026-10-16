#include "cli.h"
#include<unistd.h>
#include<getopt.h>
#include <stdlib.h>


int main(int argc, char **argv){
	
	if(argc < 2){
		usage();
		return 2;
	}

	else{
		struct config shiva_config = {.shiva_timeout = 10};
		parser(argc, argv, &shiva_config);
	}

	return 1;
}
