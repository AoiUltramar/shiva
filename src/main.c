#include "cli.h"
#include<unistd.h>
#include<getopt.h>



int main(int argc, char **argv){
	
	if(argc < 2){
		usage();
		return 2;
	}

	else{
		parser(argc, argv);
	}

	return 1;
}
