#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cli.h"
#include "llock.h"

int main(int argc, char **argv){

	struct config shiva_config;
	int ret, status;
	pid_t pid;

	ret = parser(argc, argv, &shiva_config);
	if (ret)
		return ret;

	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* child: cage itself, then become the target */
		if (shiva_llock_target(shiva_config.target_argv[0]))
			_exit(1);
		execvp(shiva_config.target_argv[0], shiva_config.target_argv);
		perror("execvp");
		_exit(127);
	}

	/* parent: stays outside the cage and waits */
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status)) {
		fprintf(stderr, "shiva: target exited with status %d\n",
			WEXITSTATUS(status));
		return WEXITSTATUS(status);
	}
	if (WIFSIGNALED(status)) {
		fprintf(stderr, "shiva: target killed by signal %d\n",
			WTERMSIG(status));
		return 128 + WTERMSIG(status);
	}

	return 1;
}
