#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cli.h"
#include "llock.h"
#include "resolve.h"
#include <poll.h>
#include <sys/pidfd.h>

int main(int argc, char **argv){

	struct config shiva_config;
	int ret, status;
	pid_t pid;

	ret = parser(argc, argv, &shiva_config);
	if (ret)
		return ret;

	fflush(stdout);
	
	int abi = shiva_llock_abi(shiva_config.shiva_allow_degraded);
	if(abi < 0){
		return 1;
	}

	/* find the real file once, and use it for both the rule and the exec */
	char *target_path = shiva_resolve(shiva_config.target_argv[0]);
	if (!target_path) {
		fprintf(stderr, "shiva: %s: command not found\n",
			shiva_config.target_argv[0]);
		return 127;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* child: cage itself, then become the target */
		if (shiva_llock_target(target_path, abi))
			_exit(1);
		setpgid(0, 0);
		execv(target_path, shiva_config.target_argv);
		perror("execv");
		_exit(127);
	}

	/* parent: stays outside the cage and waits */
	free(target_path);

	/* own process group, so the timeout can kill everything the target starts */
	setpgid(pid, pid);
	int childfd = pidfd_open(pid, 0);
	if(childfd < 0){
		perror("pidfd_open");
		kill(-pid, SIGKILL);
		return 1;
	}

	struct pollfd pfd = {.fd = childfd, .events = POLLIN};

	/* shiva_timeout is in seconds, poll takes the timer using ms */
	ret = poll(&pfd, 1, shiva_config.shiva_timeout * 1000);
	
	close(childfd);

	/* the target timedout */
	if(ret == 0){
		kill(-pid, SIGKILL);
		waitpid(pid, &status, 0);
		fprintf(stderr, "shiva: target timed out after %d seconds\n", shiva_config.shiva_timeout);
		return 124;
	}
	/* Couldn't resolve poll */
	if(ret < 0){
		kill(-pid, SIGKILL);
		waitpid(pid, &status, 0);
		perror("poll");
		return 1;
	}

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
