#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cli.h"
#include "llock.h"
#include "resolve.h"
#include "sfilter.h"

/* What the child writes to the status pipe if it fails before exec */
#define SETUP_FAILED_CAGE 'c'
#define SETUP_FAILED_EXEC 'e'

/*
 * The only environment variables the target gets. Everything else (API
 * tokens, SSH_AUTH_SOCK, DBUS_SESSION_BUS_ADDRESS, ...) stays outside.
 */
static const char *const env_keep[] = {
	"PATH", "HOME", "TERM", "LANG", "LC_ALL", "TZ",
};
#define ENV_KEEP_N (sizeof(env_keep) / sizeof(env_keep[0]))

static char **clean_env(void)
{
	static char *envp[ENV_KEEP_N + 1];
	size_t n = 0;

	for (size_t i = 0; i < ENV_KEEP_N; i++) {
		const char *val = getenv(env_keep[i]);

		if (!val && !strcmp(env_keep[i], "PATH"))
			val = "/usr/local/bin:/usr/bin:/bin";
		if (val && asprintf(&envp[n], "%s=%s", env_keep[i], val) >= 0)
			n++;
	}
	envp[n] = NULL;
	return envp;
}

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static _Noreturn void child_fail(int status_fd, char why, int code)
{
	ssize_t r = write(status_fd, &why, 1);

	(void)r;
	_exit(code);
}

/*
 * Kill every process the target left behind. Shiva is a child subreaper,
 * so whenever a caged process dies, its children become ours. Killing our
 * children round after round therefore reaches the whole tree, including
 * processes that called setsid() or double-forked to hide.
 * Returns how many processes were killed, or -1 if /proc could not be read.
 */
static int kill_leftovers(void)
{
	char path[64];
	int killed = 0;

	snprintf(path, sizeof(path), "/proc/self/task/%d/children", (int)getpid());

	for (;;) {
		pid_t pids[256];
		size_t n = 0;
		long p;
		FILE *f = fopen(path, "r");

		if (!f)
			return -1;
		while (n < sizeof(pids) / sizeof(pids[0]) && fscanf(f, "%ld", &p) == 1)
			pids[n++] = (pid_t)p;
		fclose(f);

		if (n == 0)
			return killed;

		for (size_t i = 0; i < n; i++)
			kill(pids[i], SIGKILL);
		for (size_t i = 0; i < n; i++) {
			int st;

			if (waitpid(pids[i], &st, 0) == pids[i] &&
			    WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
				killed++;
		}
	}
}

int main(int argc, char **argv){

	struct config shiva_config;
	int ret, status;
	int status_pipe[2];
	sigset_t stop_sigs, old_mask;
	pid_t pid;

	ret = parser(argc, argv, &shiva_config);
	if (ret)
		return ret;

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
	char **target_env = clean_env();

	/* orphans of the target are re-parented to us, see kill_leftovers() */
	if (prctl(PR_SET_CHILD_SUBREAPER, 1)) {
		perror("shiva: PR_SET_CHILD_SUBREAPER");
		return 1;
	}

	/*
	 * Ctrl-C, kill, closing the terminal: handle them in the poll loop so
	 * the target is never left running without its supervisor.
	 */
	sigemptyset(&stop_sigs);
	sigaddset(&stop_sigs, SIGINT);
	sigaddset(&stop_sigs, SIGTERM);
	sigaddset(&stop_sigs, SIGHUP);
	sigaddset(&stop_sigs, SIGQUIT);
	sigprocmask(SIG_BLOCK, &stop_sigs, &old_mask);
	int sigfd = signalfd(-1, &stop_sigs, SFD_CLOEXEC);
	if (sigfd < 0) {
		perror("shiva: signalfd");
		return 1;
	}

	/* closed by a successful exec, so EOF means the target is running */
	if (pipe2(status_pipe, O_CLOEXEC)) {
		perror("shiva: pipe");
		return 1;
	}

	fflush(stdout);
	fflush(stderr);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* child: cage itself, then become the target */
		close(status_pipe[0]);

		/*
		 * New session, no controlling terminal: the target cannot inject
		 * keystrokes (TIOCSTI) into the shell that started Shiva, and its
		 * process group is its own.
		 */
		setsid();

		if (shiva_llock_target(target_path, abi))
			child_fail(status_pipe[1], SETUP_FAILED_CAGE, 1);
		if (shiva_seccomp_install())
			child_fail(status_pipe[1], SETUP_FAILED_CAGE, 1);

		/* don't hand the target any file descriptor beyond stdio */
		if (close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)) {
			perror("shiva: close_range");
			child_fail(status_pipe[1], SETUP_FAILED_CAGE, 1);
		}
		sigprocmask(SIG_SETMASK, &old_mask, NULL);

		execve(target_path, shiva_config.target_argv, target_env);
		perror("execve");
		child_fail(status_pipe[1], SETUP_FAILED_EXEC, 127);
	}

	/* parent: stays outside the cage and waits */
	free(target_path);
	close(status_pipe[1]);

	char why;
	ssize_t n;
	do {
		n = read(status_pipe[0], &why, 1);
	} while (n < 0 && errno == EINTR);
	close(status_pipe[0]);

	if (n == 1) {
		/* the child already explained what failed */
		waitpid(pid, &status, 0);
		kill_leftovers();
		if (why == SETUP_FAILED_EXEC)
			return 127;
		fprintf(stderr, "shiva: could not set up the cage, target not run\n");
		return 1;
	}

	int childfd = pidfd_open(pid, 0);
	if(childfd < 0){
		perror("pidfd_open");
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		kill_leftovers();
		return 1;
	}

	enum { RUNNING, EXITED, TIMED_OUT, INTERRUPTED, FAILED } state = RUNNING;
	int stop_sig = 0;
	int64_t deadline = now_ms() + (int64_t)shiva_config.shiva_timeout * 1000;

	while (state == RUNNING) {
		int64_t left = deadline - now_ms();
		struct pollfd pfd[2] = {
			{ .fd = childfd, .events = POLLIN },
			{ .fd = sigfd,   .events = POLLIN },
		};

		if (left <= 0) {
			state = TIMED_OUT;
			break;
		}
		ret = poll(pfd, 2, left > INT_MAX ? INT_MAX : (int)left);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			state = FAILED;
		} else if (pfd[0].revents) {
			state = EXITED;
		} else if (pfd[1].revents) {
			struct signalfd_siginfo si;

			if (read(sigfd, &si, sizeof(si)) == sizeof(si))
				stop_sig = si.ssi_signo;
			state = INTERRUPTED;
		}
		/* ret == 0: the loop checks the deadline again */
	}
	close(childfd);

	if (state != EXITED)
		kill(pid, SIGKILL);
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		state = FAILED;
	}

	int leftovers = kill_leftovers();
	if (leftovers < 0) {
		/* no /proc/<pid>/task/<tid>/children: best effort, the target's session */
		kill(-pid, SIGKILL);
		while (waitpid(-1, NULL, WNOHANG) > 0)
			;
		fprintf(stderr, "shiva: warning: cannot list leftover processes, "
			"some may still be running\n");
	} else if (leftovers > 0) {
		fprintf(stderr, "shiva: killed %d process%s the target left running\n",
			leftovers, leftovers == 1 ? "" : "es");
	}

	switch (state) {
	case TIMED_OUT:
		fprintf(stderr, "shiva: target timed out after %d seconds\n",
			shiva_config.shiva_timeout);
		return 124;
	case INTERRUPTED:
		fprintf(stderr, "shiva: interrupted by signal %d, target killed\n",
			stop_sig);
		return 128 + stop_sig;
	case FAILED:
		return 1;
	default:
		break;
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
