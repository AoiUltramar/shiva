/*
 * seccomp filter for the things Landlock cannot restrict (as of ABI 7):
 *
 *  - socket(AF_UNIX): connecting to a named UNIX socket is not covered by
 *    Landlock. Through the D-Bus session bus a caged program can ask
 *    systemd to start any command *outside* the cage (systemd-run --user),
 *    and through $SSH_AUTH_SOCK it can use the user's SSH keys.
 *  - io_uring_setup: io_uring can open sockets without calling socket(),
 *    which would bypass the rule above.
 *  - ioctl(TIOCSTI / TIOCLINUX): pushing keystrokes into the terminal the
 *    target inherited, i.e. typing commands into the user's shell.
 *  - new namespaces (unshare, clone with CLONE_NEW*, clone3, setns): in a
 *    user namespace of its own a program is "root" over network, mount and
 *    other namespaces it creates, which opens up a lot of kernel code that
 *    an ordinary user cannot reach. Shiva sets up the one namespace the
 *    cage needs before this filter is installed (see mntns.c).
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "sfilter.h"

#if defined(__x86_64__)
# define SHIVA_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define SHIVA_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && __riscv_xlen == 64
# define SHIVA_AUDIT_ARCH AUDIT_ARCH_RISCV64
#else
# error "shiva: the seccomp filter has not been ported to this architecture"
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
# error "shiva: the seccomp filter assumes a little-endian CPU"
#endif

/* low 32 bits of syscall argument N (little-endian) */
#define ARG_LO(n) (offsetof(struct seccomp_data, args) + (n) * sizeof(__u64))

#define LOAD(off)       BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define RET(val)        BPF_STMT(BPF_RET | BPF_K, (val))
#define DENY(err)       RET(SECCOMP_RET_ERRNO | ((err) & SECCOMP_RET_DATA))
/* if A == k fall through to the next instruction, else skip it */
#define IF_EQ(k)        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), 0, 1)
/* if A == k skip the next n instructions, else fall through */
#define IF_EQ_SKIP(k, n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (n), 0)
/* if A has any of the bits fall through to the next instruction, else skip it */
#define IF_ANY_BIT(bits) BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, (bits), 0, 1)

/* CLONE_NEWTIME is 0x80: never set in a valid clone() exit signal */
#define NEW_NAMESPACE (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | \
		       CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | \
		       CLONE_NEWCGROUP | CLONE_NEWTIME)

int shiva_seccomp_install(void)
{
	struct sock_filter filter[] = {
		/* a syscall from another ABI (e.g. 32-bit) would bypass the numbers below */
		LOAD(offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SHIVA_AUDIT_ARCH, 1, 0),
		RET(SECCOMP_RET_KILL_PROCESS),

		LOAD(offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
		/* x32 syscalls report the same arch: refuse them */
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1),
		RET(SECCOMP_RET_KILL_PROCESS),
#endif
		/* ENOSYS makes programs fall back to normal I/O */
		IF_EQ(__NR_io_uring_setup),
		DENY(ENOSYS),

		/* clone3 hides its flags in a struct: ENOSYS makes libc use clone */
		IF_EQ(__NR_clone3),
		DENY(ENOSYS),
		IF_EQ(__NR_setns),
		DENY(EPERM),

		/*
		 * The rest depends on an argument: jump to the block that
		 * checks it. The numbers count the instructions in between,
		 * so they change when a block above the target grows.
		 */
		IF_EQ_SKIP(__NR_socket,  4),
		IF_EQ_SKIP(__NR_ioctl,   7),
		IF_EQ_SKIP(__NR_unshare, 12),
		IF_EQ_SKIP(__NR_clone,   11),
		RET(SECCOMP_RET_ALLOW),

		/* socket(domain, ...) */
		LOAD(ARG_LO(0)),
		IF_EQ(AF_UNIX),
		DENY(EACCES),
		RET(SECCOMP_RET_ALLOW),

		/* ioctl(fd, request, ...) */
		LOAD(ARG_LO(1)),
		IF_EQ(TIOCSTI),
		DENY(EPERM),
		IF_EQ(TIOCLINUX),
		DENY(EPERM),
		RET(SECCOMP_RET_ALLOW),

		/* unshare(flags) and clone(flags, ...): flags come first on all three architectures */
		LOAD(ARG_LO(0)),
		IF_ANY_BIT(NEW_NAMESPACE),
		DENY(EPERM),
		RET(SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)) {
		perror("shiva: seccomp");
		return -1;
	}
	return 0;
}
