/*
 * User and mount namespace for the cage (see mntns.h).
 *
 * An unprivileged process may create a user namespace, and inside it a
 * mount namespace in which it is allowed to mount. That is all this uses:
 * the uid and gid are mapped to themselves, so the target sees the same
 * user as before, and it has no capabilities left after exec.
 *
 * sfilter.c stops the target from making namespaces of its own on top.
 */
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include "mntns.h"

static int write_file(const char *path, const char *fmt, ...)
{
	char buf[64];
	va_list ap;
	int fd, len, ok;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ok = write(fd, buf, len) == len;
	close(fd);
	return ok ? 0 : -1;
}

/*
 * Mount flags of the filesystem PATH is on. In a user namespace a remount
 * may add flags but has to repeat these, or the kernel refuses it.
 */
static unsigned long flags_to_keep(const char *path)
{
	struct statvfs st;
	unsigned long flags = 0;

	if (statvfs(path, &st))
		return 0;
	if (st.f_flag & ST_NOSUID)     flags |= MS_NOSUID;
	if (st.f_flag & ST_NODEV)      flags |= MS_NODEV;
	if (st.f_flag & ST_NOEXEC)     flags |= MS_NOEXEC;
	if (st.f_flag & ST_NOATIME)    flags |= MS_NOATIME;
	if (st.f_flag & ST_NODIRATIME) flags |= MS_NODIRATIME;
	if (st.f_flag & ST_RELATIME)   flags |= MS_RELATIME;
	return flags;
}

static int not_here(const char *what)
{
	fprintf(stderr, "shiva: note: %s: %s. The fake home stays at its own "
		"path, and paths into the real home are only denied\n",
		what, strerror(errno));
	return 1;
}

int shiva_ns_enter(const char *fake_home, const char *real_home,
		   const char *target, const char *target_in_fake)
{
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
		return not_here("user namespaces are not available");

	/*
	 * Until this is done we are "nobody" in the new namespace and do not
	 * own our files any more, so failing here is not something to carry
	 * on from. setgroups does not exist on kernels before 3.19.
	 */
	if ((write_file("/proc/self/setgroups", "deny") && errno != ENOENT) ||
	    write_file("/proc/self/uid_map", "%u %u 1", (unsigned)uid, (unsigned)uid) ||
	    write_file("/proc/self/gid_map", "%u %u 1", (unsigned)gid, (unsigned)gid)) {
		fprintf(stderr, "shiva: cannot map the user into the new "
			"namespace: %s\n", strerror(errno));
		return -1;
	}

	/* nothing we mount may show up outside the cage */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return not_here("cannot make the mounts private");

	if (target_in_fake) {
		if (mount(target, target_in_fake, NULL, MS_BIND, NULL))
			return not_here("cannot keep the target visible");
		/*
		 * The target now sits below the fake home, where it may write.
		 * It must not be able to rewrite its own file on disk.
		 */
		if (mount(NULL, target_in_fake, NULL,
			  MS_BIND | MS_REMOUNT | MS_RDONLY | flags_to_keep(target),
			  NULL)) {
			int saved = errno;

			umount2(target_in_fake, MNT_DETACH);
			errno = saved;
			return not_here("cannot make the target read-only");
		}
	}

	/* MS_REC brings the mount of the target along */
	if (mount(fake_home, real_home, NULL, MS_BIND | MS_REC, NULL)) {
		int saved = errno;

		if (target_in_fake)
			umount2(target_in_fake, MNT_DETACH);
		errno = saved;
		return not_here("cannot mount the fake home over the real one");
	}
	return 0;
}
