/*
 * The fake home (see fakehome.h).
 *
 * Reads are noticed with inotify, which needs no privilege. inotify does not
 * say which process touched a file, but everything that can reach this
 * directory is inside the cage, so that does not matter.
 *
 * Only the directories that hold decoys are watched, and only for reads.
 * Changes are not taken from inotify: once the target is dead, the directory
 * is compared with what was planted. That cannot miss an event, and the
 * target cannot make us use more watches by creating directories.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fakehome.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Limits for the list of what the target created. Executables and copies
 * of secrets have a limit of their own, so they cannot be pushed off the
 * list by creating a thousand empty files first.
 */
#define MAX_LISTED    32
#define MAX_DEPTH     16

#define WATCH_MASK (IN_OPEN | IN_ACCESS | IN_ONLYDIR | IN_DONT_FOLLOW)

#define SEEN_OPEN 1
#define SEEN_READ 2

#define ALNUM  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define BASE64 ALNUM "+/"

/* Fill OUT with N random characters from ALPHABET, and terminate it. */
static void rand_chars(char *out, size_t n, const char *alphabet)
{
	size_t len = strlen(alphabet);
	unsigned char byte;

	for (size_t i = 0; i < n; i++) {
		if (getrandom(&byte, 1, 0) != 1)
			byte = (unsigned char)rand();
		out[i] = alphabet[byte % len];
	}
	out[n] = '\0';
}

/*
 * The decoys. Every secret is random and made up again on each run, so a
 * decoy cannot be recognized by its content and never works anywhere.
 */
static void fill_ssh_key(FILE *f)
{
	/* what every unencrypted ed25519 key file starts with, then noise */
	char body[401] =
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"
		"AAAAMwAAAAtzc2gtZWQyNTUxOQAA";
	size_t have = strlen(body);

	rand_chars(body + have, sizeof(body) - 1 - have, BASE64);
	fputs("-----BEGIN OPENSSH PRIVATE KEY-----\n", f);
	for (size_t i = 0; i < sizeof(body) - 1; i += 70)
		fprintf(f, "%.70s\n", body + i);
	fputs("-----END OPENSSH PRIVATE KEY-----\n", f);
}

static void fill_aws(FILE *f)
{
	char id[17], secret[41];

	rand_chars(id, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
	rand_chars(secret, 40, BASE64);
	fprintf(f, "[default]\naws_access_key_id = AKIA%s\n"
		"aws_secret_access_key = %s\n", id, secret);
}

static void fill_npmrc(FILE *f)
{
	char token[37];

	rand_chars(token, 36, ALNUM);
	fprintf(f, "//registry.npmjs.org/:_authToken=npm_%s\n", token);
}

static void fill_git_credentials(FILE *f)
{
	char token[37];

	rand_chars(token, 36, ALNUM);
	fprintf(f, "https://dev:ghp_%s@github.com\n", token);
}

static void fill_history(FILE *f)
{
	fputs("cd projects\ngit pull\nmake\nssh build@10.0.3.12\n"
	      "aws s3 ls\nnpm publish\n", f);
}

static void fill_bashrc(FILE *f)
{
	fputs("# ~/.bashrc\ncase $- in *i*) ;; *) return ;; esac\n"
	      "HISTSIZE=1000\nalias ll='ls -l'\n", f);
}

static void fill_profile(FILE *f)
{
	fputs("# ~/.profile\nif [ -n \"$BASH_VERSION\" ] && [ -f \"$HOME/.bashrc\" ]; then\n"
	      "\t. \"$HOME/.bashrc\"\nfi\n", f);
}

/* Directories the fake home starts with. Parents come before children. */
static const char *const home_dirs[] = {
	".ssh", ".aws", ".config", ".cache", ".local", ".local/share", "tmp",
};

struct decoy {
	const char *path;
	const char *what;
	int secret;             /* nothing honest has a reason to open it */
	void (*fill)(FILE *f);
};

static const struct decoy decoys[] = {
	{ ".ssh/id_ed25519",  "SSH private key",       1, fill_ssh_key },
	{ ".aws/credentials", "AWS credentials",       1, fill_aws },
	{ ".npmrc",           "npm token",             1, fill_npmrc },
	{ ".git-credentials", "Git credentials",       1, fill_git_credentials },
	{ ".bash_history",    "shell history",         1, fill_history },
	/* shells read these on their own, so only a change means something */
	{ ".bashrc",          "runs in every new shell", 0, fill_bashrc },
	{ ".profile",         "runs at every login",     0, fill_profile },
};
#define N_DECOYS ARRAY_SIZE(decoys)

struct watch {
	int wd;
	const char *rel;        /* directory, relative to the home; "" is the home */
};

struct shiva_home {
	char *path;
	int dirfd;
	int ifd;
	struct watch watches[1 + ARRAY_SIZE(home_dirs)];
	size_t nwatches;
	int lost_events;        /* the kernel dropped events, or a watch failed */
	struct {
		char *content;
		size_t len;
		unsigned seen;
	} planted[N_DECOYS];
	/* what shiva_home_add_file() made: paths relative to the home */
	char **added;
	size_t nadded;
	char *added_file;
	int findings;
	/* used while listing what the target created */
	int listed[2];          /* [1] counts executables and copies of secrets */
	int not_listed;
};

/* "dir" + "/" + "name", or just "name" at the top. Caller frees. */
static char *join(const char *dir, const char *name)
{
	char *out;

	if (asprintf(&out, "%s%s%s", dir, *dir ? "/" : "", name) < 0)
		return NULL;
	return out;
}

static void add_watch(struct shiva_home *h, const char *rel)
{
	char *full = join(h->path, rel);
	int wd = full ? inotify_add_watch(h->ifd, full, WATCH_MASK) : -1;

	free(full);
	if (wd < 0) {
		h->lost_events = 1;
		return;
	}
	h->watches[h->nwatches].wd = wd;
	h->watches[h->nwatches].rel = rel;
	h->nwatches++;
}

static int plant(struct shiva_home *h, size_t i)
{
	const struct decoy *d = &decoys[i];
	FILE *mem = open_memstream(&h->planted[i].content, &h->planted[i].len);
	int fd, ok;

	if (!mem)
		return -1;
	d->fill(mem);
	if (fclose(mem))
		return -1;

	fd = openat(h->dirfd, d->path,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		    d->secret ? 0600 : 0644);
	if (fd < 0)
		return -1;
	ok = write(fd, h->planted[i].content, h->planted[i].len) ==
	     (ssize_t)h->planted[i].len;
	close(fd);
	return ok ? 0 : -1;
}

struct shiva_home *shiva_home_create(void)
{
	struct shiva_home *h = calloc(1, sizeof(*h));
	const char *tmp = getenv("TMPDIR");

	if (!h)
		return NULL;
	h->dirfd = h->ifd = -1;

	if (!tmp || tmp[0] != '/')
		tmp = "/tmp";
	if (asprintf(&h->path, "%s/shiva-XXXXXX", tmp) < 0) {
		h->path = NULL;
		goto err;
	}
	if (!mkdtemp(h->path)) {
		fprintf(stderr, "shiva: cannot create the fake home %s: %s\n",
			h->path, strerror(errno));
		free(h->path);
		h->path = NULL;
		goto err;
	}
	h->dirfd = open(h->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (h->dirfd < 0)
		goto err_msg;

	for (size_t i = 0; i < ARRAY_SIZE(home_dirs); i++)
		if (mkdirat(h->dirfd, home_dirs[i], 0700))
			goto err_msg;
	for (size_t i = 0; i < N_DECOYS; i++)
		if (plant(h, i))
			goto err_msg;

	/*
	 * Watch only now, so our own writes above are not reported. Without
	 * inotify the target still runs: changes are found by comparing, only
	 * reads go unnoticed.
	 */
	h->ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (h->ifd < 0) {
		fprintf(stderr, "shiva: warning: inotify: %s, reads of the decoy "
			"files will not be reported\n", strerror(errno));
	} else {
		add_watch(h, "");
		for (size_t i = 0; i < ARRAY_SIZE(home_dirs); i++)
			add_watch(h, home_dirs[i]);
	}
	return h;

err_msg:
	fprintf(stderr, "shiva: cannot set up the fake home %s: %s\n",
		h->path, strerror(errno));
err:
	shiva_home_destroy(h);
	return NULL;
}

static int remember(struct shiva_home *h, const char *rel, size_t len)
{
	char **grown = realloc(h->added, (h->nadded + 1) * sizeof(*grown));

	if (!grown)
		return -1;
	h->added = grown;
	h->added[h->nadded] = strndup(rel, len);
	if (!h->added[h->nadded])
		return -1;
	h->nadded++;
	return 0;
}

const char *shiva_home_add_file(struct shiva_home *h, const char *rel)
{
	int fd;

	if (h->added_file || !*rel)
		return NULL;

	/* "a/b/file": first the directories "a" and "a/b" */
	for (const char *slash = strchr(rel, '/'); slash; slash = strchr(slash + 1, '/')) {
		char *dir = strndup(rel, slash - rel);
		int failed = !dir || (mkdirat(h->dirfd, dir, 0700) && errno != EEXIST);

		free(dir);
		if (failed || remember(h, rel, slash - rel))
			return NULL;
	}
	fd = openat(h->dirfd, rel, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return NULL;
	close(fd);
	if (remember(h, rel, strlen(rel)))
		return NULL;
	h->added_file = join(h->path, rel);
	return h->added_file;
}

const char *shiva_home_path(const struct shiva_home *h)
{
	return h->path;
}

int shiva_home_fd(const struct shiva_home *h)
{
	return h->ifd;
}

static void handle_event(struct shiva_home *h, const struct inotify_event *ev)
{
	const char *dir = NULL;
	char *rel;

	if (ev->mask & IN_Q_OVERFLOW) {
		h->lost_events = 1;
		return;
	}
	if (!ev->len)
		return;         /* about a watched directory itself */

	for (size_t i = 0; i < h->nwatches; i++)
		if (h->watches[i].wd == ev->wd)
			dir = h->watches[i].rel;
	if (!dir)
		return;
	rel = join(dir, ev->name);
	if (!rel)
		return;

	for (size_t i = 0; i < N_DECOYS && !(ev->mask & IN_ISDIR); i++) {
		if (strcmp(rel, decoys[i].path))
			continue;
		if (ev->mask & IN_OPEN)
			h->planted[i].seen |= SEEN_OPEN;
		if (ev->mask & IN_ACCESS)
			h->planted[i].seen |= SEEN_READ;
	}
	free(rel);
}

void shiva_home_drain(struct shiva_home *h)
{
	char buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));
	ssize_t len;

	while (h->ifd >= 0) {
		len = read(h->ifd, buf, sizeof(buf));
		if (len < 0 && errno == EINTR)
			continue;
		if (len < 0 && errno == EAGAIN)
			return;
		if (len <= 0) {
			/* never spin on a broken descriptor */
			close(h->ifd);
			h->ifd = -1;
			h->lost_events = 1;
			return;
		}
		for (char *p = buf; p < buf + len; ) {
			const struct inotify_event *ev = (const struct inotify_event *)p;

			handle_event(h, ev);
			p += sizeof(*ev) + ev->len;
		}
	}
}

/*
 * Open a directory the target may have made unreadable or unwritable.
 * Only used once the target is dead, on a tree we are about to delete.
 */
static int open_subdir(int dirfd, const char *name)
{
	int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
	int fd = openat(dirfd, name, flags);

	if (fd < 0 && errno == EACCES && !fchmodat(dirfd, name, 0700, 0))
		fd = openat(dirfd, name, flags);
	if (fd >= 0)
		fchmod(fd, 0700);
	return fd;
}

static void finding(struct shiva_home *h, const char *verb, const char *path,
		    const char *note)
{
	/* a run with nothing to report prints nothing at all */
	if (!h->findings++)
		fprintf(stderr, "shiva: in its fake home, the target:\n");
	fprintf(stderr, "shiva:   %-8s ~/%s%s%s%s\n", verb, path,
		note ? " (" : "", note ? note : "", note ? ")" : "");
}

/* Returns 0 if the file REL holds exactly what decoy I was given, 1 if not, 2 if it is gone. */
static int compare(const struct shiva_home *h, const char *rel, size_t i)
{
	size_t len = h->planted[i].len, got = 0;
	char *buf;
	int fd, state = 1;
	ssize_t n;

	fd = openat(h->dirfd, rel, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT || errno == ENOTDIR ? 2 : 1;
	buf = malloc(len + 1);
	if (buf) {
		/* one byte more than we wrote, to notice an append */
		while ((n = read(fd, buf + got, len + 1 - got)) > 0)
			got += n;
		if (n == 0 && got == len && !memcmp(buf, h->planted[i].content, len))
			state = 0;
		free(buf);
	}
	close(fd);
	return state;
}

static int was_planted(const struct shiva_home *h, const char *rel)
{
	for (size_t i = 0; i < h->nadded; i++)
		if (!strcmp(rel, h->added[i]))
			return 1;
	for (size_t i = 0; i < ARRAY_SIZE(home_dirs); i++)
		if (!strcmp(rel, home_dirs[i]))
			return 1;
	for (size_t i = 0; i < N_DECOYS; i++)
		if (!strcmp(rel, decoys[i].path))
			return 1;
	return 0;
}

/* List what the target created under DIR. Takes ownership of FD. */
static void list_created(struct shiva_home *h, int fd, const char *dir, int depth)
{
	DIR *d = fdopendir(fd);
	struct dirent *e;

	if (!d) {
		close(fd);
		return;
	}
	while ((e = readdir(d))) {
		struct stat st;
		char *rel;
		int is_dir, is_new;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW))
			continue;
		rel = join(dir, e->d_name);
		if (!rel)
			continue;
		is_dir = S_ISDIR(st.st_mode);
		is_new = !was_planted(h, rel);

		if (is_new) {
			char copy_of[64];
			int exe = S_ISREG(st.st_mode) && (st.st_mode & 0111);
			const char *note =
				is_dir ? "directory" :
				!S_ISREG(st.st_mode) ? "not a regular file" :
				exe ? "executable" : NULL;

			/* a secret under a new name: copied, renamed or hard-linked */
			for (size_t i = 0; i < N_DECOYS && S_ISREG(st.st_mode); i++) {
				if (!decoys[i].secret ||
				    (size_t)st.st_size != h->planted[i].len ||
				    compare(h, rel, i))
					continue;
				snprintf(copy_of, sizeof(copy_of), "copy of ~/%s",
					 decoys[i].path);
				note = copy_of;
			}
			if (h->listed[exe || note == copy_of] == MAX_LISTED) {
				h->not_listed++;
			} else {
				h->listed[exe || note == copy_of]++;
				finding(h, "created", rel, note);
			}
		}
		if (is_dir && depth < MAX_DEPTH) {
			int sub = open_subdir(fd, e->d_name);

			if (sub >= 0)
				list_created(h, sub, rel, depth + 1);
		} else if (is_dir) {
			h->not_listed++;
		}
		free(rel);
	}
	closedir(d);
}

int shiva_home_report(struct shiva_home *h)
{
	int top;

	shiva_home_drain(h);
	/* from here on the opens are our own */
	if (h->ifd >= 0) {
		close(h->ifd);
		h->ifd = -1;
	}

	/* the target may have locked us out of what we planted */
	fchmod(h->dirfd, 0700);
	for (size_t i = 0; i < ARRAY_SIZE(home_dirs); i++) {
		/* may be gone, and then there is nothing to unlock */
		if (fchmodat(h->dirfd, home_dirs[i], 0700, 0))
			continue;
	}

	for (size_t i = 0; i < N_DECOYS; i++) {
		int state = compare(h, decoys[i].path, i);
		const char *verb = NULL;

		if (state == 2)
			verb = "removed";
		else if (state == 1)
			verb = "changed";
		else if (decoys[i].secret && (h->planted[i].seen & SEEN_READ))
			verb = "read";
		else if (decoys[i].secret && (h->planted[i].seen & SEEN_OPEN))
			verb = "opened";
		if (verb)
			finding(h, verb, decoys[i].path, decoys[i].what);
	}

	top = open_subdir(h->dirfd, ".");
	if (top >= 0)
		list_created(h, top, "", 0);
	if (h->not_listed)
		fprintf(stderr, "shiva:   ... and created more that is not listed\n");
	if (h->lost_events)
		fprintf(stderr, "shiva: warning: some events in the fake home were "
			"lost, reads of decoy files may be missing\n");
	return h->findings;
}

/*
 * Delete everything under PATH, then PATH. Not recursive: the target chose
 * how deep the tree is. Each round either removes an entry, or steps into
 * a directory that is not empty, or steps back out of one that now is.
 */
static int remove_tree(const char *path)
{
	int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
	int fd = open(path, flags);
	long depth = 0;

	if (fd < 0)
		return errno == ENOENT ? 0 : -1;
	fchmod(fd, 0700);

	while (fd >= 0) {
		DIR *d = fdopendir(fd);
		struct dirent *e;
		int next = -1;

		if (!d) {
			close(fd);
			return -1;
		}
		while (next < 0 && (e = readdir(d))) {
			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
				continue;
			if (!unlinkat(fd, e->d_name, 0) ||
			    !unlinkat(fd, e->d_name, AT_REMOVEDIR))
				continue;
			next = open_subdir(fd, e->d_name);
			if (next < 0) {
				/* neither removable nor a directory we can enter */
				closedir(d);
				return -1;
			}
			depth++;
		}
		if (next < 0 && depth > 0) {
			next = openat(fd, "..", flags);
			depth--;
		}
		closedir(d);
		fd = next;
	}
	return rmdir(path);
}

void shiva_home_destroy(struct shiva_home *h)
{
	if (!h)
		return;
	if (h->ifd >= 0)
		close(h->ifd);
	if (h->dirfd >= 0)
		close(h->dirfd);
	if (h->path && remove_tree(h->path))
		fprintf(stderr, "shiva: warning: could not delete the fake home %s\n",
			h->path);
	for (size_t i = 0; i < N_DECOYS; i++)
		free(h->planted[i].content);
	for (size_t i = 0; i < h->nadded; i++)
		free(h->added[i]);
	free(h->added);
	free(h->added_file);
	free(h->path);
	free(h);
}
