
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "llock.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Rights that apply to files */
#define LL_FILE_R   (LANDLOCK_ACCESS_FS_READ_FILE)
#define LL_FILE_RX  (LANDLOCK_ACCESS_FS_EXECUTE | \
		     LANDLOCK_ACCESS_FS_READ_FILE)
#define LL_FILE_RW  (LANDLOCK_ACCESS_FS_READ_FILE | \
		     LANDLOCK_ACCESS_FS_WRITE_FILE)

/* Rights that apply to directories (and everything beneath them) */
#define LL_DIR_RO   (LANDLOCK_ACCESS_FS_READ_FILE | \
		     LANDLOCK_ACCESS_FS_READ_DIR)
#define LL_DIR_RX   (LL_DIR_RO | LANDLOCK_ACCESS_FS_EXECUTE)
#define LL_DIR_RW   (LL_DIR_RO | \
		     LANDLOCK_ACCESS_FS_WRITE_FILE | \
		     LANDLOCK_ACCESS_FS_REMOVE_FILE | \
		     LANDLOCK_ACCESS_FS_REMOVE_DIR | \
		     LANDLOCK_ACCESS_FS_MAKE_REG | \
		     LANDLOCK_ACCESS_FS_MAKE_DIR | \
		     LANDLOCK_ACCESS_FS_TRUNCATE)

static int check_abi(void){
	return syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

//THose are the basic permissions the program should have to execute properly
//In the future, the user should be able to customize which parameters to restrict and which to allow
static int add_path_rule(int ruleset_fd, const char *path, uint64_t access)
{
	struct landlock_path_beneath_attr rule = {
		.allowed_access = access,
		.parent_fd = open(path, O_PATH | O_CLOEXEC),
	};
	int ret;

	if (rule.parent_fd < 0) {
		perror(path);
		return -1;
	}
	ret = syscall(SYS_landlock_add_rule, ruleset_fd,
		      LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
	if (ret)
		perror(path);
	close(rule.parent_fd);
	return ret;
}

static int shiva_llock_allow(int ruleset_fd, const char *shiva_target){
	//This will be changed at will in the future
	static const struct path_rule default_rules[] = {
		{ "/usr",             LL_DIR_RX  },
		{ "/bin",             LL_DIR_RX  },
		{ "/lib",             LL_DIR_RX  },
		{ "/lib64",           LL_DIR_RX  },
		{ "/etc/ld.so.cache", LL_FILE_R  },
		{ "/dev/null",        LL_FILE_RW },
	};

	for (size_t i = 0; i < ARRAY_SIZE(default_rules); i++){
		add_path_rule(ruleset_fd, default_rules[i].path,default_rules[i].access);
	}/* optional: warn only */

	if (add_path_rule(ruleset_fd, shiva_target, LL_FILE_RX)){
		return 1;                                 
	}

	return 0;

}

int shiva_llock_target(const char *shiva_target){

	struct landlock_ruleset_attr attr = {
        .handled_access_fs =
        	LANDLOCK_ACCESS_FS_EXECUTE |
        	LANDLOCK_ACCESS_FS_WRITE_FILE |
        	LANDLOCK_ACCESS_FS_READ_FILE |
        	LANDLOCK_ACCESS_FS_READ_DIR |
       		LANDLOCK_ACCESS_FS_REMOVE_DIR |
        	LANDLOCK_ACCESS_FS_REMOVE_FILE |
        	LANDLOCK_ACCESS_FS_MAKE_CHAR |
       		LANDLOCK_ACCESS_FS_MAKE_DIR |
        	LANDLOCK_ACCESS_FS_MAKE_REG |
        	LANDLOCK_ACCESS_FS_MAKE_SOCK |
        	LANDLOCK_ACCESS_FS_MAKE_FIFO |
        	LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        	LANDLOCK_ACCESS_FS_MAKE_SYM |
        	LANDLOCK_ACCESS_FS_REFER |
        	LANDLOCK_ACCESS_FS_TRUNCATE |
        	LANDLOCK_ACCESS_FS_IOCTL_DEV,

        .handled_access_net =
                LANDLOCK_ACCESS_NET_BIND_TCP |
                LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .scoped =
                LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
                LANDLOCK_SCOPE_SIGNAL,
        };

	int abi = check_abi();

	if(abi < 1){
		fprintf(stderr, "Landlock is not available\n");
		return 1;
	}

	switch (abi) {
	case 1:
    	/* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
    		attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    		__attribute__((fallthrough));
	case 2:
    	/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
    		attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    		__attribute__((fallthrough));
	case 3:
    	/* Removes network support for ABI < 4 */
    		attr.handled_access_net &=
        	~(LANDLOCK_ACCESS_NET_BIND_TCP |
          	LANDLOCK_ACCESS_NET_CONNECT_TCP);
    		__attribute__((fallthrough));
	case 4:
    	/* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
    		attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
    		__attribute__((fallthrough));
	case 5:
    	/* Removes LANDLOCK_SCOPE_* for ABI < 6 */
    		attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
                             LANDLOCK_SCOPE_SIGNAL);
        }

	int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);

	if(ruleset_fd < 0){
		perror("landlock_create_ruleset");
		return 1;
	}

	shiva_llock_allow(ruleset_fd, shiva_target);

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0,0);
        syscall(SYS_landlock_restrict_self, ruleset_fd, 0);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return 1;
	}

	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0)) {
		perror("landlock_restrict_self");
		return 1;
	}

	close(ruleset_fd);

	fprintf(stderr, "All set as chained\n");
	return 0;
}


