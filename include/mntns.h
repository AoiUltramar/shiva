#ifndef SHIVA_MNTNS_H
#define SHIVA_MNTNS_H

/*
 * Put the fake home where the real one is.
 *
 * Moves the calling process into a user and mount namespace of its own and
 * mounts FAKE_HOME over REAL_HOME there. From then on every path into the
 * home, also one written out in full like /home/you/.ssh/id_rsa, leads to
 * the decoys. The mounts exist only inside the cage: the rest of the system
 * keeps seeing the real home. No privilege is needed.
 *
 * If the target lives in the real home it would vanish together with it.
 * TARGET_IN_FAKE, when not NULL, is an empty file in the fake home at the
 * place where the target used to be: TARGET is mounted on it, read-only.
 *
 * Call before Landlock, which forbids mounting.
 *
 * Returns  0 when the fake home is in place,
 *          1 when that is not possible here: nothing the target can see was
 *            changed, and the caller carries on with the fake home at its
 *            own path,
 *         -1 when the process was left half set up and must not run the
 *            target.
 * A reason is printed for 1 and -1.
 */
int shiva_ns_enter(const char *fake_home, const char *real_home,
		   const char *target, const char *target_in_fake);

#endif
