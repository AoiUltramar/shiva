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
