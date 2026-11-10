# Shiva

Lightweight threat isolation for Linux, built on [Landlock](https://docs.kernel.org/userspace-api/landlock.html).

Shiva runs a suspicious program inside a kernel-enforced cage and tells you what
happened. No virtual machine, no container image, no root: the cage is set up by
an ordinary process in milliseconds.

> **Status: early development.** Shiva is a learning project and is not ready
> to analyze real malware. See [Safety](#safety) before running anything you
> don't trust.

## How it works

1. Shiva checks which Landlock version the kernel supports, and refuses to run
   if the kernel cannot enforce the full cage (unless you allow it).
2. Shiva finds the program the same way the shell does, through `$PATH`.
3. Shiva forks. The parent stays outside the cage.
4. The child creates a Landlock ruleset that denies filesystem access by
   default, then allows only what a program needs to start: the target binary,
   system libraries under `/usr`, the loader cache and `/dev/null`.
5. The child restricts itself, adds a seccomp filter for what Landlock cannot
   cover (see below), and `exec`s the target with a cleaned environment. The
   target inherits the cage and can never remove it.
6. The parent waits and reports how the target ended. When the target ends,
   times out, or Shiva itself is interrupted (Ctrl-C, `kill`), every process
   in the cage is killed, including ones that tried to detach with `setsid`
   or a double fork. Nothing caged outlives Shiva.

Anything the target tries outside its allowed paths, such as reading `~/.ssh`,
`/etc` or your home directory, is denied by the kernel.

Landlock alone leaves some doors open, so Shiva also:

- **Blocks UNIX sockets** (`socket(AF_UNIX)`). Landlock does not restrict
  connecting to a named socket, and through the D-Bus session bus a caged
  program could ask systemd to run any command outside the cage
  (`systemd-run --user ...`), or use your SSH keys through `ssh-agent`.
- **Blocks io_uring**, which could otherwise open sockets without `socket()`.
- **Detaches the target from your terminal** (new session, and `TIOCSTI` is
  blocked), so it cannot type commands into the shell that started Shiva.
- **Cleans the environment.** The target only gets `PATH`, `HOME`, `TERM`,
  `LANG`, `LC_ALL` and `TZ`. Tokens and secrets in your environment stay out.
- **Closes inherited file descriptors** other than stdin, stdout and stderr.

The seccomp filter only allows the native architecture: 32-bit programs are
killed when they make their first system call.

## Requirements

- Linux with Landlock enabled (`cat /sys/kernel/security/lsm` should list
  `landlock`)
- Landlock ABI 6 or newer for the full cage (kernel 6.12+). Older kernels
  work with `--allow-degraded`, with a weaker cage.
- Kernel headers 6.12 or newer to build
- GCC and Make
- x86-64, arm64 or riscv64 (for the seccomp filter)

## Build and install

```
make
sudo make install                  # installs to /usr/local/bin
```

To install for your user only, without root:

```
make install PREFIX=$HOME/.local   # installs to ~/.local/bin
```

`sudo make uninstall` removes it again. `make test` runs the regression tests.

## Usage

```
shiva -r [-t SECS] [-a] PROGRAM [ARGS...]

  -r, --run             run PROGRAM inside the cage
  -t, --timeout SECS    kill PROGRAM after SECS seconds (default 10)
  -a, --allow-degraded  run even if the kernel cannot enforce the full cage
  -h, --help            show help
```

Examples:

```
$ shiva -r ls /usr                # allowed: lists /usr
$ shiva -r ls /home               # denied: Permission denied
$ shiva -r cat /etc/hostname      # denied
$ shiva -r ./sample               # a program in the current folder
$ shiva -t 2 -r sleep 10          # killed after 2 seconds, exit 124
```

Programs given without a `/` are looked up in `$PATH`. The current folder is
only used when you write `./` explicitly.

### Exit codes

| Code | Meaning |
|---|---|
| target's own code | the target ran and exited normally |
| 128 + N | the target was killed by signal N, or Shiva was interrupted by signal N (130 for Ctrl-C) |
| 1 | Shiva could not set up the cage (for example, Landlock unavailable); the target did not run |
| 2 | usage error |
| 127 | program not found |
| 124 | the target ran longer than the timeout and was killed |

Shiva never runs the target uncaged. With `--allow-degraded` on an older
kernel, it prints a warning for each protection that is missing.

## Safety

- **The cage shares the host kernel.** Landlock cannot stop a kernel exploit.
  Shiva is meant as a fast first-pass triage tier, not a replacement for a VM.
- **Only test in a disposable VM** until the project matures.
- **Network restrictions are not complete yet.** TCP is blocked by Landlock
  (ABI 4+), but UDP and raw sockets are not, so a target could still send
  data out over UDP. See the roadmap.

## Roadmap

**v0.1: the cage** (current)
- [x] Command-line interface (`-r`, `-t`, `-h`)
- [x] Landlock ruleset with ABI detection
- [x] Default allow-list for system paths
- [x] Fork/exec supervisor that reports how the target ended
- [x] Refuse to run on kernels that cannot enforce the full cage
- [x] `--allow-degraded` to run with a weaker cage, with a warning
- [x] Resolve programs through `$PATH`
- [x] `make install` / `make uninstall`
- [x] Enforce `--timeout`
- [x] Kill everything left in the cage when the target ends
- [x] Block UNIX sockets, io_uring and terminal injection with seccomp
- [x] Clean environment and file descriptors for the target
- [ ] Scratch directory the target can write to

**v0.2: the report**
- [ ] Detect and report denied accesses (Landlock audit, kernel 6.15+)
- [ ] Honeytokens: fake credentials and keys planted as bait
- [ ] Verdict exit codes (clean, suspicious, inconclusive)
- [ ] JSON output (`--json`)
- [ ] Test suite with harmless "fake malware" programs (started: `make test`)

**v0.3: a stronger cage**
- [ ] seccomp syscall filtering
- [ ] Network isolation (Landlock TCP rules, network namespaces, sinkhole)
- [ ] Resource limits with cgroups
- [ ] User-configurable rules (`--allow-ro`, `--allow-rw`)
- [ ] Build with older kernel headers (fallback definitions)

**Later**
- [ ] Watchlist of suspicious files and behaviors
- [ ] Automatic interception of watched binaries (`shiva watch`)
- [ ] Escalation of dangerous samples to a microVM
- [ ] Agent layer that analyzes unclear cases and proposes detection rules

## Acknowledgements

The ABI compatibility handling follows the examples in the Linux kernel's
[Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).
