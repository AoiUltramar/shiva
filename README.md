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
5. The child restricts itself and `exec`s the target, which inherits the cage
   and can never remove it.
6. The parent waits and reports how the target ended.

Anything the target tries outside its allowed paths, such as reading `~/.ssh`,
`/etc` or your home directory, is denied by the kernel.

## Requirements

- Linux with Landlock enabled (`cat /sys/kernel/security/lsm` should list
  `landlock`)
- Landlock ABI 6 or newer for the full cage (kernel 6.12+). Older kernels
  work with `--allow-degraded`, with a weaker cage.
- Kernel headers 6.12 or newer to build
- GCC and Make

## Build and install

```
make
sudo make install                  # installs to /usr/local/bin
```

To install for your user only, without root:

```
make install PREFIX=$HOME/.local   # installs to ~/.local/bin
```

`sudo make uninstall` removes it again.

## Usage

```
shiva -r [-t SECS] [-a] PROGRAM [ARGS...]

  -r, --run             run PROGRAM inside the cage
  -t, --timeout SECS    timeout in seconds (default 10; not enforced yet)
  -a, --allow-degraded  run even if the kernel cannot enforce the full cage
  -h, --help            show help
```

Examples:

```
$ shiva -r ls /usr                # allowed: lists /usr
$ shiva -r ls /home               # denied: Permission denied
$ shiva -r cat /etc/hostname      # denied
$ shiva -r ./sample               # a program in the current folder
$ shiva -t 2 -r sleep 10          # timed out after 2 seconds, exit 124, after exactly 2 s.
```

Programs given without a `/` are looked up in `$PATH`. The current folder is
only used when you write `./` explicitly.

### Exit codes

| Code | Meaning |
|---|---|
| target's own code | the target ran and exited normally |
| 128 + N | the target was killed by signal N |
| 1 | Shiva could not set up the cage (for example, Landlock unavailable) |
| 2 | usage error |
| 127 | program not found |
| 124 | the target ran longer than the timeout and was killed |

Shiva never runs the target uncaged. With `--allow-degraded` on an older
kernel, it prints a warning for each protection that is missing.

## Safety

- **The cage shares the host kernel.** Landlock cannot stop a kernel exploit.
  Shiva is meant as a fast first-pass triage tier, not a replacement for a VM.
- **Only test in a disposable VM** until the project matures.
- **Network restrictions are not complete yet.** See the roadmap.

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
- [ ] Scratch directory the target can write to

**v0.2: the report**
- [ ] Detect and report denied accesses (Landlock audit, kernel 6.15+)
- [ ] Honeytokens: fake credentials and keys planted as bait
- [ ] Verdict exit codes (clean, suspicious, inconclusive)
- [ ] JSON output (`--json`)
- [ ] Test suite with harmless "fake malware" programs

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
