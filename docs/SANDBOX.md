# Sandbox

Agent code runs through `core/kernel/sandbox`: `BwrapSandbox.execute_python`
runs a Python program in bubblewrap with a seccomp filter, and returns its
output, exit code and an `error` that says whether the sandbox itself failed.
This page says what a run gets and what it does not. The boundary is
bubblewrap plus the seccomp filter; the Python import blocklist and the
renamed builtins are guards against accidents, not part of it.

## What a run gets

- New user, PID, network, IPC, UTS and mount namespaces, and a new session:
  no controlling terminal, so agent code cannot write to the caller's
  terminal, change its modes or push keystrokes into it. Standard input is
  `/dev/null`. Only standard input, output and error are open.
- Inside, the user is `nobody` (65534) with no capabilities and
  `no_new_privs` set.
- `/usr`, `/lib`, `/lib64`, `/bin` and `/sbin` read-only, and two files
  from `/etc` (`ld.so.cache`, `localtime`). Nothing else from the host,
  unless the caller binds a directory with `extra_ro_binds`.
- Writable places are fresh tmpfs mounts with a size: `/tmp` 64 MiB
  (`tmpfs_size`), `/home`, `/mnt`, `/root`, `/var`, `/run` and `/dev/shm`
  1 MiB each. `/dev` and the root are otherwise read-only. Nothing written survives the
  run.
- The environment holds `PATH` and `HOME=/tmp`, and nothing from the
  caller's.

The sizes need bubblewrap 0.7.0 or later, which added `--size`. An older
bubblewrap (Ubuntu 22.04, and so JetPack 6, ships 0.6.1) refuses any mount
with a size, so there the mounts are unsized: a run can fill them up to the
host's memory, though `tmpfs_size` still caps each file. The kernel logs a
warning and `get_capabilities()` reports `tmpfs_sized: false`. Whether
--size is taken is read from `bwrap --help`; if that cannot be read the
sizes stay, and an older bubblewrap then fails every run.

## The seccomp filter

`restricted` is the default; `strict` adds the network and process
creation; `""` runs without a filter. Any other `seccomp_level` raises
`ValueError` before the code runs.

`restricted` refuses with EPERM: `acct`, the keyrings (`add_key`, `keyctl`,
`request_key`), `bpf`, `init_module` and `delete_module`, `kcmp`, `kexec_load` and
`kexec_file_load`, `memfd_create`, `perf_event_open`, `pivot_root`, `process_vm_readv` and
`process_vm_writev`, `ptrace`, `reboot`, `setns`, `swapon` and `swapoff`,
`sysfs`, `userfaultfd`, `vhangup`, `io_uring`, `unshare`, and the mount
calls (`mount`, `umount2`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
`move_mount`, `open_tree`, `mount_setattr`). It refuses `clone` with any
namespace flag and answers `clone3`, whose flags a filter cannot read,
with ENOSYS, so the C library falls back to `clone`: threads, `fork` and
subprocesses work, a new namespace (where agent code would hold every
capability again) does not. `get_capabilities()` lists each profile.

Every filter first checks the system call ABI: a call through another one
kills the process, and an x32 call on x86_64 is refused. Syscall numbers
come from each architecture's own headers. On a machine with no table
(riscv64, 32-bit ARM) no filter is built and the code runs without one;
`get_capabilities()` reports `seccomp_enabled: false`.

A filter that cannot be installed stops the run before agent code starts.
The bootstrap reports through a private pipe it closes first, so the result
says `seccomp_not_installed` and agent code can neither fake that nor hide
it. A run that never reaches the bootstrap reports nothing, and says
`sandbox_not_started`.

## Limits

| Limit | Default | Set with |
|-------|---------|----------|
| Wall time; the whole run is killed after it | 30 s | `timeout` |
| Output kept, per stream; read while the code runs, the last part kept | 10,000 characters | `max_output` |
| Address space, per process | 1 GiB | `memory_limit` |
| Largest file written, and the size of `/tmp` | 64 MiB | `tmpfs_size` |
| Processes | 64 | `max_processes` |
| Open files, per process | 256 | `MAX_OPEN_FILES` |

A memfd would hold memory outside the address space limit and every sized
tmpfs, so `restricted` refuses it; pipes, which hold kernel memory too, are
bounded by the open files.

The memory and process limits are per process and per user. Linux does not
apply the process limit to root, and `nobody` inside the sandbox is the
kernel's own user outside it, so when the kernel runs as root the number of
processes is bounded by the timeout alone, and several processes together
can use more than one process's limit. A cgroup (`memory.max`, `pids.max`)
would bound the run as a whole; it is not used.

## Files bound in

`nobody` inside is the kernel's own user outside. A file in a directory
given to `extra_ro_binds` can be read by agent code whenever the kernel's
user could read it, whatever its mode says about `nobody`. Bind only what
agent code may read. Running the kernel under its own unprivileged account
would change this.

## Without bubblewrap

With air-gap mode on, or `NGARI_SANDBOX_REQUIRE_BWRAP=1`, agent code is
refused when bubblewrap is missing (`error` is `sandbox_unavailable`). With
both off, or `require_bwrap=False`, it runs in a plain subprocess: the same
filter, limits, new session and empty standard input, from a private
working directory with `python -I`, so nothing on its import path is
writable by anyone else. It has no namespaces: the host's filesystem and
network are reachable as the kernel's user. A timeout kills every process
the run started, read from `/proc` by parent and by session; one that both
leaves the session and loses its parent is not found. Each is signalled
only while it is still the process `/proc` showed (same start time, through
a pidfd where the kernel has them), so a pid given to another process in the
meantime is spared. A process the code
leaves running after it exits on its own is not stopped.

## The result

`error` is empty for a run that ended on its own, whatever its exit code.
Otherwise:

| `error` | Meaning |
|---------|---------|
| `timeout:<N>s` | The run took longer than the timeout and was killed |
| `sandbox_unavailable` | bubblewrap is required and missing; the code was not run |
| `seccomp_not_installed` | A filter was asked for and not installed; the code was not run |
| `sandbox_not_started` | A filter was asked for and the run stopped before installing it (bubblewrap or Python could not start); the code was not run, and `stderr` says why |
| anything else | The sandbox could not start the run; the text says why |

Output that is not UTF-8 is kept, with replacement characters.
