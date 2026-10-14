# Engineering decisions

## Keep the original kernel mechanisms visible

The original code already contained the important educational pieces. We keep
fork/exec, ptrace register access, single-step, INT3 byte patching, procfs
memory and Capstone. Responsibility extraction makes their preconditions visible;
it does not delegate process control to another debugger. Launch now SEIZEs a
socket-gated child to support reliable PTRACE_INTERRUPT for all-stop thread control.

## `/proc/PID/mem` instead of word-wise PEEK/POKE

The original byte-oriented patch implementation maps naturally onto pread/pwrite.
Every descriptor has RAII ownership and CLOEXEC, every offset/range is checked,
and all operations require a stopped child. Reads distinguish an exact requested
range from a valid short prefix for disassembly. Disassembly bounds its request
to the end of the current executable VMA before calling Capstone.

Writes first snapshot the full requested range. They retry EINTR and account for
partial writes. A later failure restores the already-written prefix; breakpoint
metadata is updated only after success. Rollback itself can fail (for example,
an externally killed tracee). That is a distinct `MemoryCorruption` error which
terminates the session. All managed tasks remain stopped during mutation; this does not provide atomic
transactions against unrelated processes sharing mappings or external writers.

## ELF virtual address, load bias and image base

ELF headers are validated as little-endian ELF64 x86-64 ET_EXEC/ET_DYN. Program and
section table ranges and arithmetic are checked before reads. ET_DYN describes
the ELF type, not whether a program uses a dynamic linker.

Runtime translation is `ELF virtual address + load bias`. Load bias is matched
from page-aligned PT_LOAD file offsets and virtual addresses against the actual
proc mappings, using file device/inode identity rather than pathname substrings.
ET_EXEC requires zero bias. `breakrva` retains the old user-facing notion of an
offset from the lowest loaded image page, so a non-PIE image starting at 0x400000
has bias 0 but image base 0x400000. These two values are intentionally distinct.

Symbols are cached from `.symtab` and `.dynsym`. Undefined imports, TLS, IFUNC and
non-code symbols are rejected for breakpoints. Data commands separately resolve
defined OBJECT/NOTYPE symbols; TLS remains unsupported. Ambiguous names require
an explicit address. There is no demangler, shared-library resolver or DWARF dependency.

## Stop reasons and scope

The kernel wait status is classified once by Tracee. Breakpoint identification
then combines that typed trap, siginfo code, installed state and RIP. Syscall
entry/exit uses GET_SYSCALL_INFO, never unconditional RIP−2 guesses. Each Linux TID has its own resume mode, syscall pair and pending signal.
The controller presents an all-stop single-process model, with shared software
breakpoints and per-task hardware registers. See [task debugging](task-debugging.md).
Fork-family tracing and job-control preservation remain outside the contract.

## Reproducibility over feature count

Batch mode drives the same command/controller path as interactive mode. Fixtures
verify actual outputs, exit codes and repeated RIP locations. ELF and memory
module checks supplement integration tests where deterministic malformed inputs
or injected I/O failures matter. Source commit `37c1e96` passed the actual
[native CI run](https://github.com/Mistbornk/SDB/actions/runs/38536434814): Debug,
Release, ASan/UBSan and the public Ubuntu Docker image, each with 11 CTest entries
and no scenario skips. The local TCG results retain their separate combined
single-step/watchpoint skip; see [validation records](testing.md).

The native Release runner also found an event-ordering defect missed by the
earlier local run: delayed terminal SIGINT produced a second prompt after
continue. A target that deliberately masks the signal made the failure
deterministic against the old binary. An expanded case also exposed correlation
being lost across a breakpoint and single-step while SIGINT remained masked.
Correlation now survives non-SIGINT stops, propagates to same-thread-group
clones, and is matched against the process group at delivery. Both before-fix
failures and the final passing results are preserved. This is why native
execution and explicit skipped-case reporting remain necessary even when an
emulated environment passes its matrix.

References: [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html),
[proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html),
[ELF program headers](https://gabi.xinuos.com/elf/07-pheader.html),
[ELF symbol tables](https://gabi.xinuos.com/elf/05-symtab.html).
