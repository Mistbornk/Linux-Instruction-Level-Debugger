# Tasks, attachment and hardware watchpoints

## One address space, an all-stop controller

A Linux thread is a task with its own TID and ptrace state. SDB records each TID's
stop state, resume mode, pending application signal and syscall-entry number.
`pid()` is the thread-group ID; registers, `/proc/TID/mem` and maps use a live
selected task, including after the original leader calls `pthread_exit`.

Launch uses fork plus a CLOEXEC Unix socket gate (`MSG_NOSIGNAL` on the parent send). The parent applies `PTRACE_SEIZE` before
releasing the child to exec. `TRACECLONE`, `TRACEEXEC`, `TRACEEXIT` and
`TRACESYSGOOD` expose lifecycle events; `EXITKILL` is restricted to owned children.
An attached process is seized by enumerating `/proc/PID/task`, stopping tasks and
repeating until the enumerated set is stable. The kernel also reports clones
created by already-seized parents.

A visible stop triggers `PTRACE_INTERRUPT` on running peers, followed by
`waitpid(..., __WALL)` until all live tasks are stopped. Real peer events are
queued; they are not discarded as interrupts. A syscall stop may fulfill an
interrupt request without a separate `EVENT_STOP`. Synthetic interrupt stops are
consumed internally. Before another command mutates shared code, every queued
INT3 trap has its RIP corrected and every queued hardware hit has been reported.

`cont` and `syscall` resume all managed tasks. `si` runs only the selected task.
Breakpoint displacement also runs only one task: restore the original byte,
step it, reinsert INT3, then consider the next parked task. This closes the window
where a peer could run through the temporarily absent breakpoint.

Task exit does not imply process exit. Exit events let dying tasks finish rather
than holding an exit stop that prevents a nonleader exec or the final group exit.
An exec from a nonleader adopts the TGID and replaces every old task/image record.
If exec/terminal status races a peer stop, it supersedes the now-invalid event.

## Borrowed-process cleanup

`attach <pid>` requires a thread-group leader PID greater than one and kernel
permission to trace it. It does not change system-wide Yama or seccomp settings.
Tests use a cooperative fixture with `PR_SET_PTRACER_ANY`; normal targets remain
subject to their existing tracing policy.

`detach`, attached-session `q`, and EOF first restore all software bytes and DR
snapshots while every task is held, then `PTRACE_DETACH` each task. Application
signals are forwarded per task. Owned INT3/watchpoint SIGTRAPs have pending signal
zero; they are never injected into the application. A failed attach rolls back
seizes and does not intentionally terminate the external process. Once the first
DETACH succeeds, a dedicated `Detaching` state blocks ordinary debugger
operations: released peers may be running, so a failure cannot be presented as
an all-stop session. The same state is used when an ESRCH race cannot establish
that a task is still held. Controller cleanup fails closed in these cases.

A preflight rejection or first-call DETACH error that leaves every task stopped
has a different outcome: the controller reinstalls its active INT3 and DR state,
preserves IDs and original-byte/register snapshots, and allows retry. It does
not terminate the external process merely because the first DETACH failed.
Restoration itself remains checked; a failed rollback is a fatal mutation error.

Normal cleanup preserves the borrowed process. An unrecoverable rollback, failed reinsertion, or partial-detach failure is different: the debugger terminates the session's
process, even if attached, instead of releasing potentially corrupted code.
SIGTERM and SIGHUP use controlled cleanup, including restoration and detach of
borrowed tasks. SIGKILL cannot be handled; a SIGKILLed or crashed debugger cannot
restore software INT3 bytes in the external process. EXITKILL is deliberately
absent for borrowed processes, so uncontrolled debugger death must not be
described as a safe detach.

## Interrupting the debugger

In an interactive terminal session, Ctrl-C during `cont`, `syscall`, or `si`
requests `PTRACE_INTERRUPT` for running tasks, waits for all-stop, reports the
stop, and returns to the prompt. This also provides a way out of a selected-task
step that waits on a stopped peer. Ctrl-C at the prompt clears the partial
command. The debugger does not inject this control request into the target on
the next resume; explicit kill/raise-generated target SIGINT still follows the
ordinary pending-signal contract.

SIGTERM, SIGHUP, and SIGINT in batch/noninteractive mode request shutdown.
The main loop wakes even when waiting for input or for a running target, regains
all-stop as needed, and performs the same owned-kill/reap or borrowed-restore/
detach cleanup as q/EOF. Its exit status is `128 + signal` (130 for INT, 143 for
TERM, 129 for HUP). Handler code only updates signal-safe flags and writes to a
self-pipe; process-control and cleanup run in ordinary C++ control flow.

This does not add full job control, terminal ownership transfer, or a non-stop
debugger model. It also cannot make an uninterruptible kernel operation complete
or guarantee cleanup after SIGKILL or a debugger crash.

## Hardware watchpoints

`watch <address|@data-symbol> [length]` detects writes; `awatch` detects reads and
writes. SDB uses `PTRACE_PEEKUSER`/`POKEUSER` on x86 debug registers; there is no
memory polling loop. DR0–DR3 hold addresses. DR7 local-enable/RW/LEN fields select
write or read/write and lengths 1, 2, 4 or 8. Addresses must be naturally aligned.

Definitions are shared but hardware registers are per task. Original DR0–DR3,
DR6 and DR7 values are snapshotted. Pre-existing enabled slots are rejected before installing an SDB watchpoint;
coexisting owners of the same debug exception are outside the contract. Programming disables DR7 first, changes addresses/control, then
enables it last. Errors restore pre-operation snapshots; rollback failure is a
fatal mutation error. New cloned tasks receive the definitions before resume,
while restore snapshots reflect a newborn task with no enabled ptrace hardware
breakpoints. Linux clears the child's `ptrace_bps` during clone; a copied virtual
DR7 value must not create a new external watchpoint during restoration.

DR6 B0–B3 identify which owned slots fired. A single-step trap can also contain
data-watch hits: Linux prioritizes `TRAP_TRACE` when TF and hardware data
breakpoints share one #DB, so the controller checks DR6 before auto-continuing
a displaced instruction. A watchpoint is a **post-instruction**
trap: the write/read instruction has already executed, so SDB does not decrement
RIP. All matching slots are reported; status is cleared before resuming. Deleting
a watch restores that slot's original configuration. Detach restores the full
snapshots. Exec drops obsolete definitions because both address space and debug
state have changed.

x86 has no pure read-only data-breakpoint encoding. `rwatch` returns an explicit
error recommending `awatch`; it never silently substitutes a different feature.

## Boundaries

This is an all-stop single-process debugger, not a fork-family or non-stop tracer.
Cross-process shared mappings and full job-control preservation are outside its
contract. FORK/VFORK events and a non-thread
CLONE are intercepted solely for cleanup: hold the new task, normalize queued
INT3 stops, restore original bytes in both address spaces, restore DRs and detach
all tasks with an explicit unsupported-operation error. This prevents a fork
child from executing inherited debugger INT3 bytes. If exec races unsupported
process creation, the session is terminated rather than writing old-image bytes
into a replacement image. After an image replacement, a foreign child's initial
stop can also arrive before its parent's creation event. Its copied image is then
ambiguous, so SDB terminates the session conservatively; this may also reject a
new unsupported fork after exec. The sequential exec-then-fork regression accepts
either verified cleanup path, without claiming exhaustive concurrent event-order
coverage. A selected-task step can wait on a stopped peer; use continue for code
that requires peers to run, or interactive Ctrl-C to regain the prompt.
Symbol lookup covers the actual main ELF image only, opened through
`/proc/TID/exe`; replacing or removing its old pathname does not redirect lookup
to another file. This also supports an executable created through memfd/fexecve.

Tests in `task_control_test.cpp` check task lifecycle, selection, single-step peer
invariance, task-specific registers/syscalls, leader exit, nonleader exec and
attach/detach. `extensions.py` checks shared INT3 hit counts, real DR traps and
register restoration through the user-facing CLI.

References: [Linux ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html),
[Intel SDM Volume 3B, debugging facilities](https://cdrdv2-public.intel.com/835755/253669-sdm-vol-3b.pdf).

## QEMU TCG protection

Two Colima runs with QEMU 9.2.2 and Linux 6.8.0-50 ended in VM-wide RCU stalls and
soft lockups during the advanced watchpoint/single-step work. The guest logs are
preserved in [validation/colima-lockup.txt](validation/colima-lockup.txt). We have
not proved the exact kernel failure path. An [upstream QEMU report](https://lists.gnu.org/archive/html/qemu-devel/2024-02/msg02115.html)
describes a closely related ordering defect: a combined hardware watchpoint and
TF exception is delivered separately under TCG, causing a second exception inside
the guest kernel. That report used another OS, so it is supporting evidence,
not a Linux root-cause proof or a verified fixed-version announcement.

SDB conservatively rejects this combination when CPUID identifies `TCGTCGTCGTCG`,
with `SDB_TCG_GUARD=1` available to force protection for a hidden signature. Generic
QEMU identification is not used because a KVM-backed VM need not share TCG's
exception-emulation behavior. The [QEMU CPUID implementation](https://github.com/qemu/qemu/blob/master/target/i386/cpu.c)
provides the TCG-specific signature. An environment value cannot disable automatic
protection.

Before any affected task resumes, the guard checks actual DR7 enabled data slots
and the requested single-step mode or existing EFLAGS.TF. The controller also
checks before removing a software breakpoint for its internal single-step. A
rejected command leaves the task stopped and its INT3 installed; removing the
watchpoint permits ordinary stepping. All tasks are preflighted before a group
resume, so selecting an unwatched peer cannot bypass another task's TF state.
Detach checks the restored hardware state before releasing tasks.

`info environment` exposes the restriction. Real watchpoint hits during ordinary
continue remain supported. The native combined TF/watch regression is explicitly
skipped on TCG; independent rejection/recovery tests still run. Local test reports
must show that scenario skip. GitHub's native x86 runner requires the combined
regression to execute using `SDB_REQUIRE_NATIVE_WATCHSTEP=1`; its success is only
established by an actual remote run, not by a local guarded test.
