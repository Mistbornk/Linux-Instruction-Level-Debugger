# Tests and validation record

## Current hardening revision: verified on 2026-10-14

Validated source commit: [`37c1e9671c2b8a9656b00eb29253227227f73d45`](https://github.com/Mistbornk/SDB/commit/37c1e9671c2b8a9656b00eb29253227227f73d45).
The [source manifest](validation/2026-10-14-hardening/source.sha256) records 60
source, fixture, test and build/configuration inputs; the accompanying
[commit record](validation/2026-10-14-hardening/source-commit.txt) identifies the
revision independently of subsequent documentation changes.

The local Colima environment remains QEMU 9.2.2 TCG x86-64 on Apple Silicon,
Linux 6.8.0-50-generic, Ubuntu 22.04 userspace, GCC 11.4.0 and Capstone 4.0.2.
All three configurations passed their complete 11-entry CTest matrix:

| Local configuration | Result | Evidence |
|---|---|---|
| Debug | 11/11 passed; 26.70 s | [test log](validation/2026-10-14-hardening/local/Debug-sanitizers-OFF/test.log), [summary](validation/2026-10-14-hardening/local/Debug-sanitizers-OFF/summary.txt) |
| Release | 11/11 passed; 33.67 s | [test log](validation/2026-10-14-hardening/local/Release-sanitizers-OFF/test.log), [summary](validation/2026-10-14-hardening/local/Release-sanitizers-OFF/summary.txt) |
| ASan + UBSan + leak detection | 11/11 passed; 70.36 s; no sanitizer diagnostics | [test log](validation/2026-10-14-hardening/local/Debug-sanitizers-ON/test.log), [summary](validation/2026-10-14-hardening/local/Debug-sanitizers-ON/summary.txt) |

Each local configuration executed 68 Python test methods, with one additional
combined TF/watchpoint method explicitly skipped on TCG, plus both interview
demo sessions. There were no skipped CTest entries. The method inventory is
34 integration + 23 extensions + 4 executable-identity + 8 control-signal tests;
the TCG skip is inside the extensions suite. Demo sessions and C++ module checks
are counted separately from these Python methods.

[Native GitHub Actions run 38536434814](https://github.com/Mistbornk/SDB/actions/runs/38536434814)
passed for that same commit. Its four Ubuntu x86-64 jobs each passed 11/11 CTest
entries, executed all 69 Python methods with **zero scenario skips**, and passed
both interview demo sessions:

| Native job | Preserved result |
|---|---|
| Debug | [summary](validation/2026-10-14-hardening/native/linux-Debug-sanitizers-OFF/summary.txt) |
| Release | [summary](validation/2026-10-14-hardening/native/linux-Release-sanitizers-OFF/summary.txt) |
| ASan + UBSan + leak detection | [summary](validation/2026-10-14-hardening/native/linux-Debug-sanitizers-ON/summary.txt) |
| Public Ubuntu 24.04 Docker image, Release | [summary](validation/2026-10-14-hardening/native/public-container-Release/summary.txt) |

The native run uses `SDB_REQUIRE_PTRACE=1` and `SDB_REQUIRE_NATIVE_WATCHSTEP=1`.
It therefore supplies actual combined single-step/watchpoint coverage in
addition to the TCG rejection/recovery tests. The public-image job builds from
the checked-in Dockerfile and copied source, without `up25_image`, and runs with
`--init --cap-add SYS_PTRACE`. Full logs, JUnit reports, and run/job metadata are
preserved alongside the summaries.

The hardening tests cover PTY Ctrl-C and a usable prompt, delayed terminal
SIGINT and blocked syscall ordering, TERM/HUP and batch INT cleanup, preservation
of attached targets, first-DETACH retry versus partial-release failure, actual
unlinked/replaced/memfd executable identity, and the watchpoint/backtrace demo.
The task-control module also injects a closed launch-gate peer under default
SIGPIPE handling: `send(MSG_NOSIGNAL)` must report EPIPE, reap the child, and leave
the debugger reusable.

The additional final-source checks also completed successfully:

| Check | Result | Evidence |
|---|---|---|
| `make -j2 test` | Six C++ module binaries passed; 34 integration, 22 extension, 4 executable-identity and 8 signal methods passed; one TCG case skipped; interview demo passed | [Make log](validation/2026-10-14-hardening/make.log) |
| Standalone README batch demo | One `main` breakpoint hit, single-step, `VISITS=10`, target and debugger exit 0 | [transcript](validation/2026-10-14-hardening/demo.log) |
| Standalone interview demo | Both buggy and corrected sessions passed watchpoint, backtrace, memory and exit assertions | [verified transcripts](validation/2026-10-14-hardening/interview-demo.log) |
| Release benchmark | Four cases validated; seven samples per case recorded | [raw samples](validation/2026-10-14-hardening/benchmark.json), [interpretation](performance.md) |

The final Make run rebuilt the changed source incrementally; it is not described
as a clean build. Its Python suite times were 40.599 s (integration), 29.829 s
(extensions), 7.158 s (executable identity), and 18.236 s (signals). The
[environment record](validation/2026-10-14-hardening/local-environment.json)
preserves compiler/library versions and SHA-256 hashes of the Make, Debug,
Release and sanitized debugger binaries.

### Native CI found a delayed-interrupt defect

An earlier native Release job at `030abe6` failed because the target could
receive its terminal SIGINT only after the user had acknowledged Ctrl-C and
issued `cont`. SDB presented the same interruption a second time, leaving the
target stopped rather than continuing. The failure is preserved in
[the native Release log](validation/2026-10-14-hardening/native-release-before-fix.log)
from [run 38533854326](https://github.com/Mistbornk/SDB/actions/runs/38533854326).

A deterministic regression blocks SIGINT in the target, confirms the signal is
pending, then unblocks it on the next continue. It failed against the old binary
with the unwanted second prompt ([before-fix log](validation/2026-10-14-hardening/delayed-interrupt-before-fix.log)).
The first correction consumed an already-acknowledged terminal copy without
another visible stop. An expanded subcase then kept SIGINT masked across a
software breakpoint and single-step. Against `18ec3f1`, those intervening stops
discarded the correlation, so the later terminal copy was incorrectly reported
as an application SIGINT ([masked-breakpoint before-fix log](validation/2026-10-14-hardening/masked-breakpoint-before-fix.log)).

The final fix retains the correlation across all non-SIGINT stops, propagates it
to same-thread-group clones, and rechecks process-group membership when SIGINT
is delivered. A matched, already-acknowledged terminal copy resumes the requested
mode transparently. The final local and native matrices pass both masked-signal
subcases. A separate blocked `PTRACE_SYSCALL` case checks that an intervening
syscall-exit stop does not lose the correlation; an unrelated application signal
and SIGINT from another terminal remain forwardable.

## Previous expanded debugger: verified on 2026-10-14

Environment: Apple Silicon Mac → Colima QEMU 9.2.2 TCG x86-64 VM →
`up25_image` / `sdb-dev`; Linux 6.8.0-50-generic, Ubuntu 22.04 userspace,
GCC 11.4.0, Capstone 4.0.2 and CMake 3.22.1.

The complete local `scripts/ci.sh` matrix passed after the SEIZE, all-stop,
breakpoint-displacement, detach-rollback and exec/foreign-child fixes. The matrix
exited with status 0. These are local results, not remote GitHub Actions results.

| Configuration | Result | Evidence |
|---|---|---|
| CMake Debug | 8/8 CTest suites passed; 17.33 s | [test log](validation/2026-10-14/debug-tests.log), [summary](validation/2026-10-14/debug-summary.txt) |
| CMake Release | 8/8 CTest suites passed; 24.92 s | [test log](validation/2026-10-14/release-tests.log), [summary](validation/2026-10-14/release-summary.txt) |
| ASan + UBSan + leak detection | 8/8 CTest suites passed; 40.18 s; no sanitizer diagnostics | [test log](validation/2026-10-14/asan-tests.log), [summary](validation/2026-10-14/asan-summary.txt) |
| Clean `make -j2 test` | Six C++ module binaries passed; 34 integration methods passed (37.414 s); 22 extension methods passed and one TCG case skipped (28.098 s); exit 0 | [Make log](validation/2026-10-14/make.log) |
| README batch demo | One `main` breakpoint hit, registers, single-step, `VISITS=10`, target and debugger exit 0 | [demo log](validation/2026-10-14/demo.log) |

Each configuration ran 34 integration methods and 23 extension methods: 22
extension methods executed, and the native combined trap-flag/watchpoint case was
explicitly skipped on QEMU TCG. There were no skipped CTest suites. A passing
suite does **not** mean that the skipped native case was executed. Separate
tests verify the TCG refusal, unchanged stopped state and recovery after deleting
the watchpoint or clearing TF.

After a child-subreaper cleanup adjustment to the test harness, the extension
suite passed again in all three configurations, each with the same 22 executed
methods and one explicit skip:
[Debug, 15.587 s](validation/2026-10-14/debug-extensions-final.log),
[Release, 7.594 s](validation/2026-10-14/release-extensions-final.log), and
[ASan/UBSan, 12.337 s](validation/2026-10-14/asan-extensions-final.log).
This adjustment changed test cleanup, not debugger source; these rerun timings
are separate from the full-matrix timings above.

The [SHA-256 manifest](validation/2026-10-14/source.sha256) records the 49 source,
fixture, test and build/configuration inputs for this validation. The separate
[Release performance record](performance.md#recorded-run-2026-10-14) links the raw
benchmark samples and explains which tracing/disassembly costs they measure.

## Historical single-task milestone: verified on 2026-10-13

The following results apply to the earlier single-task implementation, before
the attach, thread-control and inspection extensions. They are retained as a
regression baseline and do **not** validate the current expanded source tree.

Environment: Apple Silicon Mac → Colima QEMU x86-64 VM → `up25_image` /
`sdb-dev`; Linux 6.8.0-50-generic, Ubuntu 22.04 userspace, GCC 11.4.0,
Capstone 4.0.2, CMake 3.22.1.

| Configuration | Result |
|---|---|
| Original implementation baseline | 6/6 sessions passed |
| Clean CMake Debug build | No compiler warnings; 4/4 CTest entries passed, no skips (11.26 s) |
| ASan + UBSan + leak detection, milestone harness | 4/4 CTest entries passed, no skips or sanitizer diagnostics (23.57 s) |
| Make build and milestone `make test` | All three module binaries passed; 34/34 integration methods passed (20.472 s for integration) |
| README batch demo | PIE `break main`, registers, single-step, `VISITS=10`, exit 0 |

The integration entry contains **34 Python test methods**, with additional
subcases. The four CTest entries should not be confused with four individual
debugger scenarios. These results describe this environment and do not establish
kernel-wide compatibility or remote GitHub Actions results.

## QEMU TCG restriction and regression evidence

Two validation attempts in the Colima QEMU 9.2.2 TCG environment encountered
VM-wide RCU stalls and soft lockups while exercising hardware watchpoints and
single-step together. The VM required recovery. The observed failures are not
recorded as passing or as ordinary test timeouts. An upstream
[QEMU report](https://lists.gnu.org/archive/html/qemu-devel/2024-02/msg02115.html)
describes a related TCG watchpoint/trap-flag exception problem; it does not prove
the cause of these Linux stalls or establish a fixed QEMU version.

A runtime guard now rejects a data watchpoint combined with `PTRACE_SINGLESTEP`
or an already-set EFLAGS.TF on detected TCG. `SDB_TCG_GUARD=1` forces this guard
on for portable tests. The controller checks before disabling an INT3, and
task control checks all tasks to be resumed before releasing any of them.
Ordinary continue-based hardware watchpoint tests remain enabled. The combined
single-step/watchpoint execution case is explicitly skipped on TCG and retained
for native x86-64 or KVM validation; refusal and recovery have separate tests.

The current matrix covers SEIZE launch/exec handling, interrupt bookkeeping,
shared-breakpoint displacement, blocking-syscall peer progress and fork/clone
cleanup. The sequential exec-then-fork fixture checks permitted cleanup outcomes;
it does not claim to deterministically reproduce every cross-task fork/exec race.

## Reproduce

Run in the x86-64 Colima `sdb-dev` container or a Linux x86-64 host:

```sh
cmake -S . -B /tmp/sdb-build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/sdb-build -j4
ctest --test-dir /tmp/sdb-build --output-on-failure
```

To repeat the complete local configuration matrix with saved JUnit and skip
summaries:

```sh
SDB_REQUIRE_PTRACE=1 SDB_BUILD_ROOT=/tmp/sdb-ci scripts/ci.sh
```

On native x86-64 or KVM, also set `SDB_REQUIRE_NATIVE_WATCHSTEP=1` when a run must
execute the combined trap-flag/watchpoint case. This requirement intentionally
fails on guarded TCG instead of treating its skip as equivalent coverage.

`make test` runs the same module and integration checks. Python uses only its
standard library; fixtures need GCC and binutils. Use `ctest -V` to see individual
Python test names and module diagnostics. Each debugger session has a timeout and
a separate process group, which the harness cleans up on failure.

The CMake configuration registers the following 11 entries. Results for a
specific revision are recorded above; this table describes their coverage:

| Entry | Evidence |
|---|---|
| `integration` | 34 command-driven cases, including subcases and repeated sessions |
| `tracee_memory` | real child lifecycle, ptrace stops, memory range/FD checks, syscall fault injection |
| `elf_image_pie` | ELF parser and runtime translation cross-checked against loader and kernel data |
| `elf_image_exec` | same checks with ET_EXEC, including zero load bias |
| `inspection` | register values, bounded frame chains and safe syscall string inspection |
| `task_control` | per-task stops, clone/exec/exit, attach/detach, resume guards, and closed launch-gate EPIPE/SIGPIPE cleanup |
| `detach` | real ptrace fault injection: restoration rollback, partial-detach cleanup and existing hardware-breakpoint rejection |
| `extensions` | command-driven inspection, watchpoints, thread control, attach/detach and guard recovery |
| `elf_process` | four methods for unlinked/replaced executable paths, memfd attach and later exec |
| `signals` | eight methods for control signals, PTY interruption, masked SIGINT across breakpoint/step and blocked syscalls, and ownership-aware cleanup |
| `interview_demo` | wrong-pointer store found by hardware watchpoint, four-frame backtrace, memory observations and corrected run |

The integration tests assert actual target output (`LOOP=10`, `VISITS=10`, signal
handler count), target exit status, exact breakpoint RIPs and relocated symbol
addresses. They cover ten repeated hits, two breakpoints, duplicate/delete,
original zero byte, patch overlap, single-step exit, fatal signals, signal
forwarding/suppression, syscall entry/exit at a breakpoint, exec replacement,
external SIGKILL then reload, EOF cleanup, malformed input and ELF files, stripped
symbols, quoted paths/arguments and an executable page boundary. Repeated PIE
launches check relocation and, when ASLR is enabled, varying runtime addresses.

The FD regression performs 150 breakpoint/add/disassemble/delete cycles while
observing `/proc/PID/fd`. Memory tests inject failures into the actual open/pread/
pwrite call boundaries using linker `--wrap`, including a short write followed by
failure and rollback failure. They do not substitute a mock debugger. ELF tests
compare against `dl_iterate_phdr`, `AT_ENTRY` and an actual function pointer, and
reject malformed headers, unsupported symbol kinds, FIFO/directory/NUL paths.

An independent TRACEME probe determines whether the environment permits tracing.
Denied permissions/unsupported platforms return 77; CTest marks the relevant test
**Skipped**. The TCG restriction above is a separate, named feature-case skip
inside `extensions`; its reason must remain visible in the Python results.
Assertion failures, unexpected errors, build errors and timeouts never become
skips. ELF-only checks do not require ptrace. A CTest entry can pass while one of
its Python cases is skipped, so review the detailed case results as well.

## Baseline before refactoring

On 2026-10-13, the original single-file debugger passed **6/6 baseline sessions**
in the existing Colima environment: launch/continue, registers/single-step, ten
breakpoint hits, step then continue, two breakpoints/delete, and syscall entry/exit.
This established working behavior; it was not evidence that the original handled
signals, invalid inputs or exit edge cases safely.

The original source is preserved in Git commit `01aeec7`, and the baseline harness
remains in `tests/baseline.py`. To repeat without restoring old code into the tree:

```sh
git show 01aeec7:sdb.cpp > /tmp/sdb-baseline.cpp
g++ -std=c++17 -g /tmp/sdb-baseline.cpp -lcapstone -o /tmp/sdb-baseline
python3 tests/baseline.py /tmp/sdb-baseline
```

## Defects reproduced while implementing the regression suite

- A syscall single-step returned `TRAP_BRKPT`; treating only `TRAP_TRACE` as a
  single-step caused a synthetic SIGTRAP to be forwarded and kill the fixture.
  The fix accounts for Linux x86-64 syscall-step reporting while preserving
  native INT3 and user-generated SIGTRAP as application signals.
- Killing a stopped child externally left stale stopped state and prevented the
  next load. Nonblocking wait reconciliation now consumes the terminal event
  before another command accesses registers.
- Colima's SSHFS mount produced a non-executable linker output in the first Make
  build. The Make link rule explicitly applies executable permission. Fresh
  container-local CMake builds avoid shared-mount mode/timestamp differences.
- One intermediate Make run ended with status 137. Review found that the live
  test harness shared its output file offset with the debugger and accepted an
  unterminated PID field. Reads now use pread, and external-kill tests validate
  full PID fields, parent ownership and process-group membership. The precise
  cause of that termination was not established; the historical milestone Make
  and sanitizer runs both passed with these harness fixes.

These are measured findings. The other original risks described in
`SDB_improve.md` remain a historical static review, not a claim that every original
failure was reproduced.

## Scope and evidence limits

Thread support is limited to tasks in one Linux thread group. Fork/vfork and
non-thread clone cases test safe rejection and restoration, not continued
debugging of a process family. Backtrace tests cover established frame pointers,
not DWARF unwinding, arbitrary prologues/epilogues or signal frames. Tests do not
establish shared-library symbol lookup, arbitrary self-modifying code or
transparent job control. The TCG combined-step restriction is described above.
No remote CI run is claimed by local test results.
Sanitizers instrument the debugger and module tests, not every external library
or the ordinary integration target fixtures.
