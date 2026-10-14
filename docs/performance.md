# Measuring debugger overhead

Run an optimized build inside Linux x86-64, with no other test suite running:

```sh
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
python3 scripts/benchmark.py build/release/sdb --repeats 7 --output build/benchmark.json
```

The benchmark compiles **one identical non-PIE assembly fixture** containing 200
`getpid` syscalls followed by `exit`. There is no dynamic linker or C runtime
startup in this target. It validates each case before timing, performs one warmup
per case, then shuffles the case order in each repeated round with a fixed seed.
Raw samples, medians, minimum/maximum, compiler and kernel details go into JSON.

| Case | Work performed |
| --- | --- |
| native | Execute the fixture without a debugger in the same guest |
| continue | Launch SDB, reach entry, continue the exact same fixture to exit |
| syscalls_no_disassembly | Stop at all 200 entries and 200 exits, print decoded syscall events |
| syscalls_with_disassembly | Same 400 stops, with automatic disassembly at each stop |

`(syscalls_no_disassembly − continue) / 400` estimates the incremental cost of
ptrace syscall stopping, event classification, argument decoding and reporting.
`(syscalls_with_disassembly − syscalls_no_disassembly) / 400` estimates the
additional automatic disassembly path: `/proc` mapping lookup, bounded memory
read, Capstone decode and formatted output. It does **not** isolate Capstone's
CPU time. `set disassemble off` lets actual syscall sessions avoid this work;
explicit `disasm` still works with the option disabled.

Each timing includes the subprocess session and waits for the debugger to exit;
all measured stdout goes to `/dev/null`. The subprocess creation call itself is
outside the timer. There is no comparison to an unpreserved historic executable,
nor any claim of an arbitrary percentage improvement. A Colima x86-64 VM on an
ARM Mac includes emulation and host scheduling costs, so its absolute numbers
must not be presented as native x86-64 hardware performance. Repeat on deployment
hardware before drawing conclusions about latency. Sanitized builds are for
correctness checking and should not be used to describe release performance.

ELF metadata is already loaded once per executable image. Breakpoints use an
address-indexed map and range overlays; disassembly reads at most five maximum
length x86 instructions and stops at executable VMA boundaries. These choices
bound unnecessary work without an unsupported cache of live `/proc` mappings.
Avoiding automatic disassembly is a measurable user-visible control; changing
the breakpoint container without a demonstrated bottleneck is not justified.

## Hardening revision: 2026-10-14

Source commit `37c1e96` was measured after the final Debug, Release, sanitizer,
Make and demo checks, with no other local build or test running. This is the same
Colima QEMU 9.2.2 TCG x86-64 environment described below. It includes the new
signal-monitoring and interrupt handling paths; these measurements are not a
controlled before/after comparison with the earlier revision.

```sh
python3 scripts/benchmark.py /tmp/sdb-hardening/Release-sanitizers-OFF/sdb \
  --repeats 7 --output docs/validation/2026-10-14-hardening/benchmark.json
```

| Case | Median session (ms) | Minimum–maximum (ms) |
| --- | ---: | ---: |
| native (untraced guest) | 1.484 | 1.316–1.986 |
| continue | 30.381 | 28.436–37.135 |
| syscalls_no_disassembly | 132.429 | 125.281–145.239 |
| syscalls_with_disassembly | 382.089 | 367.753–578.598 |

The median differences estimate **255.120 µs per syscall stop** beyond continue
and **624.150 µs per stop** for the automatic-disassembly path. The wide range in
the latter case remains visible in the raw samples; emulation and scheduling
are part of these wall-clock observations. They do not establish native x86
hardware latency or a historical speedup.

All four validation/warmup sessions and 28 measured sessions completed normally.
The [raw JSON](validation/2026-10-14-hardening/benchmark.json) contains all samples,
environment details and binary hashes. Its Release SDB hash matches the
[local build record](validation/2026-10-14-hardening/local-environment.json).
The [source manifest](validation/2026-10-14-hardening/source.sha256) identifies the
validated inputs; [testing.md](testing.md) records the separate native CI proof.

## Recorded run: 2026-10-14

This earlier expanded-debugger measurement is retained as historical evidence;
it predates the hardening revision above.

The Release build was measured after the Debug, Release and sanitizer suites,
with no other build or test running. Environment: Apple Silicon Mac, Colima
QEMU 9.2.2 TCG x86-64 guest with four logical CPUs, Linux 6.8.0-50-generic,
Ubuntu 22.04 userspace, GCC 11.4.0 and Capstone 4.0.2. The `native` case name
means **untraced in this emulated guest**, not execution on native x86 hardware.

```sh
python3 scripts/benchmark.py /tmp/sdb-ci-20261014/Release-sanitizers-OFF/sdb \
  --repeats 7 --output docs/validation/2026-10-14/benchmark.json
```

| Case | Median session (ms) | Minimum–maximum (ms) |
| --- | ---: | ---: |
| native (untraced guest) | 1.484 | 1.236–1.976 |
| continue | 25.814 | 25.447–27.323 |
| syscalls_no_disassembly | 86.062 | 83.458–87.355 |
| syscalls_with_disassembly | 261.863 | 258.570–269.416 |

The median differences estimate **150.620 µs per syscall stop** beyond the
continue case and **439.504 µs per stop** for the automatic-disassembly path in
this environment. The latter is the combined mapping/read/decode/output cost
described above. It demonstrates why disabling automatic disassembly can help
syscall-heavy sessions; it does not establish a general hardware-independent
speedup or a comparison with the original implementation.

All four validation/warmup sessions and 28 measured sessions completed normally;
both syscall validation sessions observed exactly 200 entries and 200 exits.
The [raw JSON](validation/2026-10-14/benchmark.json) preserves all seven samples
per case, environment details, and SHA-256 hashes of the measured SDB and fixture
binaries. The script fails if expected syscall events or normal target exit are
missing.
