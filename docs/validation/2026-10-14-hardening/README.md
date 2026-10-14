# Hardening validation — 2026-10-14

These records validate source commit
[`37c1e9671c2b8a9656b00eb29253227227f73d45`](https://github.com/Mistbornk/SDB/commit/37c1e9671c2b8a9656b00eb29253227227f73d45).
The [manifest](source.sha256) hashes 60 source, fixture, test and build inputs.
Later documentation commits do not change those inputs.

- `local/`: Colima QEMU 9.2.2 TCG x86-64 on Apple Silicon, Ubuntu 22.04;
  Debug, Release and ASan/UBSan each pass 11 CTest suites. Each runs 68 Python
  methods and explicitly skips the native single-step/watchpoint combination.
- `native/`: downloaded reports from
  [GitHub Actions run 38536434814](https://github.com/Mistbornk/SDB/actions/runs/38536434814),
  including public run/job/artifact metadata. Each of the four jobs passes all
  11 suites and 69 Python methods, with zero scenario skips. The fourth job
  builds the public Dockerfile and tests the source copied into its image.
- Six C++ test executables and the two interview demo sessions are additional
  checks, counted separately from the Python methods.
- [make.log](make.log) records the final `make -j2 test` run; [demo.log](demo.log)
  and [interview-demo.log](interview-demo.log) preserve the standalone demos.
  [benchmark.json](benchmark.json) records seven rounds per Release benchmark
  case; [local-environment.json](local-environment.json) records tool versions
  and hashes of all four local SDB binaries.

The local commands, results, scope and environment are explained in
[testing.md](../../testing.md). The [performance record](../../performance.md)
explains why emulated guest measurements are not native x86 hardware latency.

Three failure logs preserve regressions from earlier revisions; they are not
failures of the validated source above:

- [native-release-before-fix.log](native-release-before-fix.log): native Release
  at `030abe6` could present an already-acknowledged terminal interrupt twice.
- [delayed-interrupt-before-fix.log](delayed-interrupt-before-fix.log): a target
  masking SIGINT reproduces that ordering deterministically against the old binary.
- [masked-breakpoint-before-fix.log](masked-breakpoint-before-fix.log): at
  `18ec3f1`, an intervening breakpoint and single-step lost the delayed terminal
  signal's correlation and incorrectly exposed it as an application signal.

The final signal suite tests both direct delivery and delivery after a
breakpoint/single-step, as well as blocked syscall ordering and unrelated
application-signal forwarding. Full transcripts remain unedited, including
addresses, timings, expected fault-injection diagnostics and explicit skips.
