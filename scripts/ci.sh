#!/usr/bin/env bash
# The same entry point is used by local Colima validation and GitHub Actions.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

configuration=""
sanitizers=OFF
while (( $# )); do
    case "$1" in
        --build-type) configuration="${2:?missing build type}"; shift 2 ;;
        --sanitizers) sanitizers="${2:?missing sanitizer setting}"; shift 2 ;;
        --help)
            echo 'usage: scripts/ci.sh [--build-type Debug|Release --sanitizers OFF|ON]'
            echo 'Without arguments, run Debug, Release and sanitized Debug.'
            echo 'SDB_BUILD_ROOT overrides build/ci; use /tmp/sdb-ci on Colima SSHFS mounts.'
            echo 'CI reporting requires CMake/CTest 3.21+ for --output-junit.'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
if [[ "$sanitizers" != OFF && "$sanitizers" != ON ]]; then
    echo '--sanitizers must be OFF or ON' >&2
    exit 2
fi
if [[ -z "$configuration" ]]; then
    "$0" --build-type Debug --sanitizers OFF
    "$0" --build-type Release --sanitizers OFF
    "$0" --build-type Debug --sanitizers ON
    exit 0
fi
if [[ "$configuration" != Debug && "$configuration" != Release ]]; then
    echo '--build-type must be Debug or Release' >&2
    exit 2
fi
build_root="${SDB_BUILD_ROOT:-build/ci}"
build_dir="${build_root}/${configuration}-sanitizers-${sanitizers}"
mkdir -p "$build_dir"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
cmake -S . -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE="$configuration" \
    -DSDB_SANITIZERS="$sanitizers" -DBUILD_TESTING=ON 2>&1 | tee "$build_dir/configure.log"
cmake --build "$build_dir" --parallel "${SDB_BUILD_JOBS:-2}" 2>&1 | tee "$build_dir/build.log"
set +e
ctest --test-dir "$build_dir" --output-on-failure --output-junit results.xml \
    2>&1 | tee "$build_dir/test.log"
test_status=${PIPESTATUS[0]}
set -e
python3 - "$build_dir/results.xml" "$build_dir/summary.txt" <<'PY'
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

source, destination = map(Path, sys.argv[1:])
if not source.exists():
    destination.write_text("FAIL: CTest did not write its JUnit report. CMake/CTest 3.21+ is required.\n")
    print(destination.read_text(), end="")
    sys.exit(1)
root = ET.parse(source).getroot()
cases = list(root.iter("testcase"))
if not cases:
    destination.write_text("FAIL: CTest report contains no tests.\n")
    print(destination.read_text(), end="")
    sys.exit(1)
skipped = [case for case in cases if case.find("skipped") is not None]
failed = [case for case in cases if case.find("failure") is not None or case.find("error") is not None]
scenario_skips = []
for case in cases:
    details = "\n".join(case.findtext(tag, "") for tag in ("system-out", "system-err"))
    for line in details.splitlines():
        if re.search(r"\btest_\S+.*\.\.\. skipped ", line):
            scenario_skips.append((case.get("name"), line.strip()))
# LastTest.log retains complete output if the CTest version truncates a passed
# suite's JUnit system-out. Never hide a native-only scenario behind suite success.
complete_log = source.parent / "Testing/Temporary/LastTest.log"
if complete_log.exists():
    known = {line for _, line in scenario_skips}
    for line in complete_log.read_text().splitlines():
        if re.search(r"\btest_\S+.*\.\.\. skipped ", line) and line.strip() not in known:
            scenario_skips.append(("CTest log", line.strip()))
            known.add(line.strip())
summary = "CTest suites: {} total, {} passed, {} failed, {} skipped.\n".format(
    len(cases), len(cases) - len(skipped) - len(failed), len(failed), len(skipped))
for case in skipped:
    summary += "SKIP {}: {}\n".format(case.get("name"), case.findtext("system-out", "see test.log").strip())
summary += "Nested scenario skips: {} (not counted as executed feature coverage).\n".format(len(scenario_skips))
for suite, description in scenario_skips:
    summary += "SCENARIO SKIP {}: {}\n".format(suite, description)
destination.write_text(summary)
print(summary, end="")
if skipped and os.environ.get("SDB_REQUIRE_PTRACE") == "1":
    print("FAIL: this run requires actual ptrace coverage; skipped suites are not passes.")
    sys.exit(1)
if os.environ.get("SDB_REQUIRE_NATIVE_WATCHSTEP") == "1" and any(
        "native TF/watchpoint execution unavailable" in line for _, line in scenario_skips):
    print("FAIL: this run requires native combined TF/watchpoint execution; the TCG guard is not equivalent coverage.")
    sys.exit(1)
PY
exit "$test_status"
