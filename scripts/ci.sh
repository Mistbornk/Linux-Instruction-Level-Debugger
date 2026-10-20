#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD_TYPE=Debug
SANITIZERS=OFF
while (($#)); do
    case "$1" in
        --build-type) BUILD_TYPE="${2:?missing build type}"; shift 2 ;;
        --sanitizers) SANITIZERS="${2:?missing sanitizer setting}"; shift 2 ;;
        *) echo "usage: bash scripts/ci.sh [--build-type Debug|Release] [--sanitizers ON|OFF]" >&2; exit 2 ;;
    esac
done
case "$BUILD_TYPE" in Debug|Release) ;; *) echo "unsupported build type: $BUILD_TYPE" >&2; exit 2 ;; esac
case "$SANITIZERS" in ON|OFF) ;; *) echo "sanitizers must be ON or OFF" >&2; exit 2 ;; esac
BUILD_BASE="${SDB_BUILD_ROOT:-$PROJECT_DIR/build/ci}"
BUILD_PATH="$BUILD_BASE/$BUILD_TYPE-sanitizers-$SANITIZERS"
mkdir -p "$BUILD_PATH"
trap 'result=$?; echo "exit_code=$result" >> "$BUILD_PATH/summary.txt"' EXIT
echo "configuration=$BUILD_TYPE sanitizers=$SANITIZERS" > "$BUILD_PATH/summary.txt"
cmake -S "$PROJECT_DIR" -B "$BUILD_PATH" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DSDB_SANITIZERS="$SANITIZERS" -DBUILD_TESTING=ON 2>&1 | tee "$BUILD_PATH/configure.log"
cmake --build "$BUILD_PATH" --parallel "${SDB_BUILD_JOBS:-2}" 2>&1 | tee "$BUILD_PATH/build.log"
result=0
ctest --test-dir "$BUILD_PATH" --output-on-failure --output-junit "$BUILD_PATH/results.xml" \
    2>&1 | tee "$BUILD_PATH/test.log" || result=$?
python3 - "$BUILD_PATH/results.xml" <<'PY' | tee -a "$BUILD_PATH/summary.txt"
import sys
import xml.etree.ElementTree as ET
cases = ET.parse(sys.argv[1]).getroot().findall('.//testcase')
skipped = [case.get('name') for case in cases if case.find('skipped') is not None]
failed = [case.get('name') for case in cases
          if case.find('failure') is not None or case.find('error') is not None]
print(f'suites={len(cases)} failed={len(failed)} skipped={len(skipped)}')
for name in failed:
    print(f'FAIL: {name}')
for name in skipped:
    print(f'SKIP: {name}')
PY
exit "$result"
