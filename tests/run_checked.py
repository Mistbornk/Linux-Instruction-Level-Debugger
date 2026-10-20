#!/usr/bin/env python3
"""Skip only known ptrace capability failures; CI requires actual execution."""
import os
import subprocess
import sys

probe = subprocess.run([sys.argv[1]], check=False)
if probe.returncode:
    if probe.returncode == 77 and os.environ.get('SDB_REQUIRE_PTRACE') == '1':
        print('FAIL: SDB_REQUIRE_PTRACE=1 forbids skipping ptrace tests', flush=True)
        sys.exit(1)
    sys.exit(probe.returncode if probe.returncode == 77 else 1)
result = subprocess.run(sys.argv[2:], check=False)
if result.returncode == 77:
    print('FAIL: only the capability probe may skip a test suite', flush=True)
    sys.exit(1)
sys.exit(result.returncode if result.returncode >= 0 else 1)
