#!/usr/bin/env python3
"""Check that unsupported ptrace is explicit and never silently passes in CI."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).resolve().parent / 'run_checked.py'


class Runner(unittest.TestCase):
    def run_probe(self, code, required, suite_code=0):
        with tempfile.TemporaryDirectory(prefix='sdb-runner-') as directory:
            probe = Path(directory) / 'probe'
            probe.write_text(f'#!/bin/sh\nexit {code}\n')
            probe.chmod(0o700)
            env = dict(os.environ, SDB_REQUIRE_PTRACE='1' if required else '0')
            return subprocess.run([sys.executable, str(RUNNER), str(probe),
                                   sys.executable, '-c', f'raise SystemExit({suite_code})'],
                                  env=env, text=True, capture_output=True, timeout=10)

    def test_missing_capability_is_skip_locally_and_failure_in_ci(self):
        self.assertEqual(self.run_probe(77, False).returncode, 77)
        result = self.run_probe(77, True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('forbids skipping', result.stdout)

    def test_other_probe_failures_are_not_skips(self):
        self.assertEqual(self.run_probe(42, False).returncode, 1)

    def test_suite_failure_is_propagated(self):
        self.assertEqual(self.run_probe(0, False, 23).returncode, 23)
        self.assertEqual(self.run_probe(0, False, 77).returncode, 1)
        self.assertEqual(self.run_probe(0, True).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
