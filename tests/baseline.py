#!/usr/bin/env python3
"""Capture behavior of the original monolith before refactoring.

Run on Linux x86-64: python3 tests/baseline.py /path/to/original-sdb
Only existing successful behavior is asserted; defects are documented separately.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

SDB = str(Path(sys.argv.pop(1)).resolve())
ROOT = Path(__file__).resolve().parent


class Baseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sdb-baseline-")
        cls.target = Path(cls.temp.name) / "loop"
        subprocess.run(["gcc", "-nostdlib", "-no-pie", "-g", str(ROOT / "fixtures/loop.S"), "-o", str(cls.target)], check=True)
        output = subprocess.check_output(["nm", "-n", str(cls.target)], text=True)
        cls.symbols = {line.split()[2]: int(line.split()[0], 16) for line in output.splitlines() if len(line.split()) == 3}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, commands):
        proc = subprocess.Popen([SDB, str(self.target)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            out, _ = proc.communicate("\n".join(commands + ["q", ""]), timeout=30)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        self.assertEqual(proc.returncode, 0, out)
        return out

    def bp(self, name):
        return "break {:x}".format(self.symbols[name])

    def test_load_continue(self):
        out = self.session(["cont"])
        self.assertIn("loaded. entry point:", out)
        self.assertIn("LOOP=10", out)
        self.assertIn("target program terminated", out)

    def test_registers_and_step(self):
        out = self.session(["info reg", "si", "cont"])
        self.assertIn("$rip", out)
        self.assertIn("LOOP=10", out)

    def test_ten_breakpoint_hits(self):
        out = self.session([self.bp("loop_body")] + ["cont"] * 11)
        self.assertEqual(out.count("hit a breakpoint"), 10, out)
        self.assertIn("LOOP=10", out)

    def test_step_then_continue(self):
        out = self.session([self.bp("loop_body"), "cont", "si"] + ["cont"] * 10)
        self.assertEqual(out.count("hit a breakpoint"), 10, out)
        self.assertIn("LOOP=10", out)

    def test_two_breakpoints_and_delete(self):
        out = self.session([self.bp("loop_body"), self.bp("after_loop"), "cont", "delete 0", "cont", "delete 1", "cont"])
        self.assertEqual(out.count("hit a breakpoint"), 2, out)
        self.assertIn("LOOP=10", out)

    def test_syscall_entry_and_exit(self):
        out = self.session(["syscall", "syscall", "cont"])
        self.assertIn("enter a syscall(1)", out)
        self.assertIn("leave a syscall(1) = 8", out)
        self.assertIn("LOOP=10", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
