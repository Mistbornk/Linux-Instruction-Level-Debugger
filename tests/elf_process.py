#!/usr/bin/env python3
"""Resolve the actual executable inode after unlink, replacement, and memfd exec.

All targets are isolated children owned by this test. The existing attach fixture
permits sibling tracing; no machine-wide ptrace or security settings are changed.
"""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

# This shared harness consumes the one SDB-path argument, leaving unittest's
# remaining arguments intact. Importing it does not run its test class.
from extensions import Live, ROOT, SDB, probe_ptrace


class ExecutableIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sdb-elf-process-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.targets = {}
        for name, flags in (("exec", ["-fno-pie", "-no-pie"]),
                            ("pie", ["-fPIE", "-pie"])):
            path = cls.directory / name
            subprocess.run(["gcc", "-Wall", "-Wextra", "-O0", "-g", "-pthread"] + flags +
                           [str(ROOT / "fixtures/ext_features.c"), "-o", str(path)], check=True)
            cls.targets[name] = path
        cls.memfd = cls.directory / "memfd-launcher"
        subprocess.run(["gcc", "-Wall", "-Wextra", "-O0", "-g", "-fno-pie", "-no-pie",
                        str(ROOT / "fixtures/elf_memfd.c"), "-o", str(cls.memfd)], check=True)

    def inspect_and_release(self, target):
        with Live([SDB]) as debugger:
            attached = debugger.command("attach {}".format(target.proc.pid))
            self.assertIn("attached to process", attached)
            debugger.command("set disassemble off")
            # This symbol belongs to the running fixture, and is absent from
            # the different ELF placed at its old pathname in the replace case.
            self.assertNotIn("** error:", debugger.command("break shared_site"))
            self.assertIn("hit a breakpoint", debugger.command("cont"))
            self.assertIn("detached", debugger.command("detach"))
            self.assertNotIn("** error:", debugger.finish())
        self.assertIsNone(target.proc.poll(), "detach terminated the external fixture")
        os.kill(target.proc.pid, signal.SIGUSR1)
        self.assertIn("ATTACH_DONE=", target.finish(""))

    def changed_path(self, replacement):
        for kind, executable in self.targets.items():
            with self.subTest(kind=kind):
                copy = self.directory / ("running-" + kind)
                shutil.copy2(executable, copy)
                with Live([str(copy), "attach"]) as target:
                    target.wait(lambda text: "ATTACH_READY=" in text)
                    proc_exe = Path("/proc/{}/exe".format(target.proc.pid))
                    before = proc_exe.stat()
                    if replacement:
                        different = self.directory / ("replacement-" + kind)
                        shutil.copy2(self.memfd, different)
                        os.replace(different, copy)
                        self.assertNotEqual((copy.stat().st_dev, copy.stat().st_ino),
                                            (before.st_dev, before.st_ino))
                    else:
                        copy.unlink()
                        self.assertFalse(copy.exists())
                    self.assertEqual((proc_exe.stat().st_dev, proc_exe.stat().st_ino),
                                     (before.st_dev, before.st_ino))
                    self.inspect_and_release(target)

    def test_attach_unlinked_executable(self):
        self.changed_path(replacement=False)

    def test_attach_replaced_executable(self):
        self.changed_path(replacement=True)

    def test_attach_memfd_executable(self):
        for kind, executable in self.targets.items():
            with self.subTest(kind=kind):
                with Live([str(self.memfd), str(executable), "attach"]) as target:
                    target.wait(lambda text: "ATTACH_READY=" in text)
                    label = os.readlink("/proc/{}/exe".format(target.proc.pid))
                    self.assertIn("memfd:sdb-elf-image", label)
                    self.inspect_and_release(target)

    def test_exec_memfd_reloads_symbols_and_clears_breakpoints(self):
        for kind, executable in self.targets.items():
            with self.subTest(kind=kind):
                with Live([SDB, str(self.memfd), str(executable), "memory"]) as debugger:
                    debugger.command("set disassemble off")
                    debugger.command("break main")
                    self.assertIn("hit a breakpoint", debugger.command("cont"))
                    executed = debugger.command("cont")
                    self.assertIn("** exec:", executed)
                    self.assertIn("memfd:sdb-elf-image", executed)
                    self.assertIn("old breakpoints cleared", executed)
                    self.assertIn("no breakpoints", debugger.command("info break"))
                    self.assertNotIn("** error:", debugger.command("break ready"))
                    self.assertIn("hit a breakpoint", debugger.command("cont"))
                    debugger.command("write @watched 2a00000000000000")
                    self.assertIn("exited with status 0", debugger.command("cont"))
                    text = debugger.finish()
                    self.assertIn("VALUE=42", text)
                    self.assertNotIn("** error:", text)


if __name__ == "__main__":
    if not probe_ptrace():
        sys.exit(77)
    unittest.main(verbosity=2)
