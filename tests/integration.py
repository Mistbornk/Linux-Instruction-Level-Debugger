#!/usr/bin/env python3
"""Command-driven Linux x86-64 ptrace regressions; Python standard library only.

Every session has a deadline and its own process group. Unsupported platforms or
a denied independent PTRACE_TRACEME probe return 77 (CTest reports a skip).
Assertion failures, compiler failures and debugger timeouts are never skipped.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
TIMEOUT = int(os.environ.get("SDB_TEST_TIMEOUT", "20"))
SDB = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "./sdb").resolve())


def probe_ptrace():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        print("SKIP: tests require a Linux x86-64 kernel", flush=True)
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        result = libc.ptrace(0, 0, None, None)  # PTRACE_TRACEME
        code = ctypes.get_errno() if result == -1 else 0
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status):
        raise RuntimeError("ptrace environment probe did not exit normally")
    code = os.WEXITSTATUS(status)
    if code in (errno.EPERM, errno.EACCES, errno.ENOSYS):
        print("SKIP: independent PTRACE_TRACEME probe: " + os.strerror(code), flush=True)
        return False
    if code:
        raise OSError(code, "unexpected PTRACE_TRACEME probe failure")
    return True


def run_process(argv, data=""):
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = proc.communicate(data, timeout=TIMEOUT)
        return proc.returncode, output
    except subprocess.TimeoutExpired as error:
        raise AssertionError("SDB session timed out: {}\n{}".format(argv, error.output)) from error
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def read_log(log):
    # stdout and the parent share an open file description. seek()/read() would
    # move the child's write offset; pread observes without disturbing it.
    return os.pread(log.fileno(), os.fstat(log.fileno()).st_size, 0).decode()


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sdb-regression-")
        cls.directory = Path(cls.temp.name)
        cls.fixtures = {}
        for name in ("loop", "exit", "patch", "boundary"):
            path = cls.directory / name
            subprocess.run(["gcc", "-nostdlib", "-no-pie", "-g", str(ROOT / "fixtures" / (name + ".S")), "-o", str(path)], check=True)
            cls.fixtures[name] = path
        for name, flags in (("nonpie", ["-fno-pie", "-no-pie"]), ("pie", ["-fPIE", "-pie"])):
            path = cls.directory / name
            subprocess.run(["gcc", "-O0", "-g", "-fno-omit-frame-pointer"] + flags + [str(ROOT / "fixtures/target.c"), "-o", str(path)], check=True)
            cls.fixtures[name] = path
        cls.symbols = {}
        for name, path in cls.fixtures.items():
            output = subprocess.check_output(["nm", "-n", str(path)], text=True)
            cls.symbols[name] = {line.split()[2]: int(line.split()[0], 16) for line in output.splitlines() if len(line.split()) == 3}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, commands, fixture="loop", args=(), expected=0, batch=False):
        text = "\n".join(commands) + "\n"
        argv = [SDB]
        if batch:
            script = self.directory / "commands.sdb"
            script.write_text(text)
            argv += ["--batch", str(script)]
            text = ""
        if fixture:
            argv += ["--", str(self.fixtures.get(fixture, fixture))] + list(args)
        code, output = run_process(argv, text)
        self.assertEqual(code, expected, output)
        for diagnostic in ("AddressSanitizer:", "runtime error:", "LeakSanitizer:"):
            self.assertNotIn(diagnostic, output)
        return output

    def bp(self, symbol, fixture="loop"):
        return "break 0x{:x}".format(self.symbols[fixture][symbol])

    def assert_exit(self, output, status=0):
        self.assertIn("exited with status {}".format(status), output)

    def test_launch_continue_and_registers(self):
        output = self.session(["info reg", "cont"])
        self.assertIn("loaded. entry point:", output)
        self.assertIn("rip", output)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_single_step_through_exit_and_reload(self):
        output = self.session(["si", "si", "si", "load {}".format(self.fixtures["exit"]), "cont"], fixture="exit")
        self.assertEqual(output.count("exited with status 0"), 2, output)
        self.assertNotIn("No such process", output)

    def test_exit_during_breakpoint_step(self):
        output = self.session([self.bp("exit_call", "exit"), "cont", "si"], fixture="exit")
        self.assertIn("hit a breakpoint", output)
        self.assert_exit(output)
        self.assertNotIn("No such process", output)

    def test_ten_breakpoint_hits_at_exact_rip(self):
        commands = [self.bp("loop_body")]
        for _ in range(10):
            commands += ["cont", "info reg"]
        output = self.session(commands + ["cont"])
        hits = re.findall(r"hit a breakpoint at 0x([0-9a-fA-F]+)", output)
        self.assertEqual([int(x, 16) for x in hits], [self.symbols["loop"]["loop_body"]] * 10, output)
        registers = re.findall(r"\brip\s*(?:=|:)??\s*0x([0-9a-fA-F]+)", output)
        self.assertEqual([int(x, 16) for x in registers], [self.symbols["loop"]["loop_body"]] * 10, output)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_step_original_instruction_once(self):
        output = self.session([self.bp("loop_body"), "cont", "si"] + ["cont"] * 10)
        self.assertEqual(output.count("hit a breakpoint"), 10, output)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_two_breakpoints_delete_and_no_stale_ids(self):
        output = self.session([self.bp("loop_body"), self.bp("after_loop"), "cont", "delete 0", "cont", "delete 1", "cont", "info break", "load {}".format(self.fixtures["loop"]), self.bp("loop_body"), "delete 0", "cont"])
        self.assertEqual(output.count("hit a breakpoint"), 2, output)
        self.assertIn("no breakpoints", output.lower())
        self.assertEqual(output.count("LOOP=10"), 2, output)

    def test_duplicate_breakpoint_is_not_registered_twice(self):
        command = self.bp("loop_body")
        output = self.session([command, command, "info break", "delete 0", "cont"])
        self.assertIn("already exists", output)
        self.assertNotIn("hit a breakpoint", output)
        self.assertIn("LOOP=10", output)

    def test_zero_original_byte(self):
        output = self.session([self.bp("zero_site", "patch"), "cont", "delete 0", "cont"], fixture="patch")
        self.assertIn("hit a breakpoint", output)
        self.assert_exit(output)

    def test_patch_preserves_breakpoint_and_restores_new_byte(self):
        address = self.symbols["patch"]["patch_site"]
        output = self.session([self.bp("patch_site", "patch"), "patch {:x} 97".format(address), "cont", "delete 0", "cont"], fixture="patch")
        self.assertEqual(output.count("hit a breakpoint"), 1, output)
        self.assert_exit(output, 7)

    def test_invalid_patch_does_not_change_breakpoint_byte(self):
        address = self.symbols["patch"]["patch_site"]
        output = self.session([self.bp("patch_site", "patch"), "patch {:x} zz".format(address), "patch ffffffffffffffff 9090", "cont", "delete 0", "cont"], fixture="patch", expected=1, batch=True)
        self.assertIn("hit a breakpoint", output)
        self.assert_exit(output, 0)

    def test_symbol_breakpoints_pie_and_nonpie(self):
        for fixture in ("pie", "nonpie"):
            with self.subTest(fixture=fixture):
                output = self.session(["break main", "cont", "info reg", "si", "cont"], fixture=fixture)
                hit = re.search(r"hit a breakpoint at 0x([0-9a-fA-F]+)", output)
                self.assertIsNotNone(hit, output)
                if fixture == "nonpie":
                    self.assertEqual(int(hit.group(1), 16), self.symbols[fixture]["main"])
                else:
                    bias = re.search(r"load bias 0x([0-9a-fA-F]+)", output)
                    self.assertIsNotNone(bias, output)
                    self.assertEqual(int(hit.group(1), 16) - int(bias.group(1), 16), self.symbols[fixture]["main"])
                self.assertIn("VISITS=10", output)
                self.assert_exit(output)

    def test_pie_relocation_repeated_launch(self):
        addresses = set()
        for _ in range(3):
            output = self.session(["break tick"] + ["cont"] * 11, fixture="pie")
            self.assertEqual(output.count("hit a breakpoint"), 10, output)
            hit = re.search(r"hit a breakpoint at 0x([0-9a-fA-F]+)", output)
            addresses.add(int(hit.group(1), 16))
            self.assertIn("VISITS=10", output)
            self.assert_exit(output)
        if int(Path("/proc/sys/kernel/randomize_va_space").read_text()) > 0:
            self.assertGreater(len(addresses), 1, "ASLR is enabled, but PIE never relocated across three launches")

    def test_signal_forwarding_and_suppression(self):
        for command, count in (("cont", 1), ("cont 0", 0)):
            with self.subTest(command=command):
                output = self.session(["cont", command], fixture="nonpie", args=["usr1"])
                self.assertIn("stopped by signal SIGUSR1", output)
                self.assertIn("HANDLED={}".format(count), output)
                self.assertNotIn("syscall entry", output)
                self.assert_exit(output)

    def test_fatal_signals_are_not_syscalls(self):
        for mode, name in (("segv", "SIGSEGV"), ("ill", "SIGILL"), ("trap", "SIGTRAP"), ("int3", "SIGTRAP")):
            with self.subTest(signal=name):
                output = self.session(["cont", "cont"], fixture="nonpie", args=[mode])
                self.assertIn("stopped by signal " + name, output)
                self.assertIn("terminated by signal " + name, output)
                self.assertNotIn("hit a breakpoint", output)
                self.assertNotIn("syscall entry", output)

    def test_syscall_entry_exit(self):
        output = self.session(["syscall", "syscall", "syscall", "cont"])
        self.assertRegex(output, r"syscall entry (?:write[ (]+)?1\b")
        self.assertRegex(output, r"syscall exit (?:write[ (]+)?1\b.*= 8\b")
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_syscall_instruction_at_breakpoint(self):
        output = self.session([self.bp("write_call"), "cont", "syscall", "syscall", "cont"])
        self.assertIn("hit a breakpoint", output)
        self.assertIn("syscall entry 1 at rip", output)
        self.assertIn("syscall exit 1 = 8", output)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_signal_during_breakpoint_step_over(self):
        output = self.session(["break signal_call", "cont", "cont", "cont"], fixture="nonpie", args=["break-signal"])
        self.assertEqual(output.count("hit a breakpoint"), 1, output)
        self.assertIn("stopped by signal SIGUSR1", output)
        self.assertIn("HANDLED=1", output)
        self.assert_exit(output)

    def test_exec_clears_old_breakpoints(self):
        output = self.session(["break tick", "cont", "info break", "cont"], fixture="nonpie", args=["exec"])
        self.assertIn("exec:", output)
        self.assertIn("no breakpoints", output)
        self.assert_exit(output)

    def test_breakrva_uses_mapped_image_base(self):
        for fixture, symbol in (("loop", "loop_body"), ("pie", "main")):
            with self.subTest(fixture=fixture):
                headers = subprocess.check_output(["readelf", "-lW", str(self.fixtures[fixture])], text=True)
                bases = [int(line.split()[2], 16) for line in headers.splitlines() if line.strip().startswith("LOAD ")]
                self.assertTrue(bases, headers)
                offset = self.symbols[fixture][symbol] - (min(bases) & ~4095)
                output = self.session(["breakrva {:x}".format(offset), "cont", "delete 0", "cont"], fixture=fixture)
                self.assertEqual(output.count("hit a breakpoint"), 1, output)
                self.assertIn("LOOP=10" if fixture == "loop" else "VISITS=10", output)
                self.assert_exit(output)

    def test_program_arguments(self):
        output = self.session(["cont"], fixture="nonpie", args=["args", "hello world", "--flag"])
        self.assertIn("ARG[0]=hello world", output)
        self.assertIn("ARG[1]=--flag", output)

    def test_quoted_load_arguments_and_parser_recovery(self):
        path = self.directory / "program with spaces"
        path.symlink_to(self.fixtures["nonpie"])
        command = "load '{}' args \"two words\" '' '#literal' a\\ b # trailing comment".format(path)
        output = self.session(["load 'unfinished", command, "cont"], fixture=None, expected=1, batch=True)
        for index, argument in enumerate(("two words", "", "#literal", "a b")):
            self.assertIn("ARG[{}]={}\n".format(index, argument), output)
        self.assert_exit(output)

    def test_batch_file_and_stdin(self):
        output = self.session(["# repeatable session", "", "cont"], batch=True)
        self.assertIn("LOOP=10", output)
        self.assertNotIn("(sdb)", output)
        code, output = run_process([SDB, "--batch", "-", str(self.fixtures["exit"])], "cont\n")
        self.assertEqual(code, 0, output)
        self.assert_exit(output)

    def test_bad_commands_report_errors_and_continue(self):
        output = self.session(["break", "breakrva -1", "delete nope", "delete 9999999999999999999999999999", "patch", "patch 401000 9", "cont invalid-signal", "unknown", "cont"], expected=1, batch=True)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_invalid_launch_rollback_then_valid_load(self):
        invalid = self.directory / "not-an-elf"
        invalid.write_text("not ELF\n")
        empty = self.directory / "empty"
        empty.write_bytes(b"")
        denied = self.directory / "not-executable"
        shutil.copyfile(self.fixtures["exit"], denied)
        denied.chmod(0o600)
        bad_magic = self.directory / "truncated-elf"
        bad_magic.write_bytes(b"\x7fELF" + b"\0" * 20)
        commands = ["load {}".format(path) for path in (self.directory / "missing", invalid, empty, denied, bad_magic)]
        commands += ["load {}".format(self.fixtures["exit"]), "cont"]
        output = self.session(commands, fixture=None, expected=1, batch=True)
        self.assertEqual(output.count("loaded. entry point:"), 1, output)
        self.assert_exit(output)

    def test_stripped_symbol_error_keeps_debugger_usable(self):
        path = self.directory / "stripped"
        shutil.copyfile(self.fixtures["nonpie"], path)
        path.chmod(0o755)
        subprocess.run(["strip", "--strip-all", str(path)], check=True)
        output = self.session(["break main", "cont"], fixture=str(path), expected=1, batch=True)
        self.assertIn("symbol", output.lower())
        self.assertIn("VISITS=10", output)

    def test_malformed_elf_metadata_is_rejected(self):
        original = self.fixtures["exit"].read_bytes()
        mutations = {"class": (4, b"\x01"), "endianness": (5, b"\x02"),
                     "machine": (18, b"\xb7\x00"), "program-table": (32, b"\xff" * 8)}
        for name, (offset, replacement) in mutations.items():
            with self.subTest(name=name):
                data = bytearray(original)
                data[offset:offset + len(replacement)] = replacement
                path = self.directory / ("bad-" + name)
                path.write_bytes(data)
                path.chmod(0o755)
                output = self.session(["load {}".format(path), "load {}".format(self.fixtures["exit"]), "cont"], fixture=None, expected=1, batch=True)
                self.assertEqual(output.count("loaded. entry point:"), 1, output)
                self.assert_exit(output)

    def test_noncode_and_unknown_symbols_are_rejected(self):
        output = self.session(["break visits", "break printf", "break definitely_missing", "cont"], fixture="nonpie", expected=1, batch=True)
        self.assertNotIn("hit a breakpoint", output)
        self.assertIn("VISITS=10", output)
        self.assert_exit(output)

    def test_disassembly_at_executable_mapping_boundary(self):
        address = self.symbols["boundary"]["boundary_site"]
        output = self.session(["disasm {:x}".format(address), "cont"], fixture="boundary")
        self.assertRegex(output, r"{:x}:.*\bret\b".format(address))
        self.assert_exit(output)

    def test_address_errors_are_recoverable(self):
        output = self.session(["break 0", "break ffffffffffffffff", "disasm 0", "cont"], expected=1, batch=True)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_repeated_breakpoint_add_delete(self):
        commands = []
        for number in range(150):
            commands += [self.bp("loop_body"), "delete {}".format(number)]
        output = self.session(commands + ["cont"])
        self.assertNotIn("hit a breakpoint", output)
        self.assertIn("LOOP=10", output)
        self.assert_exit(output)

    def test_eof_reaps_stopped_child(self):
        proc = subprocess.Popen([SDB, str(self.fixtures["loop"])], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                start_new_session=True)
        children = []
        try:
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                path = Path("/proc/{}/task/{}/children".format(proc.pid, proc.pid))
                if path.exists():
                    children = path.read_text().split()
                if children:
                    break
                self.assertIsNone(proc.poll(), "debugger exited before creating tracee")
                time.sleep(0.01)
            self.assertTrue(children, "debugger never created tracee")
            output, _ = proc.communicate("", timeout=TIMEOUT)
            self.assertEqual(proc.returncode, 0, output)
            for child in children:
                self.assertFalse(Path("/proc/" + child).exists(), "EOF left tracee {} behind".format(child))
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    stream.close()

    def test_external_sigkill_is_reaped_before_next_command(self):
        for next_command in ("cont\n", ""):
            with self.subTest(next_command=next_command or "load"), tempfile.TemporaryFile(mode="w+") as log:
                proc = subprocess.Popen([SDB, str(self.fixtures["exit"])], stdin=subprocess.PIPE,
                                        stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
                try:
                    deadline = time.monotonic() + TIMEOUT
                    child = None
                    while time.monotonic() < deadline:
                        output = read_log(log)
                        # Wait for the delimiter: a partial write must never be
                        # interpreted as a shorter PID and used as a kill target.
                        match = re.search(r"tracee pid (\d+), load bias", output)
                        if match:
                            child = int(match.group(1))
                            break
                        self.assertIsNone(proc.poll(), output)
                        time.sleep(0.01)
                    self.assertIsNotNone(child, "tracee PID was not reported")
                    proc.stdin.write("info break\n")
                    proc.stdin.flush()
                    while time.monotonic() < deadline:
                        if "no breakpoints" in read_log(log):
                            break
                        time.sleep(0.01)
                    else:
                        self.fail("debugger did not reach its command loop")
                    children_path = Path("/proc/{}/task/{}/children".format(proc.pid, proc.pid))
                    self.assertGreater(child, 1)
                    self.assertIn(str(child), children_path.read_text().split(),
                                  "refusing to signal a PID not owned by this debugger")
                    self.assertEqual(os.getpgid(child), proc.pid,
                                     "tracee must belong to this isolated test process group")
                    os.kill(child, signal.SIGKILL)
                    # TRACEEXIT holds even a killed task in a ptrace stop until
                    # the tracer consumes that event. Drive the command loop;
                    # waiting for Z here deadlocks the very cleanup under test.
                    commands = next_command + "load {}\ncont\n".format(self.fixtures["exit"])
                    proc.communicate(commands, timeout=TIMEOUT)
                    output = read_log(log)
                    self.assertEqual(proc.returncode, 0, output)
                    self.assertIn("terminated by signal SIGKILL", output)
                    self.assertEqual(output.count("loaded. entry point:"), 2, output)
                    self.assertNotIn("already loaded", output)
                    self.assertNotIn("No such process", output)
                    self.assert_exit(output)
                    self.assertFalse(Path("/proc/{}".format(child)).exists(),
                                     "externally killed tracee was not reaped")
                finally:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                    if proc.stdin is not None:
                        proc.stdin.close()

    def test_breakpoint_and_disassembly_file_descriptors_do_not_grow(self):
        with tempfile.TemporaryFile(mode="w+") as log:
            proc = subprocess.Popen([SDB, str(self.fixtures["loop"])], stdin=subprocess.PIPE,
                                    stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            def wait_for(marker):
                deadline = time.monotonic() + TIMEOUT
                while time.monotonic() < deadline:
                    output = read_log(log)
                    if marker in output:
                        return output
                    self.assertIsNone(proc.poll(), output)
                    time.sleep(0.01)
                self.fail("timed out waiting for debugger output: " + marker)
            try:
                wait_for("loaded. entry point:")
                descriptors = Path("/proc/{}/fd".format(proc.pid))
                before = len(list(descriptors.iterdir()))
                commands = []
                for number in range(150):
                    commands += [self.bp("loop_body"), "disasm", "delete {}".format(number)]
                commands += ["info break"]
                proc.stdin.write("\n".join(commands) + "\n")
                proc.stdin.flush()
                wait_for("no breakpoints")
                after = len(list(descriptors.iterdir()))
                self.assertLessEqual(after, before + 1, "FD count grew from {} to {}".format(before, after))
                proc.communicate("q\n", timeout=TIMEOUT)
                self.assertEqual(proc.returncode, 0)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                if proc.stdin is not None:
                    proc.stdin.close()

    def test_cli_usage_errors(self):
        for arguments in (["--batch"], ["--batch", str(self.directory / "missing-script")], ["--unknown"]):
            with self.subTest(arguments=arguments):
                code, output = run_process([SDB] + arguments)
                self.assertNotEqual(code, 0, output)


if __name__ == "__main__":
    if not probe_ptrace():
        sys.exit(77)
    unittest.main(verbosity=2)
