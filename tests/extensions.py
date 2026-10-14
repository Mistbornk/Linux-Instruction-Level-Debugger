#!/usr/bin/env python3
"""Feature acceptance against actual Linux tasks, registers, traps and memory.

All targets are isolated children owned by this test. Attach fixtures explicitly
permit sibling tracing; the suite never alters Yama, seccomp or host settings.
Only the independent ptrace environment probe can skip this suite. The native
combined TF/watchpoint case is explicitly skipped on QEMU TCG, where separate
tests verify safe rejection and recovery instead; the CI summary records it.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
SDB = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "./sdb").resolve())
TIMEOUT = int(os.environ.get("SDB_TEST_TIMEOUT", "30"))
TCG_GUARD_ERROR = "QEMU TCG cannot safely combine single-step and hardware watchpoints"


def probe_ptrace():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        print("SKIP: extensions require Linux x86-64", flush=True)
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if not pid:
        result = libc.ptrace(0, 0, None, None)
        os._exit(ctypes.get_errno() if result == -1 else 0)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status):
        raise RuntimeError("ptrace probe did not exit normally")
    code = os.WEXITSTATUS(status)
    if code in (errno.EPERM, errno.EACCES, errno.ENOSYS):
        print("SKIP: independent ptrace probe: " + os.strerror(code), flush=True)
        return False
    if code:
        raise OSError(code, "ptrace probe")
    return True


def output(log):
    return os.pread(log.fileno(), os.fstat(log.fileno()).st_size, 0).decode()


class Live:
    """File-backed stdout cannot deadlock a stopped debugger on a full pipe."""
    def __init__(self, argv, env=None):
        self.log = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=self.log,
                                     stderr=subprocess.STDOUT, text=True, start_new_session=True,
                                     env=None if env is None else dict(os.environ, **env))

    def wait(self, condition):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            text = output(self.log)
            if condition(text):
                return text
            if self.proc.poll() is not None:
                raise AssertionError("process exited before expected output:\n" + text)
            time.sleep(0.01)
        raise AssertionError("process timed out:\n" + output(self.log))

    def command(self, command):
        before = output(self.log)
        fences = before.count("load <program>")
        self.proc.stdin.write(command + "\nhelp\n")
        self.proc.stdin.flush()
        text = self.wait(lambda s: s.count("load <program>") > fences)
        # The fence begins after the requested command has completed, but help
        # itself may still be flushing. The next fence count is unambiguous.
        return text[len(before):]

    def finish(self, commands="q\n", expected=0):
        self.proc.communicate(commands, timeout=TIMEOUT)
        text = output(self.log)
        if self.proc.returncode != expected:
            raise AssertionError("exit {} != {}:\n{}".format(self.proc.returncode, expected, text))
        for diagnostic in ("AddressSanitizer:", "runtime error:", "LeakSanitizer:"):
            if diagnostic in text:
                raise AssertionError(text)
        return text

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()
        if self.proc.stdin:
            self.proc.stdin.close()
        self.log.close()


class Extensions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sdb-extensions-")
        cls.directory = Path(cls.temp.name)
        cls.targets = {}
        cls.symbols = {}
        for name, flags in (("exec", ["-fno-pie", "-no-pie"]), ("pie", ["-fPIE", "-pie"])):
            path = cls.directory / name
            subprocess.run(["gcc", "-O0", "-g", "-fno-omit-frame-pointer", "-pthread"] + flags +
                           [str(ROOT / "fixtures/ext_features.c"), "-o", str(path)], check=True)
            cls.targets[name] = path
            lines = subprocess.check_output(["nm", "-n", str(path)], text=True).splitlines()
            cls.symbols[name] = {s[2]: int(s[0], 16) for line in lines if len(s := line.split()) == 3}
        cls.dr_probe = cls.directory / "debug-registers"
        subprocess.run(["gcc", "-Wall", "-Wextra", str(ROOT / "fixtures/ext_debug_registers.c"),
                        "-o", str(cls.dr_probe)], check=True)
        cls.blocking_target = cls.directory / "blocking-syscall"
        subprocess.run(["gcc", "-Wall", "-Wextra", "-O0", "-g", "-fno-pie", "-no-pie", "-pthread",
                        str(ROOT / "fixtures/ext_blocking.c"), "-o", str(cls.blocking_target)], check=True)
        with Live([SDB]) as live:
            environment = live.command("info environment")
            cls.tcg_guard = "watchpoint single-step: unavailable (QEMU TCG)" in environment
            if not cls.tcg_guard and "watchpoint single-step: enabled" not in environment:
                raise AssertionError("unknown watchpoint stepping capability:\n" + environment)
            live.finish()
        print("COVERAGE: native TF/watchpoint execution {}".format(
            "unavailable on QEMU TCG; explicit guard/recovery tests apply" if cls.tcg_guard else "enabled"), flush=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, commands, mode="memory", fixture="exec", expected=0):
        with Live([SDB, "--batch", "-", str(self.targets[fixture]), mode]) as live:
            return live.finish("\n".join(commands) + "\n", expected)

    def read_register(self, live, name):
        text = live.command("register read " + name)
        match = re.search(r"\$?" + re.escape(name) + r"\s+(?:=\s*)?0x([0-9a-f]+)", text)
        self.assertIsNotNone(match, text)
        return int(match.group(1), 16)

    def physical_byte(self, live, address):
        # Read only our own stopped fixture. Unlike x, this intentionally sees
        # the physical INT3 instead of the debugger's logical original-byte view.
        match = re.search(r"tracee pid (\d+), load bias", output(live.log))
        self.assertIsNotNone(match, output(live.log))
        pid = int(match.group(1))
        children = Path("/proc/{}/task/{}/children".format(live.proc.pid, live.proc.pid))
        self.assertIn(str(pid), children.read_text().split())
        fd = os.open("/proc/{}/mem".format(pid), os.O_RDONLY | os.O_CLOEXEC)
        try:
            return os.pread(fd, 1, address)
        finally:
            os.close(fd)

    def test_named_register_read_write_and_value_validation(self):
        text = self.session(["register write rax 123", "register read rax",
                             "register write r12 0xffffffffffffffff", "register read r12",
                             "register write unknown 1", "register write rax -1",
                             "register write rax 18446744073709551616", "register read rax"], expected=1)
        self.assertRegex(text, r"rax\s+(?:=\s*)?0x0*7b\b")
        self.assertRegex(text, r"r12\s+(?:=\s*)?0xffffffffffffffff\b")
        self.assertEqual(len(re.findall(r"rax\s+(?:=\s*)?0x0*7b\b", text)), 2, text)
        self.assertEqual(text.count("** error:"), 3, text)

    def test_memory_read_write_pie_and_nonpie(self):
        for fixture in self.targets:
            with self.subTest(fixture=fixture):
                text = self.session(["break ready", "cont", "write @watched 2a00000000000000",
                                     "x/8 @watched", "cont"], fixture=fixture)
                self.assertRegex(text, r"2a(?:\s+00){7}")
                self.assertIn("VALUE=42", text)
                self.assertIn("exited with status 0", text)

    def test_memory_bounds_and_executable_write_rejection(self):
        address = self.symbols["exec"]["ready"]
        text = self.session(["write 0x{:x} 90".format(address), "x/0 @watched",
                             "x/999999999999999999999 1", "x/4 ffffffffffffffff",
                             "write 0 01", "write @watched xyz", "cont"], expected=1)
        self.assertEqual(text.count("** error:"), 6, text)
        self.assertIn("VALUE=0", text)
        self.assertIn("exited with status 0", text)

    def test_write_watchpoint_reports_real_post_instruction_rip(self):
        text = self.session(["watch @watched 8", "cont", "register read rip", "cont",
                             "delete watch 0", "cont"], mode="watch")
        self.assertEqual(text.count("watchpoint 0 hit"), 2, text)
        rips = re.findall(r"\$?rip\s+(?:=\s*)?0x([0-9a-f]+)", text)
        self.assertEqual(int(rips[0], 16), self.symbols["exec"]["after_first_write"], text)
        self.assertIn("WATCHED=12", text)
        self.assertIn("exited with status 0", text)

    def test_watchpoint_during_software_breakpoint_step_over(self):
        if self.tcg_guard:
            self.skipTest("native TF/watchpoint execution unavailable on QEMU TCG; guard/recovery tested separately")
        for command in ("cont", "si"):
            with self.subTest(command=command):
                with Live([SDB, str(self.targets["exec"]), "watch"]) as live:
                    live.command("watch @watched 8")
                    live.command("break watched_store")
                    self.assertIn("hit a breakpoint", live.command("cont"))
                    stepped = live.command(command)
                    self.assertIn("watchpoint 0 hit", stepped)
                    location = live.command("register read rip")
                    rip = re.search(r"rip\s+(?:=\s*)?0x([0-9a-f]+)", location)
                    self.assertEqual(int(rip.group(1), 16), self.symbols["exec"]["after_first_write"], location)
                    self.assertIn("watchpoint 0 hit", live.command("cont"))
                    live.command("delete watch 0")
                    self.assertIn("exited with status 0", live.command("cont"))
                    self.assertIn("WATCHED=12", live.finish())

    def test_tcg_guard_preserves_software_breakpoint_and_allows_recovery(self):
        for command in ("cont", "si"):
            with self.subTest(command=command):
                with Live([SDB, str(self.targets["exec"]), "watch"], env={"SDB_TCG_GUARD": "1"}) as live:
                    self.assertIn("unavailable (QEMU TCG)", live.command("info environment"))
                    live.command("watch @watched 8")
                    live.command("break watched_store")
                    self.assertIn("hit a breakpoint", live.command("cont"))
                    before = self.read_register(live, "rip")
                    self.assertEqual(before, self.symbols["exec"]["watched_store"])
                    self.assertEqual(self.physical_byte(live, before), b"\xcc")
                    refused = live.command(command)
                    self.assertIn(TCG_GUARD_ERROR, refused)
                    self.assertEqual(self.read_register(live, "rip"), before)
                    self.assertEqual(self.physical_byte(live, before), b"\xcc")
                    self.assertRegex(live.command("info watch"), r"(?m)^0\s+0x[0-9a-f]+\s+8\s+write")
                    live.command("delete watch 0")
                    self.assertIn("single-step stop", live.command("si"))
                    self.assertEqual(self.read_register(live, "rip"), self.symbols["exec"]["after_first_write"])
                    self.assertIn("exited with status 0", live.command("cont"))
                    self.assertIn("WATCHED=12", live.finish(expected=1))

    def test_tcg_guard_rejects_direct_single_step_with_watchpoint(self):
        with Live([SDB, str(self.targets["exec"]), "memory"], env={"SDB_TCG_GUARD": "1"}) as live:
            live.command("watch @watched 8")
            before = self.read_register(live, "rip")
            self.assertIn(TCG_GUARD_ERROR, live.command("si"))
            self.assertEqual(self.read_register(live, "rip"), before)
            live.command("delete watch 0")
            self.assertIn("single-step stop", live.command("si"))
            self.assertNotEqual(self.read_register(live, "rip"), before)
            self.assertIn("exited with status 0", live.command("cont"))
            live.finish(expected=1)

    def test_tcg_guard_rejects_manual_trap_flag_on_continue(self):
        with Live([SDB, str(self.targets["exec"]), "memory"], env={"SDB_TCG_GUARD": "1"}) as live:
            live.command("watch @watched 8")
            before = self.read_register(live, "rip")
            flags = self.read_register(live, "eflags")
            self.assertEqual(flags & 0x100, 0)
            live.command("register write eflags 0x{:x}".format(flags | 0x100))
            self.assertIn(TCG_GUARD_ERROR, live.command("cont"))
            self.assertEqual(self.read_register(live, "rip"), before)
            self.assertEqual(self.read_register(live, "eflags") & 0x100, 0x100)
            live.command("register write eflags 0x{:x}".format(flags))
            live.command("delete watch 0")
            self.assertIn("exited with status 0", live.command("cont"))
            live.finish(expected=1)

    def test_tcg_guard_checks_peer_flags_before_resuming_any_task(self):
        with self.attached_target(multiple=True) as target:
            with Live([SDB], env={"SDB_TCG_GUARD": "1"}) as live:
                live.command("attach {}".format(target.proc.pid))
                live.command("watch @watched 8")
                listing = live.command("info threads")
                tids = [int(x) for x in re.findall(r"^[ *]*(\d+)\s+stopped\b", listing, re.M)]
                self.assertEqual(len(tids), 2, listing)
                before = {}
                for tid in tids:
                    live.command("thread {}".format(tid))
                    before[tid] = self.read_register(live, "rip")
                flags = self.read_register(live, "eflags")
                self.assertEqual(flags & 0x100, 0)
                live.command("register write eflags 0x{:x}".format(flags | 0x100))
                live.command("thread {}".format(tids[0]))
                self.assertIn(TCG_GUARD_ERROR, live.command("cont"))
                for tid in tids:
                    live.command("thread {}".format(tid))
                    self.assertEqual(self.read_register(live, "rip"), before[tid])
                    self.assertRegex(Path("/proc/{}/status".format(tid)).read_text(), r"State:\s+t\b")
                live.command("register write eflags 0x{:x}".format(flags))
                live.command("delete watch 0")
                live.command("detach")
                live.finish(expected=1)
            os.kill(target.proc.pid, signal.SIGUSR1)
            self.assertIn("ATTACH_DONE=", target.finish(""))

    def test_access_watchpoint_observes_reads_and_writes(self):
        with Live([SDB, str(self.targets["pie"]), "watch"]) as live:
            live.command("awatch @watched 8")
            for _ in range(12):
                text = live.command("cont")
                if "exited with status" in text:
                    break
            else:
                self.fail("access watchpoint did not allow target to finish")
            text = live.finish()
            # Two writes, the explicitly loaded value, and printf's final read.
            self.assertEqual(text.count("watchpoint 0 hit"), 4, text)
            self.assertIn("WATCHED=12", text)

    def test_watchpoint_slots_alignment_mode_and_delete(self):
        address = self.symbols["exec"]["watched"]
        commands = ["watch {:x} 8".format(address + 1), "watch {:x} 3".format(address),
                    "rwatch @watched 8"]
        commands += ["watch {:x} 8".format(address + i * 8) for i in range(4)]
        commands += ["watch {:x} 8".format(address + 32), "info watch",
                     "delete watch 1", "watch {:x} 8".format(address + 32), "cont"]
        text = self.session(commands, expected=1)
        self.assertEqual(text.count("** error:"), 4, text)
        self.assertIn("align", text.lower())
        self.assertRegex(text.lower(), r"read.only|read only")
        self.assertIn("exited with status 0", text)

    def test_watchpoint_each_hardware_length(self):
        for size in (1, 2, 4, 8):
            with self.subTest(size=size):
                text = self.session(["watch @watched {}".format(size), "cont", "delete watch 0", "cont"],
                                    mode="watch")
                self.assertEqual(text.count("watchpoint 0 hit"), 1, text)
                self.assertIn("WATCHED=12", text)

    def test_backtrace_nested_frames_and_corrupt_chain(self):
        for fixture in self.targets:
            with self.subTest(fixture=fixture):
                text = self.session(["break bt_site", "cont", "bt", "register write rbp 1", "bt"],
                                    mode="backtrace", fixture=fixture)
                frames = re.findall(r"^#\d+.*", text, re.M)
                self.assertGreaterEqual(len(frames), 5, text)
                # The exact interior assembler label is more precise than its
                # containing bt_leaf function at frame zero.
                for name in ("bt_site", "bt_middle", "bt_outer", "main"):
                    self.assertTrue(any(name in frame for frame in frames), text)
                self.assertRegex(text.lower(), r"(unaligned|invalid|unreadable|outside|stop)")

    def test_restart_clears_old_addresses_and_relocates_symbols(self):
        text = self.session(["break ready", "cont", "restart", "info break", "break ready", "cont", "cont"], fixture="pie")
        self.assertEqual(text.count("hit a breakpoint"), 2, text)
        self.assertEqual(text.count("loaded. entry point:"), 2, text)
        self.assertIn("no breakpoints", text)
        self.assertIn("VALUE=0", text)

    def test_syscall_names_arguments_and_bad_pointer_are_bounded(self):
        with Live([SDB, str(self.targets["exec"]), "syscalls"]) as live:
            live.command("break ready")
            live.command("cont")
            for _ in range(40):
                text = live.command("syscall")
                if "exited with status" in text:
                    break
            else:
                self.fail("syscall fixture did not finish")
            text = live.finish()
            self.assertIn("openat", text)
            self.assertIn("/dev/null", text)
            self.assertIn("write", text)
            self.assertIn("hello", text)
            self.assertRegex(text, r"-14\b|EFAULT")
            self.assertIn("SYSCALLS_DONE", text)

    def test_history_and_optional_automatic_disassembly(self):
        with Live([SDB, str(self.targets["exec"]), "memory"]) as live:
            live.command("set disassemble off")
            quiet = live.command("si")
            self.assertNotIn("=>", quiet)
            explicit = live.command("disasm")
            self.assertIn("=>", explicit)
            live.command("set disassemble on")
            shown = live.command("si")
            self.assertIn("=>", shown)
            history = live.command("history")
            self.assertIn("set disassemble off", history)
            self.assertIn("disasm", history)
            live.finish()

    def test_threads_shared_breakpoints_all_stop_and_signals(self):
        with Live([SDB, str(self.targets["exec"]), "threads"]) as live:
            live.command("break shared_site")
            observed_multiple = False
            tested_selection = False
            for _ in range(80):
                result = live.command("cont")
                if "exited with status" in result:
                    break
                listing = live.command("info threads")
                tids = [int(x) for x in re.findall(r"^[ *]*(\d+)\s+stopped\b", listing, re.M)]
                if len(tids) > 1:
                    observed_multiple = True
                    for tid in tids:
                        state = Path("/proc/{}/status".format(tid)).read_text()
                        self.assertRegex(state, r"State:\s+t\b", state)
                    if not tested_selection:
                        live.command("thread {}".format(tids[-1]))
                        selected = live.command("register read rip")
                        self.assertRegex(selected, r"rip\s+(?:=\s*)?0x[0-9a-f]+")
                        live.command("thread {}".format(tids[0]))
                        tested_selection = True
            else:
                self.fail("threaded fixture did not finish")
            text = live.finish()
            self.assertTrue(observed_multiple, text)
            self.assertTrue(tested_selection, text)
            self.assertEqual(text.count("hit a breakpoint"), 12, text)
            self.assertIn("THREAD_VISITS=12 HANDLED=1", text)
            self.assertIn("SIGUSR2", text)
            self.assertNotIn("** error:", text)

    def attached_target(self, multiple=False):
        target = Live([str(self.targets["exec"]), "attach"] + (["threads"] if multiple else []))
        try:
            text = target.wait(lambda s: "ATTACH_READY={}\n".format(target.proc.pid) in s)
            self.assertIn("ATTACH_READY", text)
            return target
        except BaseException:
            target.__exit__()
            raise

    def test_watchpoint_is_installed_for_new_threads(self):
        with Live([SDB, str(self.targets["exec"]), "threads"]) as live:
            live.command("watch @watched 8")
            for _ in range(60):
                text = live.command("cont")
                if "exited with status" in text:
                    break
            else:
                self.fail("thread watchpoint fixture did not finish")
            text = live.finish()
            self.assertEqual(text.count("watchpoint 0 hit"), 6, text)
            self.assertIn("THREAD_VISITS=12 HANDLED=1", text)

    def test_continue_from_blocking_syscall_breakpoint_runs_waking_peer(self):
        with Live([SDB, str(self.blocking_target)]) as live:
            live.command("break futex_wait_call")
            for _ in range(10):
                if "hit a breakpoint" in live.command("cont"):
                    break
            else:
                self.fail("worker never reached its raw futex instruction")
            live.command("write @wake_allowed 01000000")
            for _ in range(10):
                if "exited with status" in live.command("cont"):
                    break
            else:
                self.fail("continue did not release the waking peer")
            text = live.finish()
            self.assertIn("BLOCKING_SYSCALL_DONE", text)
            self.assertIn("exited with status 0", text)

    def test_attach_detach_restores_code_and_hardware_registers(self):
        with self.attached_target() as target:
            before = subprocess.check_output([str(self.dr_probe), str(target.proc.pid)], text=True)
            with Live([SDB]) as live:
                attached = live.command("attach {}".format(target.proc.pid))
                self.assertIn("attached to process", attached)
                live.command("break shared_site")
                live.command("watch @watched 8")
                hit = live.command("cont")
                self.assertIn("hit a breakpoint", hit)
                self.assertIn("detached", live.command("detach"))
                live.finish()
            after = subprocess.check_output([str(self.dr_probe), str(target.proc.pid)], text=True)
            self.assertEqual(before, after, "detach changed debug registers")
            # Returning from the interrupted function and calling it repeatedly
            # proves neither a stale INT3 nor an uncorrected RIP survived detach.
            os.kill(target.proc.pid, signal.SIGUSR1)
            text = target.finish("", 0)
            self.assertRegex(text, r"ATTACH_DONE=[1-9]\d*")

    def test_attach_existing_thread_group_and_eof_detach(self):
        with self.attached_target(multiple=True) as target:
            with Live([SDB]) as live:
                live.command("attach {}".format(target.proc.pid))
                listing = live.command("info threads")
                tids = re.findall(r"^[ *]*(\d+)\s+stopped\b", listing, re.M)
                self.assertEqual(len(tids), 2, listing)
                live.command("break shared_site")
                live.finish("")
            self.assertIsNone(target.proc.poll())
            os.kill(target.proc.pid, signal.SIGUSR1)
            self.assertIn("ATTACH_DONE=", target.finish(""))

    def test_invalid_attach_recovers_without_loaded_program(self):
        with Live([SDB]) as live:
            for value in ("-1", "0", "999999999999999999999999", "2147483647"):
                self.assertIn("** error:", live.command("attach " + value))
            live.command("load {} memory".format(self.targets["exec"]))
            live.command("cont")
            text = live.finish(expected=1)
            self.assertIn("VALUE=0", text)

    def test_unsupported_fork_restores_parent_and_child_before_detach(self):
        libc = ctypes.CDLL(None, use_errno=True)
        original = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(original), 0, 0, 0) == -1:  # PR_GET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "get child subreaper")
        if libc.prctl(36, 1, 0, 0, 0) == -1:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "set child subreaper")
        adopted = None

        def reap_known_child(pid):
            deadline = time.monotonic() + TIMEOUT
            forced = False
            while True:
                try:
                    child, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    # SDB may have reaped it itself on an earlier failure. Do
                    # not signal a PID for which this process has no ownership.
                    return
                if child == pid:
                    if forced:
                        self.fail("detached fixture needed SIGKILL before it could be reaped")
                    return
                if time.monotonic() >= deadline:
                    if forced:
                        self.fail("timed out reaping known detached fixture {}".format(pid))
                    # waitpid just proved this is our live child. Without an
                    # intervening reap its PID cannot be recycled into a peer.
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    forced = True
                    deadline = time.monotonic() + 1
                time.sleep(0.01)

        try:
            with Live([SDB, str(self.targets["exec"]), "fork"]) as live:
                live.command("break shared_site")
                match = re.search(r"tracee pid (\d+), load bias", output(live.log))
                self.assertIsNotNone(match, output(live.log))
                adopted = int(match.group(1))
                children = Path("/proc/{}/task/{}/children".format(live.proc.pid, live.proc.pid))
                self.assertIn(str(adopted), children.read_text().split())
                live.command("watch @watched 8")
                result = live.command("cont")
                self.assertIn("** error:", result)
                self.assertIn("detached all", result)
                # Both address spaces inherited the installed INT3; both execute
                # that function and write the watched value after automatic detach.
                live.wait(lambda s: "FORK_CHILD_OK" in s and "FORK_PARENT_OK" in s)
                text = live.finish(expected=1)
                self.assertNotIn("hit a breakpoint", text)
                self.assertNotIn("watchpoint 0 hit", text)
                # Reap before Live's process-group cleanup, so ordinary success
                # lets the detached parent finish naturally rather than killing it.
                reap_known_child(adopted)
                adopted = None
        finally:
            try:
                if adopted is not None:
                    reap_known_child(adopted)
            finally:
                if libc.prctl(36, original.value, 0, 0, 0) == -1:
                    raise OSError(ctypes.get_errno(), "restore child subreaper")


if __name__ == "__main__":
    if not probe_ptrace():
        sys.exit(77)
    unittest.main(verbosity=2)
