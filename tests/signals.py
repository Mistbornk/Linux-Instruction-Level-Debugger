#!/usr/bin/env python3
"""Exercise debugger control signals with owned children and a real terminal."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

# Shared harness intentionally consumes the SDB-path argument once.
from extensions import Live, ROOT, SDB, TIMEOUT, probe_ptrace


def wait_for(condition, description):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("timed out: " + description)


def task_state(pid):
    text = Path("/proc/{}/status".format(pid)).read_text()
    return re.search(r"^State:\s+(\S)", text, re.MULTILINE).group(1)


def physical_byte(pid, address):
    fd = os.open("/proc/{}/mem".format(pid), os.O_RDONLY)
    try:
        value = os.pread(fd, 1, address)
        if len(value) != 1:
            raise AssertionError("short read of fixture code")
        return value
    finally:
        os.close(fd)


class Terminal:
    """A controlling PTY sends Ctrl-C to the actual foreground process group."""
    def __init__(self, argv, ready=None):
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            try:
                os.execv(argv[0], argv)
            except BaseException:
                os._exit(127)
        self.text = ""
        self.status = None
        self.ready = ready or (lambda text: "(sdb) " in text)

    def pump(self):
        if select.select([self.master], [], [], 0.05)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            self.text += data.decode(errors="replace").replace("\r", "")
        if self.status is None:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited:
                self.status = status

    def wait(self, condition):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            self.pump()
            if condition(self.text):
                return self.text
            if self.status is not None:
                raise AssertionError("terminal debugger exited early:\n" + self.text)
        raise AssertionError("terminal debugger timed out:\n" + self.text)

    def send(self, text):
        data = text.encode()
        while data:
            written = os.write(self.master, data)
            if written == 0:
                raise AssertionError("PTY write made no progress")
            data = data[written:]

    def command(self, command):
        before = len(self.text)
        prompts = self.text.count("(sdb) ")
        self.send(command + "\n")
        self.wait(lambda text: text.count("(sdb) ") > prompts)
        return self.text[before:]

    def finish(self, command="q\n"):
        if command is not None:
            self.send(command)
        deadline = time.monotonic() + TIMEOUT
        while self.status is None and time.monotonic() < deadline:
            self.pump()
        if self.status is None:
            raise AssertionError("terminal debugger did not quit:\n" + self.text)
        self.pump()
        if not os.WIFEXITED(self.status) or os.WEXITSTATUS(self.status) != 0:
            raise AssertionError("terminal debugger failed:\n" + self.text)
        return self.text

    def __enter__(self):
        try:
            self.wait(self.ready)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if self.status is None:
            _, self.status = os.waitpid(self.pid, 0)
        os.close(self.master)


class ControlSignals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sdb-signals-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.target = cls.directory / "signal-target"
        subprocess.run(["gcc", "-Wall", "-Wextra", "-O0", "-g", "-fno-pie", "-no-pie",
                        "-pthread", str(ROOT / "fixtures/signal_target.c"), "-o", str(cls.target)],
                       check=True)
        cls.probe = cls.directory / "debug-registers"
        subprocess.run(["gcc", "-Wall", "-Wextra", str(ROOT / "fixtures/ext_debug_registers.c"),
                        "-o", str(cls.probe)], check=True)
        symbols = subprocess.check_output(["nm", "-n", str(cls.target)], text=True)
        cls.symbols = {fields[2]: int(fields[0], 16) for line in symbols.splitlines()
                       if len(fields := line.split()) == 3}

    def debug_registers(self, pid):
        return subprocess.check_output([str(self.probe), str(pid)], text=True, timeout=TIMEOUT)

    def signal_exit(self, debugger, requested):
        os.kill(debugger.proc.pid, requested)
        debugger.proc.wait(timeout=TIMEOUT)
        text = debugger.finish("", expected=128 + requested)
        self.assertNotIn("** error:", text)
        return text

    def test_term_and_hup_restore_attached_target_at_prompt_and_while_running(self):
        for requested in (signal.SIGTERM, signal.SIGHUP):
            for running in (False, True):
                with self.subTest(signal=requested, running=running):
                    with Live([str(self.target)]) as target:
                        target.wait(lambda text: "SIGNAL_READY=" in text)
                        original_code = physical_byte(target.proc.pid, self.symbols["cleanup_site"])
                        original_debug = self.debug_registers(target.proc.pid)
                        with Live([SDB]) as debugger:
                            self.assertIn("attached to process", debugger.command(
                                "attach {}".format(target.proc.pid)))
                            debugger.command("break cleanup_site")
                            debugger.command("watch @watched 8")
                            self.assertEqual(physical_byte(target.proc.pid,
                                                           self.symbols["cleanup_site"]), b"\xcc")
                            self.assertRegex(debugger.command("info watch"),
                                             r"(?m)^0\s+0x[0-9a-f]+\s+8\s+write")
                            if running:
                                debugger.proc.stdin.write("cont\n")
                                debugger.proc.stdin.flush()
                                wait_for(lambda: task_state(target.proc.pid) not in ("t", "T"),
                                         "attached target to resume")
                            self.signal_exit(debugger, requested)
                            self.assertIsNone(target.proc.poll())
                            self.assertEqual(physical_byte(target.proc.pid,
                                                           self.symbols["cleanup_site"]),
                                             original_code)
                            self.assertEqual(self.debug_registers(target.proc.pid), original_debug)
                        os.kill(target.proc.pid, signal.SIGUSR1)
                        self.assertIn("SIGNAL_DONE=42 INTERRUPTS=0", target.finish(""))

    def test_sigterm_reaps_owned_running_target(self):
        with Live([SDB, str(self.target)]) as debugger:
            debugger.proc.stdin.write("cont\n")
            debugger.proc.stdin.flush()
            text = debugger.wait(lambda text: "SIGNAL_READY=" in text)
            child = int(re.search(r"SIGNAL_READY=(\d+)", text).group(1))
            self.signal_exit(debugger, signal.SIGTERM)
            self.assertFalse(Path("/proc/{}".format(child)).exists(), "owned target was not reaped")

    def test_batch_sigint_exits_130_and_discards_remaining_commands(self):
        script = self.directory / "interrupted.sdb"
        sentinel = "sdb_signal_command_must_not_execute"
        script.write_text("cont\nload /no/such/{}\nhelp\n".format(sentinel))
        with Live([SDB, "--batch", str(script), str(self.target)]) as debugger:
            text = debugger.wait(lambda text: "SIGNAL_READY=" in text)
            child = int(re.search(r"SIGNAL_READY=(\d+)", text).group(1))
            text = self.signal_exit(debugger, signal.SIGINT)
            self.assertNotIn(sentinel, text)
            self.assertNotIn("load <program>", text)
            self.assertFalse(Path("/proc/{}".format(child)).exists(), "batch child was not reaped")

    def test_terminal_ctrl_c_stops_all_threads_and_allows_continue(self):
        with Terminal([SDB, str(self.target), "threads"]) as terminal:
            terminal.command("set disassemble off")
            for _ in range(8):
                prompts = terminal.text.count("(sdb) ")
                terminal.send("cont\n")
                terminal.wait(lambda text: "SIGNAL_READY=" in text or
                              text.count("(sdb) ") > prompts)
                if "SIGNAL_READY=" in terminal.text:
                    break
            else:
                self.fail("threaded fixture never became ready:\n" + terminal.text)
            child = int(re.search(r"SIGNAL_READY=(\d+)", terminal.text).group(1))
            for attempt in range(2):
                prompts = terminal.text.count("(sdb) ")
                before = len(terminal.text)
                terminal.send("\x03")
                terminal.wait(lambda text: text.count("(sdb) ") > prompts)
                self.assertIn("interrupted; all threads stopped", terminal.text[before:])
                listing = terminal.command("info threads")
                tids = [int(tid) for tid in re.findall(r"(?m)^\s*\*?\s*(\d+) stopped$", listing)]
                self.assertEqual(len(tids), 3, listing)
                for tid in tids:
                    self.assertEqual(task_state(tid), "t", "not every task is ptrace-stopped")
                if attempt == 0:
                    terminal.send("cont\n")
                    wait_for(lambda: task_state(child) not in ("t", "T"), "terminal target to resume")
            terminal.command("write @finish 01000000")
            for _ in range(8):
                result = terminal.command("cont")
                if "exited with status 0" in result:
                    break
            else:
                self.fail("threaded fixture did not finish:\n" + terminal.text)
            text = terminal.finish()
            self.assertIn("SIGNAL_DONE=42 INTERRUPTS=0", text)
            self.assertNotIn("** error:", text)
            self.assertFalse(Path("/proc/{}".format(child)).exists())

    def test_terminal_ctrl_c_discards_partial_command(self):
        with Terminal([SDB]) as terminal:
            prompts = terminal.text.count("(sdb) ")
            terminal.send('load "unfinished')
            terminal.send("\x03")
            terminal.wait(lambda text: text.count("(sdb) ") > prompts)
            self.assertIn("load <program>", terminal.command("help"))
            self.assertNotIn("** error:", terminal.finish())

    def test_terminal_ctrl_c_delayed_by_target_mask_does_not_stop_next_continue(self):
        for interrupting_before_unmask in (False, True):
            with self.subTest(interrupting_before_unmask=interrupting_before_unmask):
                with Terminal([SDB, str(self.target), "delayed-int"]) as terminal:
                    terminal.command("set disassemble off")
                    terminal.send("cont\n")
                    terminal.wait(lambda text: "SIGNAL_READY=" in text)
                    child = int(re.search(r"SIGNAL_READY=(\d+)", terminal.text).group(1))
                    prompts = terminal.text.count("(sdb) ")
                    terminal.send("\x03")
                    terminal.wait(lambda text: text.count("(sdb) ") > prompts)
                    self.assertIn("interrupted; all threads stopped", terminal.text)

                    def target_has_blocked_pending_interrupt():
                        status = Path("/proc/{}/status".format(child)).read_text()
                        values = {name: int(value, 16) for name, value in
                                  re.findall(r"(?m)^(SigBlk|SigPnd|ShdPnd):\s+([0-9a-fA-F]+)$", status)}
                        mask = 1 << (signal.SIGINT - 1)
                        return (values["SigBlk"] & mask and
                                (values["SigPnd"] | values["ShdPnd"]) & mask)

                    wait_for(target_has_blocked_pending_interrupt,
                             "terminal SIGINT pending behind target mask")
                    terminal.command("write @finish 01000000")
                    if interrupting_before_unmask:
                        terminal.command("break before_unmask")
                        self.assertIn("hit a breakpoint", terminal.command("cont"))
                        self.assertIn("single-step stop", terminal.command("si"))
                        terminal.command("delete 0")
                        self.assertTrue(target_has_blocked_pending_interrupt())
                    # A deferred terminal signal remains debugger-owned across
                    # intervening breakpoint/single-step stops and CLI commands.
                    result = terminal.command("cont")
                    self.assertIn("exited with status 0", result)
                    self.assertNotIn("interrupted; all threads stopped", result)
                    self.assertNotIn("stopped by signal SIGINT", result)
                    text = terminal.finish()
                    self.assertIn("SIGNAL_DONE=42 INTERRUPTS=0", text)
                    self.assertNotIn("** error:", text)
                    self.assertFalse(Path("/proc/{}".format(child)).exists())

    def test_terminal_ctrl_c_during_blocked_syscall_keeps_delayed_sigint_suppressed(self):
        with Terminal([SDB, str(self.target), "blocked-read"]) as terminal:
            terminal.command("set disassemble off")
            terminal.command("break signal_read_call")
            self.assertIn("hit a breakpoint", terminal.command("cont"))
            child = int(re.search(r"SIGNAL_READY=(\d+)", terminal.text).group(1))
            self.assertIn("syscall entry 0", terminal.command("syscall"))
            terminal.command("delete 0")

            def blocked_read():
                return (task_state(child) == "S" and
                        Path("/proc/{}/syscall".format(child)).read_text().split()[0] == "0")

            # The next PTRACE_SYSCALL is genuinely waiting inside a read on an
            # empty private pipe, rather than stopped at its entry boundary.
            terminal.send("syscall\n")
            wait_for(blocked_read, "fixture to block inside read under PTRACE_SYSCALL")
            before = len(terminal.text)
            prompts = terminal.text.count("(sdb) ")
            terminal.send("\x03")
            terminal.wait(lambda text: text.count("(sdb) ") > prompts)
            interrupted = terminal.text[before:]
            self.assertIn("interrupted; all threads stopped", interrupted)
            self.assertIn("syscall exit 0", interrupted)
            self.assertNotIn("stopped by signal SIGINT", interrupted)

            # The delayed copy must be suppressed transparently after the CLI
            # acknowledged Ctrl-C, even with an intervening syscall-exit stop.
            before = len(terminal.text)
            prompts = terminal.text.count("(sdb) ")
            terminal.send("cont\n")
            terminal.wait(lambda text: text.count("(sdb) ") > prompts or blocked_read())
            self.assertEqual(terminal.text.count("(sdb) "), prompts, terminal.text[before:])
            self.assertTrue(blocked_read(), terminal.text[before:])
            self.assertNotIn("stopped by signal SIGINT", terminal.text[before:])
            # An unrelated user signal remains forwardable. Its handler writes
            # the pipe token, allowing the restarted read to finish normally.
            prompts = terminal.text.count("(sdb) ")
            os.kill(child, signal.SIGUSR1)
            terminal.wait(lambda text: text.count("(sdb) ") > prompts)
            self.assertIn("stopped by signal SIGUSR1", terminal.text)
            self.assertIn("exited with status 0", terminal.command("cont"))
            text = terminal.finish()
            self.assertIn("SIGNAL_DONE=42 INTERRUPTS=0", text)
            self.assertNotIn("** error:", text)
            self.assertFalse(Path("/proc/{}".format(child)).exists())

    def test_other_terminal_sigint_is_reported_and_forwarded_to_attached_target(self):
        with Terminal([str(self.target)], ready=lambda text: "SIGNAL_READY=" in text) as target:
            with Live([SDB]) as debugger:
                self.assertNotEqual(os.getpgid(target.pid), os.getpgid(debugger.proc.pid))
                self.assertIn("attached to process", debugger.command("attach {}".format(target.pid)))
                debugger.command("set disassemble off")
                debugger.proc.stdin.write("cont\n")
                debugger.proc.stdin.flush()
                wait_for(lambda: task_state(target.pid) not in ("t", "T"), "external PTY target to resume")
                # Only the external target's foreground group receives this
                # SI_KERNEL signal. It is not a debugger interruption request.
                target.send("\x03")
                text = debugger.wait(lambda text: "stopped by signal SIGINT" in text)
                self.assertNotIn("interrupted; all threads stopped", text)
                debugger.proc.stdin.write("cont\n")
                debugger.proc.stdin.flush()
                wait_for(lambda: task_state(target.pid) not in ("t", "T"), "forwarded SIGINT to resume target")
                self.signal_exit(debugger, signal.SIGTERM)
            os.kill(target.pid, signal.SIGUSR1)
            self.assertIn("SIGNAL_DONE=42 INTERRUPTS=1", target.finish(command=None))


if __name__ == "__main__":
    if not probe_ptrace():
        sys.exit(77)
    unittest.main(verbosity=2)
