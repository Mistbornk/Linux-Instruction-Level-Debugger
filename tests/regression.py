#!/usr/bin/env python3
"""Exercise only stage-one commands using real Linux children and ptrace."""
from pathlib import Path
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SDB = str(Path(sys.argv.pop(1)).resolve())
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def symbols(path):
    out = subprocess.check_output(['nm', '-n', str(path)], text=True)
    return {p[2]: int(p[0], 16) for line in out.splitlines()
            if len(p := line.split()) == 3}


class Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sdb-practice-tests-')
        cls.root = Path(cls.temp.name)
        cls.targets = {}
        for name in ['loop', 'patch', 'boundary']:
            target = cls.root / name
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-g', str(FIXTURES / (name + '.S')),
                            '-o', str(target)], check=True)
            cls.targets[name] = target
        for mode in range(5):
            target = cls.root / ('behavior' + str(mode))
            subprocess.run(['gcc', '-O0', '-g', '-fPIE', '-pie', '-DMODE=' + str(mode),
                            str(FIXTURES / 'behavior.c'), '-o', str(target)], check=True)
            cls.targets['behavior' + str(mode)] = target
        cls.sym = {name: symbols(path) for name, path in cls.targets.items()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_session(self, target, commands, expected=0):
        argv = [SDB] + ([str(target)] if target else [])
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            output, _ = proc.communicate('\n'.join(commands) + '\n', timeout=20)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        self.assertEqual(proc.returncode, expected, output)
        return output

    def addr(self, fixture, symbol):
        return format(self.sym[fixture][symbol], 'x')

    def test_invalid_commands_recover(self):
        out = self.run_session(self.targets['loop'], [
            'break', 'break -1', 'break 0x', 'break 123xyz',
            'delete nope', 'delete 999999999999999999999999', 'info reg extra',
            'patch 401000 1z', 'patch 401000 123', 'cont extra', 'cont'], 1)
        self.assertEqual(out.count('** error:'), 10, out)
        self.assertIn('LOOP=10', out)

    def test_empty_lines_are_ignored(self):
        out = self.run_session(None, ['', '   ', 'info break', 'q'])
        self.assertNotIn('error', out)

    def test_zero_original_byte(self):
        site = self.addr('patch', 'zero_site')
        out = self.run_session(self.targets['patch'], [
            'break ' + site, 'cont', 'si', 'delete 0', 'cont'])
        self.assertIn('hit a breakpoint at 0x' + site, out)
        self.assertIn('exit status 0', out)

    def test_patch_over_breakpoint_updates_original(self):
        site = self.addr('patch', 'patch_site')
        out = self.run_session(self.targets['patch'], [
            'break ' + site, 'patch ' + site + ' 97', 'cont', 'delete 0', 'cont'])
        self.assertIn('hit a breakpoint', out)
        self.assertIn('exit status 7', out)

    def test_invalid_patch_preserves_breakpoint(self):
        site = self.addr('patch', 'patch_site')
        out = self.run_session(self.targets['patch'], [
            'break ' + site, 'patch ' + site + ' cc', 'patch ' + site + ' 9z',
            'cont', 'delete 0', 'cont'], 1)
        self.assertIn('hit a breakpoint', out)
        self.assertIn('exit status 0', out)

    def test_single_step_exit_and_reload(self):
        out = self.run_session(self.targets['loop'], [
            'break ' + self.addr('loop', 'exit_call'), 'cont', 'si',
            'info break', 'load ' + str(self.targets['loop']), 'cont'])
        self.assertEqual(out.count('LOOP=10'), 2, out)
        self.assertIn('no breakpoints', out)
        self.assertEqual(out.count('exit status 0'), 2, out)

    def test_breakpoint_ids_reset(self):
        site = self.addr('loop', 'loop_body')
        out = self.run_session(self.targets['loop'], ['break ' + site, 'delete 0',
            'cont', 'load ' + str(self.targets['loop']), 'break ' + site, 'delete 0', 'cont'])
        self.assertEqual(out.count('delete breakpoint 0'), 2, out)

    def test_syscall_at_breakpoint_preserves_entry_exit(self):
        out = self.run_session(self.targets['loop'], [
            'break ' + self.addr('loop', 'write_call'), 'cont', 'syscall', 'syscall', 'cont'])
        self.assertIn('enter a syscall(1)', out)
        self.assertIn('leave a syscall(1) = 8', out)
        self.assertIn('exit status 0', out)

    def test_signal_is_reported_then_forwarded(self):
        out = self.run_session(self.targets['behavior1'], ['cont', 'cont'])
        self.assertIn('stopped by signal 10', out)
        self.assertIn('HANDLED=10', out)
        self.assertNotIn('syscall(', out)

    def test_fatal_signal_and_native_int3(self):
        for fixture, signo in [('behavior2', 4), ('behavior3', 5)]:
            with self.subTest(fixture=fixture):
                out = self.run_session(self.targets[fixture], ['cont', 'cont', 'info break'])
                self.assertIn('stopped by signal ' + str(signo), out)
                self.assertIn('terminated by signal ' + str(signo), out)
                self.assertNotIn('hit a breakpoint', out)

    def test_exec_replacement_closes_old_session(self):
        out = self.run_session(self.targets['behavior4'], ['cont', 'info break',
            'load ' + str(self.targets['loop']), 'cont'], 1)
        self.assertIn('old session closed', out)
        self.assertIn('LOOP=10', out)

    def test_invalid_elf_and_exec_failure_recover(self):
        malformed = self.root / 'malformed'
        malformed.write_bytes(b'not an ELF file')
        noexec = self.root / 'noexec'
        noexec.write_bytes(self.targets['loop'].read_bytes())
        noexec.chmod(0o600)
        out = self.run_session(None, ['load /no/such/program', 'load ' + str(malformed),
            'load ' + str(noexec), 'load ' + str(self.targets['loop']), 'cont'], 1)
        self.assertEqual(out.count('** error:'), 3, out)
        self.assertIn('LOOP=10', out)

    def test_pie_entry_and_relative_breakpoint(self):
        target = self.targets['behavior0']
        entry = int(re.search(r'Entry point address:\s*(0x[0-9a-f]+)',
                    subprocess.check_output(['readelf', '-h', str(target)], text=True)).group(1), 16)
        # Typical PIE starts at ELF virtual page 0; test derives main from nm.
        main = self.sym['behavior0']['main']
        for _ in range(3):
            out = self.run_session(target, ['breakrva ' + format(main, 'x'), 'cont', 'cont'])
            loaded = int(re.search(r'entry point: 0x([0-9a-f]+)', out).group(1), 16)
            hit = int(re.search(r'hit a breakpoint at 0x([0-9a-f]+)', out).group(1), 16)
            self.assertEqual(hit - loaded, main - entry, out)
            self.assertIn('NORMAL=1', out)

    def test_disassembly_at_last_executable_byte(self):
        target = self.targets['boundary']
        # Set the entry to the final executable byte. Static initial RIP already
        # equals entry, so display must decode exactly its one-byte RET safely.
        patched = self.root / 'boundary-entry'
        data = bytearray(target.read_bytes())
        address = self.sym['boundary']['last_instruction']
        data[24:32] = address.to_bytes(8, 'little')
        patched.write_bytes(data)
        patched.chmod(0o700)
        out = self.run_session(patched, ['q'])
        self.assertIn('ret', out)
        self.assertEqual(len(re.findall(r'^\s*=> ', out, re.M)), 1, out)
        self.assertNotIn('out of the range', out)

    def test_external_kill_then_reload(self):
        proc = subprocess.Popen([SDB, str(self.targets['loop'])], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        try:
            output = b''
            deadline = time.monotonic() + 10
            while not output.endswith(b'(sdb) '):
                if time.monotonic() > deadline: self.fail('initial prompt timeout')
                if selector.select(0.1):
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk: self.fail('debugger exited before prompt')
                    output += chunk
            children = Path('/proc/{}/task/{}/children'.format(proc.pid, proc.pid)).read_text().split()
            self.assertEqual(len(children), 1)
            child = int(children[0])
            os.kill(child, signal.SIGKILL)
            deadline = time.monotonic() + 10
            while True:
                state = Path('/proc/{}/status'.format(child)).read_text()
                if re.search(r'^State:\s+Z', state, re.M): break
                if time.monotonic() > deadline: self.fail('tracee did not terminate')
                time.sleep(0.01)
            rest, _ = proc.communicate(('load ' + str(self.targets['loop']) + '\ncont\n').encode(), timeout=10)
            output += rest
            self.assertEqual(proc.returncode, 0, output.decode())
            self.assertIn(b'LOOP=10', output)
        finally:
            selector.close()
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
            proc.stdout.close()

    def test_eof_reaps_child_and_repeated_disassembly_has_no_fd_leak(self):
        proc = subprocess.Popen([SDB, str(self.targets['loop'])], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        def command(text=None):
            if text is not None:
                proc.stdin.write((text + '\n').encode())
                proc.stdin.flush()
            output = b''
            deadline = time.monotonic() + 10
            while not output.endswith(b'(sdb) '):
                if time.monotonic() >= deadline: self.fail('prompt timeout: ' + repr(output))
                if selector.select(0.1):
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk: self.fail('unexpected EOF: ' + repr(output))
                    output += chunk
            return output.decode()
        try:
            command()
            children = Path('/proc/{}/task/{}/children'.format(proc.pid, proc.pid)).read_text().split()
            self.assertEqual(len(children), 1)
            child = int(children[0])
            before = len(list(Path('/proc/{}/fd'.format(proc.pid)).iterdir()))
            site = self.addr('loop', 'loop_body')
            command('break ' + site)
            for _ in range(10):
                command('cont')
                command('si')
            after = len(list(Path('/proc/{}/fd'.format(proc.pid)).iterdir()))
            self.assertEqual(after, before)
            proc.stdin.close()
            proc.wait(timeout=10)
            self.assertEqual(proc.returncode, 0)
            self.assertFalse(Path('/proc/' + str(child)).exists(), 'owned child not reaped on EOF')
        finally:
            selector.close()
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
            proc.stdout.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
