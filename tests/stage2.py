#!/usr/bin/env python3
"""Replay command files and check argv, quoting, CLI errors and parser recovery."""
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

SDB = str(Path(sys.argv.pop(1)).resolve())
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


class StageTwo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sdb-stage-two-')
        cls.root = Path(cls.temp.name)
        cls.target = cls.root / 'target with spaces'
        subprocess.run(['gcc', '-O0', '-g', str(FIXTURES / 'arguments.c'),
                        '-o', str(cls.target)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, arguments, commands='', expected=0):
        proc = subprocess.Popen([SDB, *map(str, arguments)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, cwd=self.root, start_new_session=True)
        try:
            output, _ = proc.communicate(commands, timeout=20)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        self.assertEqual(proc.returncode, expected, output)
        return output

    def assert_arguments(self, output, arguments):
        for i, argument in enumerate(arguments):
            self.assertIn(f'ARG[{i}]={len(argument.encode())}:{argument}\n', output)
        self.assertIn('exit status 0', output)

    def test_cli_passes_target_arguments_verbatim(self):
        args = [str(self.target), 'two words', '', '--batch', '#literal', '中文']
        out = self.session(args, 'cont\nq\n')
        self.assert_arguments(out, args)

    def test_batch_and_initial_target_arguments(self):
        path = self.root / 'startup commands.txt'
        path.write_text('info reg\ncont\nq\n')
        args = [str(self.target), 'two words', '']
        out = self.session(['--command-file', path, '--', *args])
        self.assert_arguments(out, args)
        self.assertNotIn('(sdb)', out)

    def test_checked_in_command_file_replays(self):
        path = Path(__file__).resolve().parent / 'scripts' / 'loop.sdb'
        for _ in range(2):
            out = self.session(['--batch', path, self.target])
            self.assert_arguments(out, [str(self.target)])
            self.assertNotIn('(sdb)', out)

    def test_quoted_load_and_same_file_replayed_twice(self):
        args = [str(self.target), 'two words', '', "it's quoted", 'a\\b', '#literal']
        path = self.root / 'quoted commands.txt'
        path.write_text('# replayable session\n' + 'load ' + shlex.join(args)
                        + ' # trailing comment\ncont\nq')
        for _ in range(2):
            out = self.session(['--batch', path])
            self.assert_arguments(out, args)
            self.assertNotIn('(sdb)', out)

    def test_parser_error_has_file_line_and_recovers(self):
        path = self.root / 'broken commands.txt'
        path.write_text('# first line\nload "unfinished\nload '
                        + shlex.quote(str(self.target)) + '\ncont\n')
        out = self.session(['--batch', path], expected=1)
        self.assertIn(f'{path}:2: unfinished escape or quote', out)
        self.assert_arguments(out, [str(self.target)])

    def test_interactive_parser_error_recovers(self):
        out = self.session([], 'load "unfinished\ninfo break\nq\n', expected=1)
        self.assertIn('unfinished escape or quote', out)
        self.assertIn('no breakpoints', out)

    def test_shell_expressions_are_literal(self):
        marker = self.root / 'must-not-exist'
        args = [str(self.target), f'$(touch {marker})', '$HOME', '*.c']
        out = self.session(['--batch', '-'], 'load ' + shlex.join(args) + '\ncont\nq\n')
        self.assert_arguments(out, args)
        self.assertFalse(marker.exists())

    def test_double_dash_allows_dash_prefixed_executable(self):
        target = self.root / '-target'
        shutil.copy2(self.target, target)
        out = self.session(['--', '-target', '-h'], 'cont\nq\n')
        self.assert_arguments(out, ['-target', '-h'])

    def test_invalid_cli_and_help(self):
        for args in [['--batch'], ['--batch', ''], ['--unknown'],
                     ['--batch', 'a', '--command-file', 'b']]:
            with self.subTest(args=args):
                out = self.session(args, expected=1)
                self.assertIn('** error:', out)
        self.assertIn('usage:', self.session(['--help']))

    def test_nul_and_empty_path_errors_recover(self):
        out = self.session(['--batch', '-'], 'load ""\nload x\0y\ninfo break\nq\n', expected=1)
        self.assertIn('load requires an executable path', out)
        self.assertIn('commands cannot contain NUL bytes', out)
        self.assertIn('no breakpoints', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
