#!/usr/bin/env python3
"""Replay the interview's wrong-pointer diagnosis and verify its corrected run.

The same checked-in batch files are used by the manual demonstration and CTest.
Only an independent environment probe can skip; failed demo assertions are errors.
"""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def ptrace_available():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        print("SKIP: interview demo requires Linux x86-64", flush=True)
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    child = os.fork()
    if child == 0:
        result = libc.ptrace(0, 0, None, None)  # PTRACE_TRACEME
        os._exit(ctypes.get_errno() if result == -1 else 0)
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status):
        raise RuntimeError("ptrace probe did not exit normally")
    error = os.WEXITSTATUS(status)
    if error in (errno.EPERM, errno.EACCES, errno.ENOSYS):
        print("SKIP: independent ptrace probe: " + os.strerror(error), flush=True)
        return False
    if error:
        raise OSError(error, "ptrace probe")
    return True


def run(argv, expected=0):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        text, _ = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        text, _ = process.communicate()
        raise RuntimeError("demo timed out:\n" + text) from None
    if process.returncode != expected:
        raise AssertionError("exit {} != {}:\n{}".format(process.returncode, expected, text))
    for diagnostic in ("** error:", "AddressSanitizer:", "LeakSanitizer:", "runtime error:"):
        if diagnostic in text:
            raise AssertionError("unexpected diagnostic:\n" + text)
    return text


def require(condition, message, text):
    if not condition:
        raise AssertionError(message + "\n" + text)


def verify_session(text, fixed):
    hits = re.findall(r"\*\* watchpoint (\d+) hit at", text)
    require(hits == (["1"] if fixed else ["0"]), "unexpected hardware watchpoint hits", text)
    frames = re.findall(r"(?m)^#\d+ 0x[0-9a-f]+ (\w+)(?:\+|$)", text)
    require(frames[:4] == ["store_fee", "record_shipping", "process_order", "main"],
            "watchpoint did not identify the expected calling chain", text)
    memory = re.findall(r"(?m)^0x[0-9a-f]+:((?: [0-9a-f]{2}){8})$", text)
    values = [int.from_bytes(bytes.fromhex(row), "little") for row in memory]
    require(values == ([100, 0, 100, 7] if fixed else [100, 0, 7, 0]),
            "memory examination did not show the expected before/after values", text)
    expected_output = "INVOICE_TOTAL=100 SHIPPING_FEE=7" if fixed else "INVOICE_TOTAL=7 SHIPPING_FEE=0"
    require(expected_output in text, "target output does not match observed memory", text)
    require("exited with status {}".format(0 if fixed else 3) in text,
            "missing target exit status", text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdb", help="path to the SDB executable")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"), help="C compiler")
    parser.add_argument("--show-output", action="store_true", help="print both debugger transcripts")
    args = parser.parse_args()
    if not ptrace_available():
        return 77
    debugger = str(Path(args.sdb).resolve())
    with tempfile.TemporaryDirectory(prefix="sdb-interview-") as directory:
        target = str(Path(directory) / "order")
        run(shlex.split(args.cc) + ["-std=c11", "-Wall", "-Wextra", "-O0", "-g",
                                   "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls",
                                   "-fPIE", "-pie", str(ROOT / "fixtures/interview_order.c"),
                                   "-o", target])
        for mode, expected in (("bug", 3), ("fixed", 0)):
            native = run([target, mode], expected)
            require("INVOICE_TOTAL=" in native, "missing untraced target output", native)
            text = run([debugger, "--batch", str(ROOT / "scripts/interview-{}.sdb".format(mode)),
                        "--", target, mode])
            verify_session(text, mode == "fixed")
            if args.show_output:
                print("=== {}: verified transcript ===".format(mode))
                print(text, end="" if text.endswith("\n") else "\n")
    print("PASS: wrong-pointer write located by hardware watchpoint/backtrace; "
          "memory verified and corrected run exited normally")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
