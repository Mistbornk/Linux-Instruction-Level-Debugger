#!/usr/bin/env python3
"""Measure one exact fixture natively, with continue, and with syscall stops.

The on/off comparison includes executable-map discovery, memory reads, Capstone
decoding and output formatting. It is not an isolated Capstone microbenchmark.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
COUNT = 200


def checked_session(argv, commands, capture=False):
    with subprocess.Popen(argv, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
        started = time.perf_counter_ns()
        try:
            stdout, stderr = process.communicate(commands, timeout=120)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        if process.returncode or stderr:
            raise RuntimeError("benchmark command failed: {}\n{}\n{}".format(argv, stdout, stderr))
        return elapsed, stdout or ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdb", type=Path)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output", type=Path, default=Path("build/benchmark.json"))
    args = parser.parse_args()
    if args.repeats < 3 or args.repeats > 100:
        parser.error("--repeats must be 3..100")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("run inside the Linux x86-64 development environment")
    binary = str(args.sdb.resolve())
    with tempfile.TemporaryDirectory(prefix="sdb-benchmark-") as directory:
        fixture = str(Path(directory) / "syscalls")
        subprocess.run(["gcc", "-nostdlib", "-no-pie", str(ROOT / "tests/fixtures/ext_syscalls.S"),
                        "-o", fixture], check=True)
        cases = {
            "native": ([fixture], ""),
            "continue": ([binary, "--batch", "-", fixture], "set disassemble off\ncont\n"),
            "syscalls_no_disassembly": ([binary, "--batch", "-", fixture],
                                        "set disassemble off\n" + "syscall\n" * (COUNT * 2) + "cont\n"),
            "syscalls_with_disassembly": ([binary, "--batch", "-", fixture],
                                          "set disassemble on\n" + "syscall\n" * (COUNT * 2) + "cont\n"),
        }
        for name, (argv, commands) in cases.items():
            _, text = checked_session(argv, commands, capture=True)
            if name != "native" and "exited with status 0" not in text:
                raise RuntimeError("fixture did not finish: " + text)
            if name.startswith("syscalls_"):
                if text.count("syscall entry") != COUNT or text.count("syscall exit") != COUNT:
                    raise RuntimeError("benchmark did not observe the expected {} syscall pairs:\n{}".format(COUNT, text))
        # Each validated case above also warms the filesystem/code caches. Shuffle
        # each round deterministically so one case is not always measured last.
        randomizer = random.Random(0)
        samples = {name: [] for name in cases}
        for _ in range(args.repeats):
            order = list(cases)
            randomizer.shuffle(order)
            for name in order:
                elapsed, _ = checked_session(*cases[name])
                samples[name].append(elapsed)
        measurements = {name: {"samples_ms": values, "median_ms": statistics.median(values),
                               "min_ms": min(values), "max_ms": max(values)}
                        for name, values in samples.items()}
        medians = {name: value["median_ms"] for name, value in measurements.items()}
        report = {
            "platform": platform.platform(), "machine": platform.machine(),
            "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
            "sdb_binary": binary,
            "sdb_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(Path(fixture).read_bytes()).hexdigest(),
            "logical_cpus": os.cpu_count(), "syscalls": COUNT, "syscall_stops": COUNT * 2,
            "repeats": args.repeats, "measurements": measurements,
            "derived": {
                "syscall_stop_overhead_us": (medians["syscalls_no_disassembly"] - medians["continue"]) * 1000 / (COUNT * 2),
                "automatic_disassembly_overhead_per_stop_us": (medians["syscalls_with_disassembly"] - medians["syscalls_no_disassembly"]) * 1000 / (COUNT * 2),
            },
            "scope": "Wall-clock subprocess session; stdout=/dev/null; no artificial speedup claim. Includes scheduling and VM overhead.",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print("One fixture: {} getpid syscalls; {} measured repetitions per case.".format(COUNT, args.repeats))
        for name, measurement in measurements.items():
            print("{:<30} median {:9.3f} ms  [{:.3f}, {:.3f}]".format(
                name, measurement["median_ms"], measurement["min_ms"], measurement["max_ms"]))
        print("Raw samples and environment:", args.output)


if __name__ == "__main__":
    main()
