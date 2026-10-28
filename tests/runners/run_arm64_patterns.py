#!/usr/bin/env python3
"""Compile and exercise authored ARM64 recognizer cases without a Dart SDK."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "capstone"], text=True))
    libdir = subprocess.check_output(["pkg-config", "--variable=libdir", "capstone"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="arm64-patterns-") as temporary:
        executable = Path(temporary) / "patterns"
        subprocess.run([os.environ.get("CXX", "c++"), "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(root / "blutter/src"), str(root / "tests/unit/arm64_patterns_test.cpp"),
                        "-o", str(executable), *flags], check=True, timeout=60)
        env = dict(os.environ)
        if libdir:
            env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
            env["DYLD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("DYLD_LIBRARY_PATH", "")
        subprocess.run([str(executable)], check=True, env=env, timeout=15)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
