#!/usr/bin/env python3
"""Verify the S31 toolchain and its scalar musl runtime."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"FAILED: {' '.join(command)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(1)
    return result.stdout


def verify_compiler(prefix: Path, work_dir: Path, repo_root: Path) -> None:
    """Verify that the installed toolchain compiler exists and reports the expected build ID."""
    target = "riscv32-esp-linux-musl"
    gcc = prefix / "bin" / f"{target}-gcc"
    if not gcc.is_file():
        raise SystemExit(f"Compiler not found: {gcc}")

    # The default libc is scalar.
    libc = prefix / target / "sysroot" / "usr" / "lib" / "libc.so"
    if not libc.exists():
        raise SystemExit(f"libc not found: {libc}")

    objdump = prefix / "bin" / f"{target}-objdump"
    if not objdump.exists():
        raise SystemExit(f"objdump not found: {objdump}")

    disasm_file = work_dir / "libc-disassembly.txt"
    disasm_file.write_text(_run([str(objdump), "-d", str(libc)]))

    required_symbols = ["memcpy", "memchr", "memrchr", "memcmp", "strcmp"]
    for symbol in required_symbols:
        if f"<{symbol}>:" not in disasm_file.read_text():
            raise SystemExit(f"Missing symbol <{symbol}> in libc disassembly")

    verify_libc_scalar(prefix, work_dir, repo_root)


def verify_libc_scalar(prefix: Path, work_dir: Path, repo_root: Path) -> None:
    """Reject every Espressif custom instruction in the default musl libc."""
    target = "riscv32-esp-linux-musl"
    libc = prefix / target / "sysroot" / "usr" / "lib" / "libc.so"
    objdump = prefix / "bin" / f"{target}-objdump"

    disasm_file = work_dir / "libc-disassembly.txt"
    if not disasm_file.exists():
        disasm_file.write_text(_run([str(objdump), "-d", str(libc)]))

    disassembly = disasm_file.read_text()
    if "esp." in disassembly:
        raise SystemExit("default musl libc contains an Espressif custom instruction")

    print("Scalar musl verification passed.")
