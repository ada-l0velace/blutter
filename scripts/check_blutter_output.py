#!/usr/bin/env python3
"""Audit output artifacts and ARM64 addresses; does not prove Dart semantics."""
import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import capstone
from capstone.arm64_const import ARM64_INS_ENDING
from elftools.elf.elffile import ELFFile


def unprivileged_load_mnemonic(data):
    # Check the allocated A64 integer-load encoding independently of Capstone's
    # erroneous same-register writeback rejection for addressing mode 10.
    word = int.from_bytes(data, "little")
    if len(data) != 4 or word & 0x3f200c00 != 0x38000800:
        return None
    size, opcode = word >> 30, (word >> 22) & 3
    if opcode == 1:
        return ("ldtrb", "ldtrh", "ldtr", "ldtr")[size]
    if opcode in (2, 3) and size < 2:
        return ("ldtrsb", "ldtrsh")[size]
    if opcode == 2 and size == 2:
        return "ldtrsw"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libapp", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    raw = args.libapp.read_bytes()
    with args.libapp.open("rb") as stream:
        elf = ELFFile(stream)
        if elf["e_machine"] != "EM_AARCH64":
            parser.error("this instruction checker supports ARM64 only")
        mappings = [(s["p_vaddr"], s["p_filesz"], s["p_offset"])
                    for s in elf.iter_segments()
                    if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1]

    def instruction_bytes(address):
        for start, size, offset in mappings:
            if start <= address and address + 4 <= start + size:
                pos = offset + address - start
                return raw[pos:pos + 4]
        return None

    errors = []
    files = {}
    for name in ("pp.txt", "objs.txt", "blutter_frida.js",
                 "ida_script/addNames.py", "ida_script/ida_dart_struct.h"):
        path = args.output / name
        files[name] = path.stat().st_size if path.is_file() else 0
        if not files[name]:
            errors.append("missing or empty artifact: " + name)
    naming = args.output / "ida_script/addNames.py"
    ranges = []
    if naming.is_file():
        try:
            tree = ast.parse(naming.read_text(errors="replace"))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "add_func" and len(node.args) == 2
                        and all(isinstance(a, ast.Constant) and type(a.value) is int
                                for a in node.args)):
                    start, end = [a.value for a in node.args]
                    ranges.append((start, end))
                    if start % 4 or end % 4 or end <= start or not any(
                            base <= start and end <= base + size
                            for base, size, _ in mappings):
                        errors.append(f"invalid exported function range: {start:#x}..{end:#x}")
        except SyntaxError as exc:
            errors.append("invalid generated IDA Python: " + str(exc))
    if not ranges:
        errors.append("no constant function ranges found in IDA naming script")

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    mnemonics = {md.insn_name(i) for i in range(1, ARM64_INS_ENDING)}
    line_pattern = re.compile(r"^\s*//\s*(0x[0-9a-fA-F]+):\s+([a-z][a-z0-9.]*)\b")
    raw_word_pattern = re.compile(r"^\s*//\s*(0x[0-9a-fA-F]+):\s+\.word\s+(0x[0-9a-fA-F]+)\b")
    assembly = sorted(p for p in (args.output / "asm").rglob("*") if p.is_file())
    nonempty = [p for p in assembly if p.stat().st_size]
    if not nonempty:
        errors.append("no nonempty assembly output")
    counts = Counter()
    addresses = set()
    for path in nonempty:
        with path.open(errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                word = raw_word_pattern.match(line)
                if word:
                    address, value = int(word[1], 16), int(word[2], 16)
                    data = instruction_bytes(address)
                    counts["raw_word_lines"] += 1
                    if address % 4 or data is None or int.from_bytes(data, "little") != value:
                        errors.append(f"{path}:{number}: raw word does not match executable bytes at {address:#x}")
                    else:
                        counts["matching_raw_words"] += 1
                    continue
                match = line_pattern.match(line)
                if not match or match[2].split(".")[0] not in mnemonics:
                    continue
                address, mnemonic = int(match[1], 16), match[2]
                counts["instruction_lines"] += 1
                addresses.add(address)
                data = instruction_bytes(address)
                if address % 4 or data is None:
                    errors.append(f"{path}:{number}: instruction outside executable mapping: {address:#x}")
                    continue
                decoded = next(md.disasm(data, address, count=1), None)
                if decoded is None:
                    if mnemonic == unprivileged_load_mnemonic(data):
                        counts["matching_instruction_mnemonics"] += 1
                        counts["unprivileged_load_words_checked"] += 1
                    else:
                        errors.append(f"{path}:{number}: invalid ARM64 instruction at {address:#x}")
                elif decoded.mnemonic != mnemonic:
                    counts["mnemonic_differences"] += 1
                    if counts["mnemonic_differences"] <= 20:
                        errors.append(f"{path}:{number}: {address:#x}: output {mnemonic}, decoded {decoded.mnemonic}")
                else:
                    counts["matching_instruction_mnemonics"] += 1
    if not counts["instruction_lines"]:
        errors.append("no machine-instruction lines recognized; format unsupported or analysis missing")
    warnings = []
    analysis_failures = []
    if args.log:
        for line in args.log.read_text(errors="replace").splitlines():
            if re.search(r"^Analysis (?:error\b|FAILED\b|INCOMPLETE\b)", line):
                analysis_failures.append(line)
            if re.search(r"analysis error|warning|unknown|unsupported|fallback|assert|fatal|segmentation|killed", line, re.I):
                warnings.append(line)
    analysis_status = None
    status_file = args.output / "analysis_status.json"
    if status_file.exists():
        try:
            analysis_status = json.loads(status_file.read_text())
            if (not isinstance(analysis_status, dict)
                    or analysis_status.get("status") not in {"running", "failed", "partial", "complete"}
                    or type(analysis_status.get("analysis_errors")) is not int
                    or analysis_status["analysis_errors"] < 0):
                raise ValueError("unsupported analysis status schema")
            if analysis_status["status"] != "complete" or analysis_status["analysis_errors"]:
                analysis_failures.append("analysis_status.json does not report successful completion")
        except (OSError, ValueError) as exc:
            errors.append("invalid analysis status: " + str(exc))
    report = {
        "sample_sha256": hashlib.sha256(raw).hexdigest(),
        "artifact_sizes": files, "nonempty_asm_files": len(nonempty),
        "exported_function_ranges": len(ranges),
        "unique_instruction_addresses": len(addresses), "instruction_checks": dict(counts),
        "log_diagnostic_count": len(warnings), "first_log_diagnostics": warnings[:50],
        "analysis_status": analysis_status,
        "analysis_failure_count": len(analysis_failures), "first_analysis_failures": analysis_failures[:50],
        "structural_errors": errors[:100], "structural_error_count": len(errors),
        "status": ("STRUCTURAL_CHECKS_FAILED" if errors else
                   "ANALYSIS_CHECKS_FAILED" if analysis_failures else "STRUCTURAL_CHECKS_PASSED"),
        "limits": "Does not establish complete function coverage, correct types, pool values, closures, or Dart semantics. Mnemonic differences can be disassembler-version aliases and need review."
    }
    print(json.dumps(report, indent=2))
    return 1 if errors or analysis_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
