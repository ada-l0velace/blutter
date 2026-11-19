"""Authored ELF relocations and ARM64 words; no application snapshots."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from elftools.common.exceptions import ELFError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import reader_probe
import reader_stub_evidence as evidence
from test_runtime_evidence import ELF_HEADER, PROGRAM_HEADER


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
        result.append(byte if done else byte | 128)
        if done:
            return bytes(result)


def packed(entries):
    # A deliberately ungrouped encoding exercises all per-record fields.
    data = bytearray(b'APS2' + sleb(len(entries)) + sleb(0) + sleb(len(entries)) + sleb(8))
    previous_address = previous_addend = 0
    for address, info, addend in entries:
        data.extend(sleb(address - previous_address) + sleb(info) + sleb(addend - previous_addend))
        previous_address, previous_addend = address, addend
    return bytes(data)


def engine_fixture(duplicate=False, encoding='aps2', stride=8):
    base = 0x208 if stride == 16 else 0x200
    entries = [(base, 1027, 0x300), (base + stride, 1027, 0x320)]
    if duplicate:
        entries.extend([(base + 0x40, 1027, 0x300), (base + 0x40 + stride, 1027, 0x320)])
    encoded = (b''.join(struct.pack('<QQq', *row) for row in entries)
               if encoding == 'rela' else packed(entries))
    data = bytearray(0x500)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    data[:64] = ELF_HEADER.pack(ident, 3, 183, 1, 0, 64, 0x400, 0, 64, 56, 1, 64, 3, 1)
    PROGRAM_HEADER.pack_into(data, 64, 1, 4, 0, 0, 0, len(data), len(data), 1)
    data[0x100:0x100 + len(encoded)] = encoded
    for offset, name in [(0x300, b'AuthoredFirst\0'), (0x320, b'AuthoredLast\0')]:
        data[offset:offset + len(name)] = name
    strings = b'\0.shstrtab\0.rela.dyn\0'
    data[0x380:0x380 + len(strings)] = strings
    section = struct.Struct('<IIQQQQIIQQ')
    section.pack_into(data, 0x440, 1, 3, 0, 0, 0x380, len(strings), 0, 0, 1, 0)
    section.pack_into(data, 0x480, 11, 4 if encoding == 'rela' else 0x60000002,
                      0, 0x100, 0x100, len(encoded), 0, 0, 8 if encoding == 'rela' else 1,
                      24 if encoding == 'rela' else 0)
    return data


class PackedRelocations(unittest.TestCase):
    def test_ungrouped_relocations_and_signed_deltas(self):
        rows = [(0x208, 1027, 0x320), (0x200, 1027, 0x300)]
        self.assertEqual(evidence.packed_relative_relocations(packed(rows)), {0x208: 0x320, 0x200: 0x300})

    def test_grouped_offset_info_and_addend(self):
        # Two consecutive pointers to the same authored string.
        data = b'APS2' + b''.join(map(sleb, [2, 0x1f8, 2, 15, 8, 1027, 0x300]))
        self.assertEqual(evidence.packed_relative_relocations(data), {0x200: 0x300, 0x208: 0x300})

    def test_no_addend_groups_and_nonrelative_types(self):
        data = b'APS2' + b''.join(map(sleb, [1, 0x1f8, 1, 3, 8, 1027]))
        self.assertEqual(evidence.packed_relative_relocations(data), {0x200: 0})
        self.assertEqual(evidence.packed_relative_relocations(packed([(0x200, 1025, 0x300)])), {})

    def test_every_truncated_prefix_refuses(self):
        encoded = packed([(0x200, 1027, 0x300), (0x208, 1027, 0x320)])
        for end in range(len(encoded)):
            with self.subTest(end=end), self.assertRaises(RuntimeError):
                evidence.packed_relative_relocations(encoded[:end])

    def test_invalid_counts_groups_flags_and_trailing_bytes(self):
        cases = [[0, 0], [evidence.MAX_RELOCATIONS + 1, 0],
                 [1, 0, 0, 0], [1, 0, 2, 0], [1, 0, 1, 16], [1, 0, 1, 4]]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                evidence.packed_relative_relocations(b'APS2' + b''.join(map(sleb, values)))
        with self.assertRaisesRegex(RuntimeError, 'unread'):
            evidence.packed_relative_relocations(packed([(0x200, 1027, 0x300)]) + b'\0')

    def test_overflow_alignment_and_symbol_relative_relocations(self):
        cases = [[(0x201, 1027, 0x300)], [(1 << 64, 1027, 0x300)],
                 [(0x200, (1 << 32) | 1027, 0x300)]]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(RuntimeError):
                evidence.packed_relative_relocations(packed(entries))
        with self.assertRaisesRegex(RuntimeError, 'oversized'):
            evidence.packed_relative_relocations(b'APS2' + b'\x80' * 11)

    def test_later_relocation_cannot_override_a_proved_pointer(self):
        for second_kind in (1027, 1025):
            with self.subTest(kind=second_kind), self.assertRaisesRegex(RuntimeError, 'duplicate'):
                evidence.packed_relative_relocations(packed([(0x200, 1027, 0x300), (0x200, second_kind, 0x320)]))


class PlainRelocations(unittest.TestCase):
    def test_signed_addends_and_all_write_destinations(self):
        data = b''.join(struct.pack('<QQq', *row) for row in
                        [(0x200, 1027, 0x300), (0x208, 1025, 0), (0x210, 1027, -8)])
        writes = set()
        self.assertEqual(evidence.plain_relative_relocations(data, writes),
                         {0x200: 0x300, 0x210: -8})
        self.assertEqual(writes, {0x200, 0x208, 0x210})

    def test_record_extent_and_count_limits(self):
        record = struct.pack('<QQq', 0x200, 1027, 0x300)
        for size in range(24):
            with self.subTest(size=size), self.assertRaises(RuntimeError):
                evidence.plain_relative_relocations(record[:size])
        with patch.object(evidence, 'MAX_RELOCATIONS', 1), self.assertRaises(RuntimeError):
            evidence.plain_relative_relocations(record + struct.pack('<QQq', 0x208, 1027, 0x320))

    def test_duplicate_writes_alignment_and_symbol_relative_refuse(self):
        first = struct.pack('<QQq', 0x200, 1027, 0x300)
        for kind in (1025, 1027):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'duplicate'):
                evidence.plain_relative_relocations(first + struct.pack('<QQq', 0x200, kind, 0))
        for address, info in [(0x201, 1027), (0x200, (1 << 32) | 1027)]:
            with self.subTest(address=address, info=info), self.assertRaises(RuntimeError):
                evidence.plain_relative_relocations(struct.pack('<QQq', address, info, 0x300))


class OriginalStubEvidence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'authored.so'
        self.path.write_bytes(engine_fixture())
        self.names = ['AuthoredFirst', 'AuthoredLast']

    def test_relocated_pointer_order_works_without_contiguous_name_storage(self):
        original = self.path.read_bytes()
        table = evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), self.names)
        self.assertEqual(table, 0x200)
        self.assertNotIn(b'AuthoredFirst\0AuthoredLast\0', original)
        self.assertEqual(self.path.read_bytes(), original)

    def test_reversed_missing_and_ambiguous_engine_tables_refuse(self):
        for names in [list(reversed(self.names)), ['AuthoredFirst', 'Missing']]:
            with self.subTest(names=names), self.assertRaisesRegex(RuntimeError, 'unique'):
                evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), names)
        self.path.write_bytes(engine_fixture(duplicate=True))
        with self.assertRaisesRegex(RuntimeError, 'unique'):
            evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), self.names)

    def test_both_relocation_formats_and_name_layouts(self):
        for encoding in ('aps2', 'rela'):
            for stride in (8, 16):
                with self.subTest(encoding=encoding, stride=stride):
                    self.path.write_bytes(engine_fixture(encoding=encoding, stride=stride))
                    self.assertEqual(evidence.validate_engine_stub_table(
                        evidence.OriginalElf(self.path), self.names), 0x208 if stride == 16 else 0x200)
                    self.path.write_bytes(engine_fixture(duplicate=True, encoding=encoding, stride=stride))
                    with self.assertRaisesRegex(RuntimeError, 'unique'):
                        evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), self.names)

    def test_interleaved_companion_must_be_null_and_unrelocated(self):
        for encoding in ('aps2', 'rela'):
            data = engine_fixture(encoding=encoding, stride=16)
            struct.pack_into('<Q', data, 0x200, 1)
            self.path.write_bytes(data)
            with self.subTest(encoding=encoding), self.assertRaisesRegex(RuntimeError, 'unique'):
                evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), self.names)
            rows = [(0x208, 1027, 0x300), (0x218, 1027, 0x320), (0x200, 1025, 0)]
            encoded = (packed(rows) if encoding == 'aps2' else
                       b''.join(struct.pack('<QQq', *row) for row in rows))
            data = engine_fixture(encoding=encoding, stride=16)
            data[0x100:0x100 + len(encoded)] = encoded
            struct.pack_into('<Q', data, 0x480 + 32, len(encoded))
            self.path.write_bytes(data)
            with self.subTest(encoding=encoding), self.assertRaisesRegex(RuntimeError, 'unique'):
                evidence.validate_engine_stub_table(evidence.OriginalElf(self.path), self.names)

    def test_relocation_section_type_and_entry_size_are_checked(self):
        for offset, value in [(0x480 + 4, 1), (0x480 + 56, 8)]:
            data = engine_fixture(encoding='rela')
            struct.pack_into('<I' if offset == 0x484 else '<Q', data, offset, value)
            self.path.write_bytes(data)
            with self.subTest(offset=offset), self.assertRaises((RuntimeError, ELFError)):
                evidence.OriginalElf(self.path)

    def test_target_and_file_mapping_checks(self):
        data = engine_fixture()
        struct.pack_into('<H', data, 18, 62)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(RuntimeError, 'target'):
            evidence.OriginalElf(self.path)
        self.path.write_bytes(engine_fixture())
        engine = evidence.OriginalElf(self.path)
        for address, length, executable in [(0x500, 1, False), (0, 16, True), (-1, 1, False)]:
            with self.subTest(address=address), self.assertRaises(RuntimeError):
                engine.read(address, length, executable)

    def test_declared_relocation_section_must_fit_the_file(self):
        data = engine_fixture()
        struct.pack_into('<Q', data, 0x480 + 32, 0x1000)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(RuntimeError, 'relocation section'):
            evidence.OriginalElf(self.path)

    def test_excessive_elf_header_counts_refuse_before_iteration(self):
        for offset, count in [(56, evidence.MAX_PROGRAM_HEADERS + 1), (60, 4097)]:
            data = engine_fixture()
            struct.pack_into('<H', data, offset, count)
            self.path.write_bytes(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(RuntimeError, 'header count'):
                evidence.OriginalElf(self.path)

    def test_instruction_roles_are_read_from_original_words(self):
        # LDR X0,[X26,#0x80]; STR X5,[X26,#0x100]; RET.
        words = [0xf9404340, 0xf9008345, 0xd65f03c0]
        self.assertEqual(evidence.thread_accesses(words), [('ldr', 0, 0x80), ('str', 5, 0x100)])
        with self.assertRaisesRegex(RuntimeError, 'unsupported Thread access'):
            evidence.thread_accesses([0xb9404340])  # A 32-bit load has a different contract.

    def test_abi_mode_cannot_be_selected_by_a_report_alone(self):
        report = {'schema': 1, 'status': 'deserialized', 'abi_kind': 'arm64_stub_layout_v1'}
        with patch.object(reader_probe, '_original_table') as original:
            with self.assertRaisesRegex(RuntimeError, 'ABI proof kind'):
                reader_probe.validate_probe(report, self.path, self.path)
            original.assert_not_called()

    def test_exact_stub_family_registration_still_requires_a_probe(self):
        from reader_profiles import RUNTIME_PROFILES
        from reader_compatibility import ReaderSelection
        selected = [name for name, p in RUNTIME_PROFILES.items() if p.abi_probe == 'arm64_stub_layout_v1']
        self.assertTrue(selected)
        for name in selected:
            profile = RUNTIME_PROFILES[name]
            self.assertTrue(ReaderSelection(name, profile.version, profile.engine).needs_probe)


if __name__ == '__main__':
    unittest.main()
