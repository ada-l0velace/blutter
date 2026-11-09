"""Authored ARM64 instructions and ELF containers; no application fixtures."""
from dataclasses import FrozenInstanceError
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import runtime_evidence as evidence
import binary_input
from runtime_evidence import EvidenceError, GuardKind, GuardOffsets, GuardStatus, collect_guard_evidence

ELF_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
PROGRAM_HEADER = struct.Struct('<IIQQQQQQ')
NOP = 0xd503201f


def guard_words(state=0x80, tag=0x100, native=False, target=None):
    scratch = 16 if native else 17
    target = (9 if native else 16) if target is None else target
    trap = evidence.NATIVE_GUARD_TRAP if native else evidence.LEAF_GUARD_TRAP
    result = [] if tag is None else [0xf9000000 | ((tag // 8) << 10) | (26 << 5) | target]
    result.extend([0xf9400000 | ((state // 8) << 10) | (26 << 5) | scratch,
                   0xb4000000 | (2 << 5) | scratch,
                   0xd4200000 | (trap << 5), 0xd63f0000 | (target << 5)])
    return result


def pack_words(words):
    return struct.pack('<' + 'I' * len(words), *words)


def elf_fixture(code=b'', extra_segments=(), code_offset=0x400):
    identity = b'\x7fELF\x02\x01\x01' + bytes(9)
    segments = [(1, 5, code_offset, 0x2000, 0, len(code), len(code), 4), *extra_segments]
    header = ELF_HEADER.pack(identity, 3, 183, 1, 0x2000, 64, 0, 0, 64, 56, len(segments), 0, 0, 0)
    data = bytearray(code_offset + len(code))
    data[:64] = header
    for index, segment in enumerate(segments):
        PROGRAM_HEADER.pack_into(data, 64 + index * 56, *segment)
    data[code_offset:] = code
    return data


class RuntimeEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'authored.so'
        self.sentinel = self.root / 'sentinel.txt'
        self.sentinel.write_text('unchanged')

    def collect(self, data):
        self.path.write_bytes(data)
        try:
            result = collect_guard_evidence(self.path)
        finally:
            self.assertEqual(self.path.read_bytes(), data)
            self.assertEqual(self.sentinel.read_text(), 'unchanged')
            self.assertEqual({p.name for p in self.root.iterdir()}, {self.path.name, 'sentinel.txt'})
        return result

    def reject(self, data, message=None):
        with self.assertRaisesRegex(EvidenceError, message or '.'):
            self.collect(data)

    def test_both_guard_kinds_record_original_virtual_addresses(self):
        code = pack_words(guard_words() + guard_words(native=True))
        result = self.collect(elf_fixture(code))
        self.assertEqual(result.status, GuardStatus.CONSISTENT)
        self.assertEqual([site.address for site in result.observations], [0x2004, 0x2018])
        self.assertEqual([site.kind for site in result.observations], [GuardKind.LEAF, GuardKind.NATIVE])
        self.assertEqual([site.target_register for site in result.observations], [16, 9])
        self.assertTrue(all(site.offsets == GuardOffsets(0x80, 0x100) for site in result.observations))
        self.assertEqual(result.bytes_scanned, len(code))

    def test_offsets_are_observed_not_taken_from_a_profile(self):
        for state, tag in ((0, 0), (0x180, 0x200), (0x7ff8, 0x7ff8)):
            with self.subTest(state=state, tag=tag):
                result = self.collect(elf_fixture(pack_words(guard_words(state, tag))))
                self.assertEqual(result.observations[0].offsets, GuardOffsets(state, tag))

    def test_native_targets_keep_other_general_registers(self):
        for target in (0, 1, 12, 29, 30):
            with self.subTest(target=target):
                result = self.collect(elf_fixture(pack_words(guard_words(native=True, target=target))))
                self.assertEqual(result.observations[0].target_register, target)

    def test_scratch_thread_and_zero_register_targets_do_not_match(self):
        for target in (16, 26, 31):
            with self.subTest(target=target):
                result = self.collect(elf_fixture(pack_words(guard_words(native=True, target=target))))
                self.assertEqual(result.status, GuardStatus.NOT_OBSERVED)

    def test_missing_store_context_is_partial_not_a_default(self):
        result = self.collect(elf_fixture(pack_words(guard_words(tag=None))))
        self.assertEqual(result.status, GuardStatus.PARTIAL)
        self.assertIsNone(result.observations[0].offsets.vm_tag)

    def test_mixed_complete_and_missing_context_stays_partial(self):
        result = self.collect(elf_fixture(pack_words(guard_words() + guard_words(tag=None))))
        self.assertEqual(result.status, GuardStatus.PARTIAL)

    def test_different_states_or_tags_conflict_without_majority_selection(self):
        for other in (guard_words(state=0x180), guard_words(tag=0x200)):
            with self.subTest(other=other):
                code = pack_words(guard_words() * 4 + other)
                result = self.collect(elf_fixture(code))
                self.assertEqual(result.status, GuardStatus.CONFLICTING)
                self.assertEqual(len(result.observations), 5)

    def test_missing_context_does_not_hide_conflicting_states(self):
        code = pack_words(guard_words() + guard_words(state=0x180, tag=None))
        self.assertEqual(self.collect(elf_fixture(code)).status, GuardStatus.CONFLICTING)

    def test_empty_or_unrecognized_code_proves_no_absence(self):
        for code in (b'', pack_words([NOP] * 8)):
            with self.subTest(code=code):
                result = self.collect(elf_fixture(code))
                self.assertEqual(result.status, GuardStatus.NOT_OBSERVED)
                self.assertEqual(result.observations, ())

    def test_results_are_immutable(self):
        result = self.collect(elf_fixture(pack_words(guard_words())))
        for value, field, replacement in ((result, 'bytes_scanned', 0),
                                           (result.observations[0], 'address', 0),
                                           (result.observations[0].offsets, 'state', 0)):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(value, field, replacement)

    def test_changed_guard_instructions_do_not_match(self):
        original = guard_words(tag=None)
        changes = [(index, NOP) for index in range(4)]
        changes.extend((index, original[index] ^ mask) for index, mask in
                       ((0, 1), (0, 1 << 5), (0, 1 << 30), (1, 1), (1, 1 << 5),
                        (1, 1 << 24), (1, 1 << 31), (2, 1 << 5), (3, 1 << 5)))
        for index, word in changes:
            with self.subTest(index=index, word=word):
                changed = original.copy()
                changed[index] = word
                result = self.collect(elf_fixture(pack_words(changed)))
                self.assertEqual(result.status, GuardStatus.NOT_OBSERVED)

    def test_negative_branch_and_wrong_continuation_do_not_match(self):
        for displacement in (-1, 0, 1, 3):
            words = guard_words(tag=None)
            words[1] = 0xb4000000 | ((displacement & 0x7ffff) << 5) | 17
            with self.subTest(displacement=displacement):
                self.assertEqual(self.collect(elf_fixture(pack_words(words))).observations, ())

    def test_truncated_guards_and_trailing_bytes_are_not_overread(self):
        code = pack_words(guard_words(tag=None))
        for length in range(len(code)):
            with self.subTest(length=length):
                self.assertEqual(self.collect(elf_fixture(code[:length])).observations, ())
        for tail in (b'x', b'xx', b'xxx'):
            result = self.collect(elf_fixture(code + tail))
            self.assertEqual(len(result.observations), 1)
            self.assertEqual(result.bytes_scanned, len(code + tail))

    def test_nonmatching_store_context_is_not_invented(self):
        for mask in (1, 1 << 5, 1 << 30):
            words = guard_words()
            words[0] ^= mask
            with self.subTest(mask=mask):
                result = self.collect(elf_fixture(pack_words(words)))
                self.assertEqual(result.status, GuardStatus.PARTIAL)
                self.assertIsNone(result.observations[0].offsets.vm_tag)

    def test_guards_across_chunk_edges_keep_context_and_are_not_duplicated(self):
        for padding in range(8):
            code = pack_words([NOP] * padding + guard_words() * 3)
            with self.subTest(padding=padding), patch.object(evidence, 'SCAN_CHUNK_BYTES', 32):
                result = self.collect(elf_fixture(code))
                self.assertEqual(len(result.observations), 3)
                self.assertEqual(result.status, GuardStatus.CONSISTENT)
                self.assertEqual([site.address for site in result.observations],
                                 [0x2004 + padding * 4 + index * 20 for index in range(3)])

    def test_other_segments_and_section_metadata_are_not_scanned(self):
        code = pack_words(guard_words())
        data = elf_fixture(code)
        struct.pack_into('<I', data, 68, 4)
        self.assertEqual(self.collect(data).observations, ())
        data = elf_fixture(code)
        struct.pack_into('<Q', data, 40, (1 << 64) - 1)
        struct.pack_into('<HHH', data, 58, 64, 0xffff, 0xffff)
        with patch.object(evidence.ELFFile, 'get_section', side_effect=AssertionError('section traversal')):
            self.assertEqual(len(self.collect(data).observations), 1)

    def test_dynamic_segments_do_not_trigger_section_or_symbol_loading(self):
        dynamic = (2, 6, (1 << 64) - 1, 0, 0, (1 << 64) - 1, 0, 0)
        data = elf_fixture(pack_words(guard_words()), [dynamic])
        with patch.object(evidence.ELFFile, 'get_section', side_effect=AssertionError('section traversal')), \
                patch.object(evidence.ELFFile, 'get_segment', side_effect=AssertionError('segment construction')):
            self.assertEqual(len(self.collect(data).observations), 1)

    def test_adjacent_segments_are_not_joined_into_a_guard(self):
        second = (1, 5, 0x408, 0x2008, 0, 12, 12, 4)
        data = elf_fixture(pack_words(guard_words()), [second])
        struct.pack_into('<Q', data, 96, 8)
        struct.pack_into('<Q', data, 104, 8)
        self.assertEqual(self.collect(data).observations, ())

    def test_context_before_the_segment_is_not_used(self):
        words = guard_words()
        data = elf_fixture(pack_words(words[1:]))
        struct.pack_into('<I', data, 0x3fc, words[0])
        self.assertEqual(self.collect(data).status, GuardStatus.PARTIAL)

    def test_all_headers_are_checked_before_any_payload_scan(self):
        data = elf_fixture(pack_words(guard_words()), [(1, 5, 0x100000, 0x3000, 0, 20, 20, 4)])
        with patch.object(evidence, '_scan_segment', side_effect=AssertionError('partial scan')):
            self.reject(data, 'Load segment')

    def test_oversized_input_is_rejected_before_elf_parsing(self):
        data = elf_fixture(pack_words(guard_words()))
        with patch.object(evidence, 'MAX_LIBRARY_BYTES', len(data) - 1), \
                patch.object(evidence, 'ELFFile', side_effect=AssertionError('parsed oversized file')):
            self.reject(data, 'bounded regular')

    def test_code_budget_is_total_and_checked_before_scanning(self):
        data = elf_fixture(pack_words(guard_words()))
        with patch.object(evidence, 'MAX_CODE_BYTES', 19), \
                patch.object(evidence, '_scan_segment', side_effect=AssertionError('scanned oversized code')):
            self.reject(data, 'scan limit')

        second = (1, 5, 0x414, 0x3000, 0, 20, 20, 4)
        data = elf_fixture(pack_words(guard_words() * 2), [second])
        struct.pack_into('<Q', data, 96, 20)
        struct.pack_into('<Q', data, 104, 20)
        with patch.object(evidence, 'MAX_CODE_BYTES', 30), \
                patch.object(evidence, '_scan_segment', side_effect=AssertionError('partial scan')):
            self.reject(data, 'scan limit')

    def test_input_and_code_budget_boundaries_are_accepted(self):
        data = elf_fixture(pack_words(guard_words()))
        with patch.object(evidence, 'MAX_CODE_BYTES', 20), patch.object(evidence, 'MAX_LIBRARY_BYTES', len(data)):
            self.assertEqual(len(self.collect(data).observations), 1)

    def test_program_header_count_boundary_is_accepted(self):
        data = elf_fixture(pack_words(guard_words()), [(0,) * 8] * 255, code_offset=0x4000)
        self.assertEqual(len(self.collect(data).observations), 1)

    def test_observation_budget_accepts_the_boundary_and_refuses_partial_results(self):
        with patch.object(evidence, 'MAX_GUARD_SITES', 2):
            self.assertEqual(len(self.collect(elf_fixture(pack_words(guard_words() * 2))).observations), 2)
            self.reject(elf_fixture(pack_words(guard_words() * 3)), 'observations')

    def test_observation_budget_is_shared_across_segments(self):
        second = (1, 5, 0x414, 0x3000, 0, 40, 40, 4)
        data = elf_fixture(pack_words(guard_words() * 3), [second])
        struct.pack_into('<Q', data, 96, 20)
        struct.pack_into('<Q', data, 104, 20)
        with patch.object(evidence, 'MAX_GUARD_SITES', 2):
            self.reject(data, 'observations')

    def test_malformed_and_truncated_elf_headers_are_rejected(self):
        data = elf_fixture(pack_words(guard_words()))
        self.reject(b'not an ELF' * 8)
        for size in (0, 1, 16, 63):
            with self.subTest(size=size):
                self.reject(data[:size])
        for offset, value in ((4, 0), (4, 1), (5, 0), (5, 2), (6, 0)):
            changed = data.copy()
            changed[offset] = value
            with self.subTest(offset=offset):
                self.reject(changed)

    def test_wrong_targets_header_sizes_and_extended_counts_are_rejected(self):
        data = elf_fixture(pack_words(guard_words()))
        fields = [(16, '<H', 1), (18, '<H', 62), (20, '<I', 0), (52, '<H', 0),
                  (54, '<H', 0), (56, '<H', 257), (56, '<H', 0xffff), (32, '<Q', 0),
                  (32, '<Q', len(data) - 1), (32, '<Q', (1 << 64) - 1)]
        for offset, fmt, value in fields:
            changed = data.copy()
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset, value=value):
                self.reject(changed)

    def test_bad_load_extents_alignments_and_address_wrap_are_rejected(self):
        data = elf_fixture(pack_words(guard_words()))
        fields = [(72, len(data)), (72, (1 << 64) - 1), (80, 0x2001),
                  (96, len(data)), (96, (1 << 64) - 1), (104, 19),
                  (104, (1 << 64) - 1), (112, 3), (112, 0x1000)]
        for offset, value in fields:
            changed = data.copy()
            struct.pack_into('<Q', changed, offset, value)
            with self.subTest(offset=offset, value=value):
                self.reject(changed)

    def test_overlapping_executable_mappings_are_rejected(self):
        code = pack_words(guard_words())
        for segment in ((1, 5, 0x400, 0x2000, 0, 20, 20, 4),
                        (1, 5, 0x400, 0x3000, 0, 20, 20, 4)):
            with self.subTest(segment=segment):
                self.reject(elf_fixture(code, [segment]), 'Overlapping executable')

    def test_bss_bytes_are_not_scanned(self):
        data = elf_fixture(pack_words(guard_words()))
        struct.pack_into('<Q', data, 104, 0x10000)
        result = self.collect(data)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.bytes_scanned, 20)

    def test_segment_order_does_not_change_observation_order(self):
        second = (1, 5, 0x414, 0x1000, 0, 20, 20, 4)
        data = elf_fixture(pack_words(guard_words() * 2), [second])
        struct.pack_into('<Q', data, 96, 20)
        struct.pack_into('<Q', data, 104, 20)
        result = self.collect(data)
        self.assertEqual([site.address for site in result.observations], [0x1004, 0x2004])

    def test_file_descriptors_are_closed_when_header_validation_fails(self):
        original_open = os.open
        descriptors = []

        def record_open(*arguments):
            descriptor = original_open(*arguments)
            descriptors.append(descriptor)
            return descriptor

        with patch.object(binary_input.os, 'open', side_effect=record_open):
            self.reject(b'not an ELF' * 8)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_last_address_space_word_is_supported_without_wrap(self):
        data = elf_fixture(pack_words(guard_words()))
        struct.pack_into('<Q', data, 80, (1 << 64) - 20)
        result = self.collect(data)
        self.assertEqual(result.observations[0].address, (1 << 64) - 16)

    def test_short_payload_reads_are_refused(self):
        segment = evidence._CodeSegment(0, 0x1000, 20, 20)
        with self.assertRaisesRegex(EvidenceError, 'Truncated'):
            evidence._scan_segment(io.BytesIO(bytes(19)), segment, [])

    def test_authored_header_bit_mutations_remain_bounded(self):
        original = elf_fixture(pack_words(guard_words()))
        for offset in range(120):
            for bit in range(8):
                data = original.copy()
                data[offset] ^= 1 << bit
                with self.subTest(offset=offset, bit=bit):
                    try:
                        result = self.collect(data)
                    except EvidenceError:
                        continue
                    self.assertLessEqual(result.bytes_scanned, len(data))
                    self.assertLessEqual(len(result.observations), 1)

    def test_input_paths_are_data_not_commands(self):
        self.path = self.root / ".authored file's \u03a9.so"
        self.assertEqual(len(self.collect(elf_fixture(pack_words(guard_words()))).observations), 1)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFOs')
    def test_nonregular_input_is_refused_without_waiting_for_a_writer(self):
        path = self.root / 'authored.pipe'
        os.mkfifo(path)
        with self.assertRaisesRegex(EvidenceError, 'regular'):
            collect_guard_evidence(path)


if __name__ == '__main__':
    unittest.main()
