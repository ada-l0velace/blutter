"""Authored controls for independent original-instruction and pool checks."""
from pathlib import Path
import sys
import unittest
import capstone
from capstone import arm64

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_snapshot_annotations import constant_move, decode_dispatch_table, decode_payload, folded_immediate_bits, integer_operation


class AnnotationChecks(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.decoder.detail = True

    def test_allocated_load_preserves_original_identity_and_effects(self):
        word = 0xf8400800 | (0x1f8 << 12) | (4 << 5) | 4  # ldtr x4, [x4, #-8]
        raw = b''.join(w.to_bytes(4, 'little') for w in (0xd503201f, word, 0xd65f03c0))
        instructions = decode_payload(self.decoder, raw, 0x1000)
        self.assertEqual([i.address for i in instructions], [0x1000, 0x1004, 0x1008])
        load = instructions[1]
        self.assertEqual((load.id, load.mnemonic, bytes(load.bytes)),
                         (arm64.ARM64_INS_LDTR, 'ldtr', raw[4:8]))
        self.assertEqual(load.operands[1].mem.disp, -8)
        self.assertEqual(load.operands[1].mem.base, arm64.ARM64_REG_X4)
        self.assertFalse(load.writeback)
        self.assertIn(arm64.ARM64_REG_X4, load.regs_access()[1])

    def test_invalid_words_and_truncation_stay_errors(self):
        for raw in (b'\xff' * 4, b'\0' * 3):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                decode_payload(self.decoder, raw, 0x1000)

    def test_folded_immediate_reconstruction_is_exact_and_bounded(self):
        self.assertEqual(folded_immediate_bits('0x800 - authored', 0x1000), 0x1800)
        self.assertEqual(folded_immediate_bits('0xfffffffffffff008 - unknown', 0x1000), 8)
        for value in ('IMM: 0x800', '0x10000000000000000 - oversized', '0x800 suffix'):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                folded_immediate_bits(value, 0x1000)

    def test_constant_moves_from_words(self):
        self.assertEqual(constant_move(0xd2800000 | (3 << 21) | (0x1234 << 5) | 5),
                         ('literal', 5, 64, 0x1234000000000000))
        self.assertEqual(constant_move(0x12800000 | (1 << 21) | (0x1234 << 5) | 1),
                         ('literal', 1, 32, 0xedcbffff))
        self.assertEqual(constant_move(0x72800000 | (1 << 21) | (0xabcd << 5) | 6),
                         ('keep', 6, 32, (0xabcd0000, 0xffff0000)))
        self.assertEqual(constant_move(0xaa0103e0), ('copy', 0, 64, 1))
        self.assertEqual(constant_move(0x2a1f03e4), ('copy', 4, 32, 31))
        for word in (0x32800000, 0x52c00000, 0x528003ff, 0x91000400):
            # Reserved move-wide encodings, an unrelated ADD, or ZR as a
            # destination cannot justify a fact about a physical X register.
            if word == 0x528003ff:
                self.assertEqual(constant_move(word)[1], 31)
            else:
                self.assertIsNone(constant_move(word))

    def test_logical_move_masks_match_independent_bit_pattern(self):
        # ORR-immediate MOV aliases: repeated bytes, rotated bits, 32-bit zero extension.
        self.assertEqual(constant_move(0xb2009fe0), ('literal', 0, 64, 0xff00ff00ff00ff))
        self.assertEqual(constant_move(0xb20103e0), ('literal', 0, 64, 0x8000000080000000))
        self.assertEqual(constant_move(0x32009fe0), ('literal', 0, 32, 0xff00ff))
        self.assertIsNone(constant_move(0x324003e0))  # invalid N for a W destination
        self.assertIsNone(constant_move(0xb200ffe0))  # reserved all-ones element

    def test_dispatch_compression_codes_repeats_recent_and_null(self):
        # Unsigned length 6, first cluster reference 1. Signed values:
        # code index 1 (65), repeat twice, null, recent[0], code index 2 (66).
        raw = bytes([134, 129, 65, 192, 194, 192, 191, 66, 192])
        self.assertEqual(decode_dispatch_table(raw, [0x1000, 0x2000], 0x3000),
                         [0x1000, 0x1000, 0x1000, 0x3000, 0x1000, 0x2000])
        self.assertEqual(decode_dispatch_table(bytes([128]), [], None), [])

    def test_dispatch_bad_encodings_are_rejected(self):
        for raw in (b'', bytes([129]), bytes([129, 128, 191]),  # unused recent
                    bytes([129, 128, 193]),  # repeat without a value
                    bytes([129, 128, 64, 192]),  # reserved Code index zero
                    bytes([129, 128, 66, 192]),  # Code index outside inventory
                    bytes([130, 128, 192, 194]),  # repeat past end
                    bytes([128, 128]), b'\x00' * 11):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                decode_dispatch_table(raw, [0x1000], 0x3000)
        with self.assertRaises(AssertionError):
            decode_dispatch_table(bytes([130, 128, 192, 192]), [], 0x3000, max_entries=1)

    def test_integer_arithmetic_words(self):
        self.assertEqual(integer_operation(0xd1001401), ('sub', 1, 64, (0, 'immediate', 5)))
        self.assertEqual(integer_operation(0x8b11001e), ('add', 30, 64, (0, 'register', 17)))
        self.assertEqual(integer_operation(0xd34c7c00), ('extract', 0, 64, (0, 12, 20)))
        self.assertIsNone(integer_operation(0x910003e0))  # ADD from SP
        self.assertIsNone(integer_operation(0x8b010400))  # shifted source


if __name__ == '__main__':
    unittest.main()
