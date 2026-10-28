"""Authored controls for independent original-instruction and pool checks."""
from pathlib import Path
import sys
import unittest
import capstone
from capstone import arm64

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_snapshot_annotations import decode_payload, folded_immediate_bits


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


if __name__ == '__main__':
    unittest.main()
