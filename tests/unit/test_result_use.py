import sys
import unittest
from pathlib import Path
import capstone
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_result_use import reads_result, transfer


class RegisterProvenance(unittest.TestCase):
    def setUp(self):
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True

    @staticmethod
    def number(ins, reg):
        name = ins.reg_name(reg)
        if name in ('fp', 'lr'): return 29 if name == 'fp' else 30
        return int(name[1:]) if name.startswith(('x', 'w')) and name[1:].isdigit() else -1

    def decode(self, word):
        return next(self.decoder.disasm(word.to_bytes(4, 'little'), 0x1000))

    def test_copy_reads_returned_value(self):
        self.assertTrue(reads_result(self.decode(0xaa0003e2), 1, self.number))
        self.assertFalse(reads_result(self.decode(0xaa0003e2), 2, self.number))

    def test_literal_has_no_value_dependency(self):
        self.assertFalse(reads_result(self.decode(0xd2800020), 1, self.number))

    def test_memory_address_reads_returned_value(self):
        self.assertTrue(reads_result(self.decode(0xf85ff001), 1, self.number))

    def test_partial_write_reads_previous_destination(self):
        self.assertTrue(reads_result(self.decode(0xf2a00005), 1 << 5, self.number))

    def test_definition_kills_old_provenance(self):
        state = [(0, 0)]*31
        state[0] = (1, 1)
        self.assertEqual(transfer(1, {0}, 0, True, False, state), 0)

    def test_known_copy_propagates(self):
        state = [(0, 0)]*31
        state[0], state[2] = (3, 1), (3, 1)
        self.assertEqual(transfer(1, {2}, 2, True, True, state), 5)

    def test_unknown_facts_do_not_support_a_target(self):
        self.assertEqual(transfer(1, set(), -1, False, True, [(0, 0)]*31), 0)

    def test_store_does_not_create_register_or_spill_provenance(self):
        state = [(0, 0)]*31
        state[0], state[29] = (3, 1), (8, 0)
        self.assertEqual(transfer(1, set(), 0, False, True, state), 1)


if __name__ == '__main__':
    unittest.main()
