import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_entry_trace import signed_field, branch_condition


class EntryPredicates(unittest.TestCase):
    def test_signed_extract(self):
        self.assertEqual(signed_field(0x93417d27, lambda *_: 4), 2)
        self.assertEqual(signed_field(0x93417d27, lambda *_: (1 << 64)-1), (1 << 64)-1)

    def test_signed_insert(self):
        self.assertEqual(signed_field(0x937f7927, lambda *_: 3), 6)
        self.assertEqual(signed_field(0x937f7927, lambda *_: (1 << 31)-1), (1 << 64)-2)

    def test_narrow_result_zero_extends(self):
        self.assertEqual(signed_field(0x13013d27, lambda *_: 0xffffffff), 0xffffffff)
        self.assertEqual(signed_field(0x131f3927, lambda *_: 0xffffffff), 0xfffffffe)

    def test_unknown_and_unsupported_fields(self):
        self.assertIsNone(signed_field(0x93417d27, lambda *_: None))
        self.assertIsNone(signed_field(0xd503201f, lambda *_: 0))

    def test_signed_and_unsigned_order(self):
        def read(number, _): return (1 << 64)-1 if number == 7 else 0
        self.assertFalse(branch_condition(0x5400008a, 0xeb0900ff, read))  # signed GE
        self.assertTrue(branch_condition(0x54000088, 0xeb0900ff, read))   # unsigned HI

    def test_boxing_shift(self):
        self.assertTrue(branch_condition(0x54000080, 0xeb8904ff, lambda *_: 0))
        self.assertFalse(branch_condition(0x54000081, 0xeb8904ff, lambda *_: 0))

    def test_predicate_requires_operands(self):
        self.assertIsNone(branch_condition(0x54000080, 0xeb0900ff, lambda *_: None))

    def test_wrong_branch_or_comparison(self):
        self.assertIsNone(branch_condition(0x14000000, 0xeb0900ff, lambda *_: 0))
        self.assertIsNone(branch_condition(0x54000080, 0xd503201f, lambda *_: 0))


if __name__ == '__main__':
    unittest.main()
