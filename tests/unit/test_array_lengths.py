"""Authored length contracts and original-word adversarial controls."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import capstone
from check_array_lengths import check_array_length, checked_length_layout


class ArrayLengthCertificates(unittest.TestCase):
    def setUp(self):
        self.graph = {'format': 16, 'receiver_metadata': {'word_return_register': 'x0', 'array_length_layout': [2, 7, 4, 1]}}
        self.audit = copy.deepcopy(self.graph['receiver_metadata'])
        # Authored argument/field loads and normal return.
        self.words = [0xf94009e3, 0xb8407060, 0xd65f03c0]
        self.claim = dict(array_sp_offset=16, array_class_id=2, result_register='x0', result_representation='zero_extended_smi',
                          heap_effect='read_only', may_fault=True, proof=[0x1000, 0x1004, 0x1008])
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True

    def check(self):
        code = list(self.decoder.disasm(b''.join(w.to_bytes(4, 'little') for w in self.words), 0x1000))
        return check_array_length(self.claim, code, self.graph, self.audit)

    def test_narrow_and_full_word_relations(self):
        self.assertEqual(self.check(), 3)
        self.graph['receiver_metadata']['array_length_layout'][2] = 8
        self.audit['array_length_layout'][2] = 8
        self.words[1] = 0xf8407060
        self.claim['result_representation'] = 'smi'
        self.assertEqual(self.check(), 3)

    def test_overlapping_base_and_copies(self):
        self.words = [0xf94009e0, 0xb8407000, 0xd65f03c0]
        self.assertEqual(self.check(), 3)
        self.words = [0xaa0f03e5, 0xf94008a3, 0xb8407060, 0x2a0003e2, 0xaa0203e0, 0xd65f03c0]
        self.claim['proof'] = [0x1000+n*4 for n in range(len(self.words))]
        self.assertEqual(self.check(), 6)

    def test_forged_contracts_fail(self):
        for defect in ('slot', 'boolean-slot', 'class', 'boolean-class', 'result', 'representation', 'effect', 'fault',
                       'proof', 'missing-proof', 'duplicate-proof', 'boolean-proof', 'extra-field', 'missing-layout', 'layout', 'audit', 'abi', 'legacy'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect == 'slot': self.claim['array_sp_offset'] = 8
                elif defect == 'boolean-slot': self.claim['array_sp_offset'] = False
                elif defect == 'class': self.claim['array_class_id'] = 3
                elif defect == 'boolean-class': self.claim['array_class_id'] = True
                elif defect == 'result': self.claim['result_register'] = 'x1'
                elif defect == 'representation': self.claim['result_representation'] = 'smi'
                elif defect == 'effect': self.claim['heap_effect'] = 'unknown'
                elif defect == 'fault': self.claim['may_fault'] = 1
                elif defect == 'proof': self.claim['proof'].pop()
                elif defect == 'missing-proof': self.claim['proof'] = None
                elif defect == 'duplicate-proof': self.claim['proof'][1] = 0x1000
                elif defect == 'boolean-proof': self.claim['proof'][0] = True
                elif defect == 'extra-field': self.claim['unconditional'] = True
                elif defect == 'missing-layout': self.graph['receiver_metadata'].pop('array_length_layout')
                elif defect == 'layout': self.graph['receiver_metadata']['array_length_layout'][1] = 15
                elif defect == 'audit': self.audit['array_length_layout'][1] = 15
                elif defect == 'abi': self.audit['word_return_register'] = None
                else: self.graph['format'] = 15
                with self.assertRaises(AssertionError): self.check()

    def test_modified_words_and_effects_fail(self):
        for n, word in [(0, 0xf94005e3), (0, 0xb94009e3), (1, 0xb840b060), (1, 0xf8407060),
                        (1, 0xb8807060), (1, 0xb8407c60), (1, 0xb8407460), (1, 0x38407060),
                        (1, 0xb8007069), (1, 0xf90001e0), (1, 0xd5033bbf), (1, 0x94000001),
                        (2, 0xd65f0260), (2, 0x14000000)]:
            with self.subTest(word=hex(word)):
                self.setUp(); self.words[n] = word
                with self.assertRaises(AssertionError): self.check()

    def test_unknown_or_narrowed_input_and_changed_result_fail(self):
        for word in (0x2a0303e3, 0xaa0903e3, 0xaa0003ef, 0xaa0003fd, 0xaa0003fe):
            with self.subTest(word=hex(word)):
                self.setUp(); self.words.insert(1, word)
                self.claim['proof'] = [0x1000+n*4 for n in range(len(self.words))]
                with self.assertRaises(AssertionError): self.check()
        for word in (0x91000400, 0xd2800000):  # Return length+1 or a constant instead.
            with self.subTest(result=hex(word)):
                self.setUp(); self.words.insert(2, word)
                self.claim['proof'] = [0x1000+n*4 for n in range(len(self.words))]
                with self.assertRaises(AssertionError): self.check()

    def test_no_return_or_trailing_code_fails(self):
        for change in ('missing', 'trailing', 'long'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'missing': self.words[-1] = 0xd503201f
                elif change == 'trailing': self.words.append(0xd503201f)
                else: self.words = [0xd503201f]*30 + self.words
                self.claim['proof'] = [0x1000+n*4 for n in range(len(self.words))]
                with self.assertRaises(AssertionError): self.check()

    def test_old_graphs_without_layout_remain_supported(self):
        self.graph['format'] = 15
        self.graph['receiver_metadata'].pop('array_length_layout')
        self.assertIsNone(checked_length_layout(self.graph, self.audit))

    def test_register_mask_is_required_and_checked_in_new_format(self):
        self.graph['format'] = 17
        self.claim['written_registers'] = 9
        self.assertEqual(self.check(), 3)
        for mask in (1, 8, 11, True, -1):
            with self.subTest(mask=mask), self.assertRaises(AssertionError):
                self.claim['written_registers'] = mask
                self.check()


if __name__ == '__main__':
    unittest.main()
