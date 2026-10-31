"""Authored conditional return invariants, with adversarial mutations."""
import copy
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import capstone
from check_array_returns import check_array_return


class ArrayReturnCertificates(unittest.TestCase):
    def setUp(self):
        # LDR array; LDR index; SBFX; ADD scaled; LDUR element; decompress; RET.
        self.words = [0xf94005e2, 0xf94001e4, 0x93417c85, 0x8b050850,
                      0xb840f200, 0x8b1c8000, 0xd65f03c0]
        self.claim = dict(array_sp_offset=8, index_sp_offset=0, index_representation='smi', index_min=0, index_max=31)
        regs = [[], [[2, 1, 8, 0]], [[2, 1, 8, 0], [4, 2, 0, 0]],
                [[2, 1, 8, 0], [4, 2, 0, 0], [5, 3, 0, 0]],
                [[16, 4, 8, 0]], [[0, 5, 8, 0]], [[0, 6, 8, 0]]]
        self.claim['states'] = [[0x1000+n*4, r] for n, r in enumerate(regs)]
        self.frames = {0x1000+n*4: (tuple([(1, 0) if r == 15 else (0, 0) for r in range(31)]), {}) for n in range(7)}
        self.metadata = dict(array_body_contract=[0x6000, 2, 15, 4, 1], heap_bits_register='x28', word_return_register='x0')
        self.audit = copy.deepcopy(self.metadata)
        self.decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True

    def check(self):
        code = list(self.decoder.disasm(b''.join(w.to_bytes(4, 'little') for w in self.words), 0x1000))
        return check_array_return(self.claim, code, self.frames, self.metadata, self.audit, {})

    def test_valid_inductive_relation(self):
        self.assertEqual(self.check(), 7)

    def test_forged_claims_fail(self):
        for defect in ('array', 'index', 'index-kind', 'lower-bound', 'upper-bound', 'seed', 'result', 'packed', 'missing-state', 'duplicate-state', 'duplicate-register', 'boolean-kind', 'wrong-audit', 'missing-heap-audit'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect == 'array': self.claim['array_sp_offset'] = 16
                elif defect == 'index': self.claim['index_sp_offset'] = 8
                elif defect == 'index-kind': self.claim['index_representation'] = 'word'
                elif defect == 'lower-bound': self.claim['index_min'] = -1
                elif defect == 'upper-bound': self.claim['index_max'] = 32
                elif defect == 'seed': self.claim['states'][0][1] = [[0, 6, 8, 0]]
                elif defect == 'result': self.claim['states'][-1][1] = [[0, 6, 16, 0]]
                elif defect == 'packed': self.claim['states'][-2][1] = [[0, 6, 8, 0]]
                elif defect == 'missing-state': self.claim['states'].pop(3)
                elif defect == 'duplicate-state': self.claim['states'].append(copy.deepcopy(self.claim['states'][2]))
                elif defect == 'duplicate-register': self.claim['states'][2][1].append([2, 1, 8, 0])
                elif defect == 'boolean-kind': self.claim['states'][1][1][0][1] = True
                elif defect == 'wrong-audit': self.audit['array_body_contract'][3] = 8
                else: self.audit.pop('heap_bits_register')
                with self.assertRaises(AssertionError): self.check()

    def test_changed_words_fail(self):
        for n, replacement in [(0, 0xf94009e2), (1, 0xf94005e4), (2, 0x93427c85),
                               (3, 0x8b050c50), (4, 0xb8413200), (5, 0x8b1b8000)]:
            with self.subTest(instruction=n):
                self.setUp()
                self.words[n] = replacement
                with self.assertRaises(AssertionError): self.check()


if __name__ == '__main__':
    unittest.main()
