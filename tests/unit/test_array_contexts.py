"""Authored caller bindings and entry-read certificates; no app fixtures."""
import copy
import unittest

import test_array_certificates as fixture
from check_receiver_analysis import check_receivers


class ArrayContexts(unittest.TestCase):
    def setUp(self):
        self.base = fixture.ArrayCertificates()
        self.base.setUp()
        self.graph = copy.deepcopy(self.base.graph)
        self.graph['format'] = 15
        self.graph['nodes'].append({'start': 0x4000, 'end': 0x4010, 'names': []})
        self.graph['receiver_metadata']['entries'] = [0x2000, 0x2004, 0x4000]
        self.context = {'payload': 0x4000, 'callers': [0x1014],
                        'inputs': [{'sp_offset': 0, 'kind': 'heap_class', 'value': '0x2'}],
                        'array_input': {'sp_offset': 0, 'length': 2, 'elements': [[0, 1]]},
                        'scope': 'entry_block', 'status': 'bound_only', 'array_reads': [],
                        'resolutions': [], 'certificate': None}
        self.graph['array_contexts'] = [self.context]
        # LDR x8,[x15]; LDUR w9,[x8,#15]; ADD x2,x9,x28,LSL#32; RET.
        self.callee = [0xf94001e8, 0xb840f109, 0x8b1c8122, 0xd65f03c0]

    def prove_read(self):
        block = copy.deepcopy(self.graph['receiver_certificates'][0]['blocks'][0])
        block.update(start=0x4000, end=0x4010, live_inputs=[0])
        self.context.update(status='read_proved',
                            array_reads=[{'site': 0x4008, 'input_sp_offset': 0, 'index': 0,
                                          'class_id': 1, 'register': 'x2', 'proof': [0x4000, 0x4004, 0x4008]}],
                            certificate={'payload': 0x4000, 'blocks': [block]})

    def check(self):
        blobs = {0x1000: b''.join(w.to_bytes(4, 'little') for w in self.base.words),
                 0x4000: b''.join(w.to_bytes(4, 'little') for w in self.callee)}
        def read(address, size):
            for start, blob in blobs.items():
                if start <= address and address+size <= start+len(blob):
                    return blob[address-start:address-start+size]
            raise AssertionError('Fixture read outside authored bytes')
        return check_receivers(self.graph, read,
                               lambda raw, address: list(self.base.fixture.decoder.disasm(raw, address)),
                               self.base.audit)

    def test_bound_only_is_not_a_read(self):
        result = self.check()
        self.assertEqual(result['array_contexts_checked'], 1)
        self.assertEqual(result['array_context_callers_checked'], 1)
        self.assertEqual(result['array_context_reads_checked'], 0)

    def test_authored_entry_read_is_checked(self):
        self.prove_read()
        self.assertEqual(self.check()['array_context_reads_checked'], 1)

    def test_changed_callee_words_fail(self):
        for n, word in [(0, 0xf94005e8), (1, 0xb8413109), (2, 0x8b1b8122)]:
            with self.subTest(instruction=n):
                self.setUp()
                self.prove_read()
                self.callee[n] = word
                with self.assertRaises(AssertionError): self.check()

    def test_forged_bindings_fail(self):
        for defect in ('class', 'length', 'slot', 'index', 'boolean-index', 'scalar', 'caller', 'scope', 'duplicate-context', 'duplicate-caller', 'legacy', 'missing-proof', 'fake-read'):
            with self.subTest(defect=defect):
                self.setUp()
                if defect == 'class': self.context['array_input']['elements'] = [[0, 2]]
                elif defect == 'length': self.context['array_input']['length'] = 3
                elif defect == 'slot': self.context['array_input']['sp_offset'] = 8
                elif defect == 'index': self.context['array_input']['elements'] = [[1, 1]]
                elif defect == 'boolean-index': self.context['array_input']['elements'] = [[False, 1]]
                elif defect == 'scalar': self.context['inputs'][0]['value'] = '0x1'
                elif defect == 'caller': self.context['callers'] = [0x1004]
                elif defect == 'scope': self.context['scope'] = 'all_iterations'
                elif defect == 'duplicate-context': self.graph['array_contexts'].append(copy.deepcopy(self.context))
                elif defect == 'duplicate-caller': self.context['callers'] *= 2
                elif defect == 'legacy': self.graph['format'] = 14
                elif defect == 'missing-proof': self.graph['receiver_certificates'] = []
                else: self.context['array_reads'] = [{'site': 0x4008}]
                with self.assertRaises(AssertionError): self.check()

    def test_forged_reads_fail(self):
        for defect in ('class', 'index', 'slot', 'register', 'proof', 'site', 'missing-certificate', 'duplicate-read'):
            with self.subTest(defect=defect):
                self.setUp()
                self.prove_read()
                claim = self.context['array_reads'][0]
                if defect == 'class': claim['class_id'] = 2
                elif defect == 'index': claim['index'] = 1
                elif defect == 'slot': claim['input_sp_offset'] = 8
                elif defect == 'register': claim['register'] = 'x3'
                elif defect == 'proof': claim['proof'] = []
                elif defect == 'site': claim['site'] = 0x4004
                elif defect == 'missing-certificate': self.context['certificate'] = None
                else: self.context['array_reads'] *= 2
                with self.assertRaises(AssertionError): self.check()


if __name__ == '__main__':
    unittest.main()
