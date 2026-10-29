"""Original-word checks for derived heap addresses and barrier effects."""
import copy
import unittest

import test_spill_certificates as spill_fixture


class HeapAddressCertificates(unittest.TestCase):
    def setUp(self):
        self.fixture = spill_fixture.SpillCertificates()
        self.fixture.setUp()
        graph, audit = self.fixture.graph, self.fixture.audit
        graph['format'] = 8
        graph['nodes'][0]['end'] = 0x1040
        metadata = graph['receiver_metadata']
        metadata['pool_classes'] = [[3, 2]]
        metadata['frame_preserving_calls'] = [[0x9000, 'array_write_barrier']]
        metadata['preserved_call_registers'] = [[0x9000, 31]]
        audit['pool_heap_classes'] = [[3, 2]]
        audit['frame_preserving_calls'] = [[0x9000, 'array_write_barrier']]
        audit['preserved_call_registers'] = [[0x9000, 31]]
        graph['dispatch_table']['entries'].append(0x2008)
        # Prefix from the authored spill fixture, then LDUR x1,[FP,#-8];
        # ADD x25,x1,#15; B +4; STR wzr,[x25]; BL barrier; reload/CID/GDT.
        self.words = [0xa9bf79fd, 0xaa0f03fd, 0xd10081ef, 0xf9401760, 0xf81f83a0, 0x94000ffb,
                      0xf85f83a1, 0x91003c39, 0x14000001, 0xb900033f, 0x94001ff6,
                      0xf85f83a2, 0xf85ff040, 0xd3485c00, 0xf8607abe, 0xd63f03c0]
        graph['edges'] = [graph['edges'][0], {'site': 0x1028, 'source': 0x1000, 'kind': 'call', 'target': 0x9000},
                          {'site': 0x103c, 'source': 0x1000, 'kind': 'indirect_call', 'target': None,
                           'static_dispatch': {'load': 0x1038, 'index': 2, 'table_index': 2, 'snapshot_target': 0x2008,
                                               'proof': list(range(0x1000, 0x103c, 4))}}]
        blocks = graph['receiver_certificates'][0]['blocks']
        blocks[1]['end'] = 0x1024
        blocks[1]['spills'] = [[-24, 2]]
        blocks[1]['facts'].append([0, 3, '0x2', '0x0', '0x0'])
        before = copy.deepcopy(blocks[1])
        before.update(start=0x1024, end=0x102c)
        before['facts'].extend([[1, 3, '0x2', '0x0', '0x0'], [25, 10, '0xf', '0x2', '0x0']])
        after = copy.deepcopy(blocks[1])
        after.update(start=0x102c, end=0x1040)
        blocks.extend([before, after])

    def check(self):
        self.fixture.raw = b''.join(w.to_bytes(4, 'little') for w in self.words)
        return self.fixture.check()

    def test_valid_derived_store_and_barrier_preserve_class(self):
        self.assertEqual(self.check()['receiver_claims_checked'], 1)

    def test_forged_offset_class_and_bounds_fail(self):
        original = copy.deepcopy(self.fixture.graph)
        for column, value in ((2, '0x10'), (2, '0x100001'), (2, '0x0'), (3, '0x3'), (3, '0x10000')):
            self.fixture.graph = copy.deepcopy(original)
            self.fixture.graph['receiver_certificates'][0]['blocks'][2]['facts'][-1][column] = value
            with self.subTest(column=column, value=value), self.assertRaises(AssertionError):
                self.check()

    def test_derived_header_write_kills_the_spill(self):
        self.words[7] = 0xd1000439  # SUB x25,x1,#1: actual header address.
        self.fixture.graph['receiver_certificates'][0]['blocks'][2]['facts'][-1][2] = '0xffffffffffffffff'
        with self.assertRaises(AssertionError):
            self.check()

    def test_unknown_base_does_not_establish_heap_address(self):
        self.words[6] = 0xf9400ba1  # LDR x1,[FP,#16], unbound input.
        with self.assertRaises(AssertionError):
            self.check()

    def test_clobbered_slot_register_cannot_survive_barrier(self):
        self.fixture.graph['receiver_certificates'][0]['blocks'][3]['facts'].append([25, 10, '0xf', '0x2', '0x0'])
        with self.assertRaises(AssertionError):
            self.check()

    def test_barrier_contract_requires_independent_audit_and_safe_mask(self):
        self.fixture.audit['frame_preserving_calls'] = []
        with self.assertRaises(AssertionError):
            self.check()
        self.fixture.audit['frame_preserving_calls'] = [[0x9000, 'array_write_barrier']]
        mask = 31 | (1 << 25)
        self.fixture.audit['preserved_call_registers'] = [[0x9000, mask]]
        self.fixture.graph['receiver_metadata']['preserved_call_registers'] = [[0x9000, mask]]
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == '__main__':
    unittest.main()
