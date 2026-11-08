"""Authored scoped-record presentation; native fixtures check original words."""
import copy
from io import StringIO
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from indirect_result_records import indirect_results
from query_register_inputs import query, render
from check_call_result_notes import expected_facts, check_stream


class IndirectResults(unittest.TestCase):
    def setUp(self):
        self.row = dict(site=0x200c, callee=0x3000, class_id=8, register='x0',
                        basis='machine_return_summary', proof=[0x2000, 0x2004, 0x2008, 0x200c])
        self.context = dict(payload=0x2000, callers=[0x1004], inputs=[dict(sp_offset=8, kind='word', value='0x2a')],
                            register_inputs=[dict(register='x1', class_id=7)], normal_return_class=None,
                            resolutions=[dict(site=0x200c, load=0x2008, snapshot_target=0x3000)], stack_observations=[],
                            certificate=dict(payload=0x2000, indirect_returns=[self.row]))
        self.graph = dict(format=28,
                          nodes=[dict(start=0x1000, end=0x1008), dict(start=0x2000, end=0x2020),
                                 dict(start=0x3000, end=0x3008)],
                          edges=[dict(site=0x1004, source=0x1000, kind='call', target=0x2000),
                                 dict(site=0x200c, source=0x2000, kind='indirect_call', target=None)],
                          receiver_metadata=dict(word_return_register='x0', machine_return_classes=[[0x3000, 8]]),
                          register_contexts=[self.context])
        self.note = ('// caller-result @0x200c [payload 0x2000]: indirect normal-return X0 -> class 0x8 '
                     '("Example") [callee 0x3000; entry regs x1=0x7; stack SP+8:word=0x2a; after calls none]\n')
        self.instruction = '// 0x200c: blr x30\n'

    def test_query_preserves_conditions_and_original_callers(self):
        result = query(self.graph, 0x200c)
        record = result['indirect_results'][0]
        self.assertEqual(record['entry_register_inputs'], self.context['register_inputs'])
        self.assertEqual(record['entry_stack_inputs'], self.context['inputs'])
        self.assertEqual(record['callers'], [0x1004])
        self.assertIn('target 0x3000; normal-return X0: class 0x8', render(result))
        self.assertIn('Call 0x200c -> context-dependent', render(result))
        self.assertEqual(query(self.graph, 0x1004)['indirect_results'], [])

    def test_older_output_is_not_reconstructed_from_block_facts(self):
        self.graph['format'] = 27
        self.context['certificate'].pop('indirect_returns')
        self.assertEqual(indirect_results(self.graph), [])
        self.assertIn('no explicit record', render(query(self.graph, 0x200c)))
        self.assertEqual(indirect_results({}), [])

    def test_old_format_cannot_claim_explicit_results(self):
        self.graph['format'] = 27
        with self.assertRaises(ValueError):
            indirect_results(self.graph)

    def test_mismatched_targets_classes_and_proof_are_rejected(self):
        for defect in ('callee', 'class', 'proof', 'basis', 'site', 'register', 'abi'):
            with self.subTest(defect=defect):
                graph = copy.deepcopy(self.graph); row = graph['register_contexts'][0]['certificate']['indirect_returns'][0]
                if defect == 'callee': row['callee'] += 4
                if defect == 'class': row['class_id'] += 1
                if defect == 'proof': row['proof'].pop()
                if defect == 'basis': row['basis'] = 'guessed'
                if defect == 'site': row['site'] = 0x1004
                if defect == 'register': row['register'] = 'x1'
                if defect == 'abi': graph['receiver_metadata']['word_return_register'] = None
                with self.assertRaises(ValueError): indirect_results(graph)

    def test_scope_cannot_be_duplicated_or_attached_to_wrong_caller(self):
        for defect in ('register', 'stack', 'caller'):
            with self.subTest(defect=defect):
                graph = copy.deepcopy(self.graph); context = graph['register_contexts'][0]
                if defect == 'register': context['register_inputs'] *= 2
                if defect == 'stack': context['inputs'] *= 2
                if defect == 'caller': context['callers'] = [0x200c]
                with self.assertRaises(ValueError): indirect_results(graph)

    def test_assembly_annotation_matches_all_conditions(self):
        expected = expected_facts(self.graph)
        observed, _ = check_stream(StringIO(self.note + self.instruction), expected, {8: 'Example'})
        self.assertEqual(set(observed), expected)
        for old, new in [('x1=0x7', 'x1=0x8'), ('word=0x2a', 'word=0x2b'),
                         ('callee 0x3000', 'callee 0x3004'), ('Example', 'Wrong')]:
            with self.subTest(old=old):
                with self.assertRaises(AssertionError):
                    check_stream(StringIO(self.note.replace(old, new) + self.instruction), expected, {8: 'Example'})

    def test_global_dispatch_can_supply_the_matching_target(self):
        self.graph['edges'][1]['static_dispatch'] = self.context['resolutions'].pop()
        self.assertEqual(indirect_results(self.graph)[0]['callee'], 0x3000)

    def test_prior_result_conditions_remain_separate_from_entry_parameters(self):
        self.graph['edges'].append(dict(site=0x2000, source=0x2000, kind='call', target=0x4000))
        context = copy.deepcopy(self.context)
        context.pop('register_inputs');context.pop('inputs');context.pop('callers')
        context['return_bindings'] = [dict(site=0x2000, callee=0x4000, class_id=7)]
        self.graph['register_contexts'] = []
        self.graph['call_result_contexts'] = [context]
        record = indirect_results(self.graph)[0]
        self.assertEqual(record['entry_register_inputs'], [])
        self.assertEqual(record['return_bindings'], context['return_bindings'])


if __name__ == '__main__':
    unittest.main()
