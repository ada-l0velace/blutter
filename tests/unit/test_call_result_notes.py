"""Authored assembly coverage, association, scope and metadata controls."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from check_call_result_notes import expected_facts, parse_note, check_stream, metadata_class_names


class CallResultNotes(unittest.TestCase):
    def setUp(self):
        self.graph = {'edges': [{'site': 0x1010, 'stack_inputs': [], 'array_arguments': []}],
            'call_result_contexts': [{'payload': 0x1000,
                'return_bindings': [{'site': 0x1010, 'class_id': 7, 'basis': 'machine_return_summary'}],
                'stack_observations': [], 'array_observations': [], 'resolutions': [], 'certificate': {}}]}
        self.note = '    // caller-result @0x1010 [payload 0x1000]: normal-return X0 -> class 0x7 ("Example") [callee summary]\n'
        self.instruction = '    // 0x1010: bl #0x2000\n'

    def check(self, lines):
        return check_stream(lines, expected_facts(self.graph), {7: 'Example'})

    def test_correct_fact_matches_its_original_instruction(self):
        observed, kinds = self.check([self.note, self.instruction])
        self.assertEqual(sum(observed.values()), 1)
        self.assertEqual(kinds, {0x1010: 'bl'})

    def test_missing_duplicate_invented_or_detached_note_is_rejected(self):
        for lines in ([self.instruction], [self.note, self.note, self.instruction], [self.note],
                      [self.note, '    // 0x1014: bl #0x2000\n', self.instruction]):
            with self.subTest(lines=lines), self.assertRaises(AssertionError):
                self.check(lines)

    def test_scope_class_name_and_basis_are_independently_checked(self):
        for before, after in [('payload 0x1000', 'payload 0x2000'), ('class 0x7', 'class 0x8'),
                              ('Example', 'WrongName'), ('callee summary', 'caller-bound helper'),
                              ('normal-return X0', 'source-return String')]:
            with self.subTest(after=after), self.assertRaises(AssertionError):
                self.check([self.note.replace(before, after), self.instruction])

    def test_physical_stack_word_array_and_ret_remain_distinct(self):
        prefix = ' // caller-result @0x1010 [payload 0x1000]: '
        for body, expected in [
            ('stack Dart SP-8 -> class 0x7 ("Example") [partial]', ('stack', -8, 'heap_class', 7)),
            ('stack Dart SP+0 -> word 0x7 [partial]', ('stack', 0, 'word', 7)),
            ('array Dart SP+16, allocation 0x1008, length 2, element[0] -> class 0x7 [partial]', ('array', 16, 0x1008, 2, 0, 7)),
            ('snapshot dispatch -> 0x3000', ('dispatch', 0x3000)),
            ('physical X0 at RET -> class 0x7', ('ret', 7))]:
            self.assertEqual(parse_note(prefix + body)[2:], expected)
        with self.assertRaises(AssertionError):
            parse_note(prefix + 'stack Dart SP+0 -> word 0x7 ("Example") [partial]')
        with self.assertRaises(AssertionError):
            parse_note(prefix + 'stack Dart SP+0 -> class 0x7')

    def test_dart_il_summary_is_not_counted_as_a_second_instruction(self):
        lines = [self.note, '    // 0x1010: r0 = Example()\n', self.instruction]
        observed, _ = check_stream(lines, expected_facts(self.graph), {7: 'Example'}, {0x1010: 'bl'})
        self.assertEqual(sum(observed.values()), 1)

    def test_new_facts_exclude_unchanged_cells_and_stack_values(self):
        c = self.graph['call_result_contexts'][0]
        self.graph['edges'][0].update(stack_inputs=[{'sp_offset': 0, 'kind': 'word', 'value': '0x7'}],
                                      array_arguments=[{'sp_offset': 8, 'allocation': 0x1000, 'elements': [[1, 8]]}])
        c['stack_observations'] = [{'site': 0x1010, 'values': copy.deepcopy(self.graph['edges'][0]['stack_inputs'])}]
        c['array_observations'] = [{'site': 0x1010, 'values': [{'sp_offset': 8, 'allocation': 0x1000, 'length': 2, 'elements': [[0, 7], [1, 8]]}]}]
        facts = expected_facts(self.graph)
        self.assertEqual(len(facts), 2)
        self.assertIn((0x1000, 0x1010, 'array', 8, 0x1000, 2, 0, 7), facts)

    def test_predefined_display_aliases_use_the_matched_boundary(self):
        script = 'const NumPredefinedCids = 10;\n[{id:7,name:"List"},{id:12,name:"Example"}]'
        self.assertEqual(metadata_class_names(script), {12: 'Example'})
        self.assertEqual(metadata_class_names(script.replace('= 10;', '= 5;')), {7: 'List', 12: 'Example'})
        with self.assertRaises(AssertionError):
            metadata_class_names('[]')

    def test_ret_il_and_machine_row_are_one_instruction(self):
        self.graph['call_result_contexts'][0].update(return_bindings=[], certificate={'return_classes': [{'site': 0x1010, 'class_id': 7}]})
        note = self.note.replace('normal-return X0', 'physical X0 at RET').replace(' [callee summary]', '')
        rows = [' // 0x1010: ret\n', note, ' //     0x1010: ret\n']
        observed, _ = check_stream(rows, expected_facts(self.graph), {7: 'Example'}, {0x1010: 'ret'})
        self.assertEqual(sum(observed.values()), 1)

    def test_shared_code_function_headers_reset_instruction_occurrences(self):
        rows = [' // ** addr: 0x1000, size: 0x20\n', self.note, self.instruction] * 2
        observed, _ = check_stream(rows, expected_facts(self.graph), {7: 'Example'}, {0x1010: 'bl'})
        self.assertEqual(sum(observed.values()), 2)


if __name__ == '__main__':
    unittest.main()
