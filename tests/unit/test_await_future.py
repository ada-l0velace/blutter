import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from async_future_bindings import CONDITIONS,check_binding_stream
from query_await_future import query,render
from graph_io import load_graph


class AwaitFutureTests(unittest.TestCase):
    def setUp(self):
        self.row=dict(site=0x1004,payload=0x1000,callee=0x12000,resume_site=0x1008,status='conditional_delivery',
                      value='heap_class',class_id=7,call=0x1000,producer=0x5000,conditions=list(CONDITIONS))
        self.producer=dict(entry=0x5000,status='matched_async_frame',forwards=[])
        self.graph=dict(format=38,await_future_bindings=[self.row],future_producers=[self.producer])
        self.note=('// async delivered-value: X0 heap class 0x7 ("Example") [conditional: Future from call 0x1000 to 0x5000; '
                   'await 0x1004; successful SDK resume; value/error-preserving callbacks; no ordinary return claim]\n')

    def test_scoped_delivery(self):
        text=render(query(self.graph,0x1004))
        self.assertIn('successful continuation 0x1008',text)
        self.assertIn('value_and_error_preserving_sdk_callbacks',text)
        self.assertIn('No ordinary return type',text)

    def test_generic_await_stays_unproved(self):
        self.row.update(status='typed_await_delivery_unproved',value='unknown',class_id=None,conditions=[])
        text=render(query(self.graph,0x1004))
        self.assertIn('delivered value unproved',text)
        self.assertNotIn('successful continuation',text)

    def test_source_cycles_do_not_loop_query(self):
        self.producer['forwards']=[dict(completion=0x5020,call=0x501c,producer=0x5000)]
        result=query(self.graph,0x1004)
        self.assertEqual(len(result['producers']),1)
        self.assertIn('separate Future instances',render(result))

    def test_unknown_forward_is_not_called_a_known_future(self):
        self.producer['forwards']=[dict(completion=0x5020,call=0x501c,producer=0x6000)]
        self.graph['future_producers'].append(dict(entry=0x6000,status='no_completion_summary',forwards=[]))
        text=render(query(self.graph,0x1004))
        self.assertIn('Future identity unproved',text)
        self.assertNotIn('chains Future',text)

    def test_incomplete_scope_is_rejected(self):
        for defect in ('conditions','class_id','resume_site'):
            g=copy.deepcopy(self.graph)
            g['await_future_bindings'][0][defect]=[] if defect=='conditions' else None
            with self.subTest(defect=defect),self.assertRaises(ValueError):query(g,0x1004)

    def test_missing_and_legacy(self):
        for g,site in [(self.graph,0x2000),(dict(format=37),0x1004)]:
            with self.assertRaises(ValueError):query(g,site)

    def test_plain_compact_gzip(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'snapshot_calls.json';gz=Path(str(path)+'.gz')
            g=dict(self.graph,export=dict(detail='compact',omitted=['receiver_blocks','call_effect_states']))
            path.write_text(json.dumps(g))
            with gzip.open(gz,'wt') as stream:json.dump(g,stream)
            self.assertEqual(query(load_graph(path),0x1004),query(load_graph(gz),0x1004))
            path.unlink();self.assertEqual(query(load_graph(temp),0x1004)['await_binding'],self.row)

    def test_note_scope_and_attachment(self):
        observed=check_binding_stream(self.graph,[self.note,'// 0x1008: ret\n'],{7:'Example'})
        self.assertEqual(observed[0x1004],1)
        for lines in ([self.note,'// 0x100c: ret\n'],[self.note],['// 0x1008: ret\n'],
                      [self.note,self.note,'// 0x1008: ret\n'],[self.note.replace('conditional: ',''),'// 0x1008: ret\n']):
            with self.assertRaises((AssertionError,KeyError)):check_binding_stream(self.graph,lines)

    def test_note_class_names_are_data(self):
        for note,names in [(self.note,{7:'Different'}),(self.note.replace('"Example"','"bad\nname"'),None)]:
            with self.assertRaises(AssertionError):check_binding_stream(self.graph,[note,'// 0x1008: ret\n'],names)

    def test_null_delivery(self):
        self.row.update(value='null',class_id=1)
        note=self.note.replace('heap class 0x7 ("Example")','null')
        self.assertEqual(check_binding_stream(self.graph,[note,'// 0x1008: ret\n'])[0x1004],1)
        self.assertIn('X0 -> null',render(query(self.graph,0x1004)))


if __name__=='__main__':unittest.main()
