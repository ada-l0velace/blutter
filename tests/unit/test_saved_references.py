import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from async_future_bindings import CONDITIONS
from saved_async_references import SCOPE,check_saved_stream
from query_saved_references import query,render
from graph_io import load_graph


class SavedReferenceTests(unittest.TestCase):
    def setUp(self):
        self.observation=dict(site=0x1020,store=0x1008,suspension=0x1014,slot=-16,register=2)
        self.context=dict(payload=0x1000,source_await=0x1004,class_id=7,status='checked',scope=SCOPE,observations=[self.observation])
        self.seed=dict(site=0x1004,resume_site=0x1008,status='conditional_delivery',class_id=7,conditions=list(CONDITIONS))
        self.graph=dict(format=39,saved_reference_contexts=[self.context],await_future_bindings=[self.seed])
        self.note=('// async restored-reference: load result X2 heap class 0x7 ("Example") '
                   '[conditional: delivery at await 0x1004; store 0x1008 to FP-16; preserved through await 0x1014; '
                   'normal call fallthrough; successful SDK resumes; value/error-preserving callbacks; reference only]\n')

    def test_query_scope_and_path(self):
        rows=query(self.graph,0x1020);text=render(rows)
        self.assertIn('X2 -> heap class 0x7 [conditional]',text)
        self.assertIn('FP-16 -> suspend 0x1014 -> load 0x1020',text)
        self.assertIn('heap-field contents and source parameter identity remain unproved',text)

    def test_missing_and_legacy(self):
        for graph,site in [(self.graph,0x3000),(dict(format=38),0x1020)]:
            with self.assertRaises(ValueError):query(graph,site)

    def test_reject_lost_scope(self):
        for key,value in [('scope','unconditional'),('status','step_limit'),('class_id',8)]:
            graph=copy.deepcopy(self.graph);graph['saved_reference_contexts'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):query(graph,0x1020)

    def test_reject_lost_source_conditions(self):
        for key,value in [('conditions',[]),('status','unknown'),('resume_site',None)]:
            graph=copy.deepcopy(self.graph);graph['await_future_bindings'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):query(graph,0x1020)

    def test_plain_compact_gzip(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'snapshot_calls.json';gz=Path(str(p)+'.gz');graph=dict(self.graph,export=dict(detail='compact',omitted=[]))
            p.write_text(json.dumps(graph))
            with gzip.open(gz,'wt') as f:json.dump(graph,f)
            self.assertEqual(query(load_graph(p),0x1020),query(load_graph(gz),0x1020))
            p.unlink();self.assertEqual(query(load_graph(temp),0x1020),query(self.graph,0x1020))

    def test_note_attachment_and_scope(self):
        self.assertEqual(check_saved_stream(self.graph,[self.note,'// 0x1020: ldur x2, [fp, #-16]\n'],{7:'Example'})[0x1020,0x1004],1)
        for lines in [[self.note],['// 0x1020: ldur x2, [fp, #-16]\n'],[self.note,'// 0x1024: ret\n'],
                      [self.note,self.note,'// 0x1020: ret\n'],[self.note.replace('conditional: ',''),'// 0x1020: ret\n']]:
            with self.assertRaises(AssertionError):check_saved_stream(self.graph,lines)

    def test_names_are_quoted_data(self):
        for note,names in [(self.note,{7:'Different'}),(self.note.replace('Example','bad\nname'),None)]:
            with self.assertRaises(AssertionError):check_saved_stream(self.graph,[note,'// 0x1020: ret\n'],names)

    def test_distinct_conditional_origins(self):
        other=copy.deepcopy(self.context);other['source_await']=0x1040;self.graph['saved_reference_contexts'].append(other)
        self.graph['await_future_bindings'].append(dict(self.seed,site=0x1040))
        self.assertEqual(len(query(self.graph,0x1020)),2)


if __name__=='__main__':unittest.main()
