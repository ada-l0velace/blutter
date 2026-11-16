#!/usr/bin/env python3
"""Show scoped frame-reference restoration after checked SDK suspension.

Use the original-byte and typed-metadata checker before trusting exported facts.
"""
import argparse,json
from pathlib import Path
from graph_io import load_graph
from saved_async_references import SCOPE
from async_future_bindings import CONDITIONS


def query(graph,site):
    found=[]
    seeds={b['site']:b for b in graph.get('await_future_bindings',[])}
    for c in graph.get('saved_reference_contexts',[]):
        for o in c['observations']:
            if o['site']!=site:continue
            source=seeds[c['source_await']]
            if c['status']!='checked' or c.get('scope')!=SCOPE or source['status']!='conditional_delivery' or source['class_id']!=c['class_id'] or source.get('conditions')!=CONDITIONS or source.get('resume_site') is None or type(c['class_id']) is not int or c['class_id']<=0:
                raise ValueError('Restored reference lacks its conditional source')
            found.append(dict(source_await=c['source_await'],class_id=c['class_id'],scope=c['scope'],conditions=source['conditions'],**o))
    if not found:raise ValueError('No checked restored reference at this instruction')
    return found


def render(rows):
    lines=[]
    for r in rows:
        lines.extend([f"Load {r['site']:#x}: X{r['register']} -> heap class {r['class_id']:#x} [conditional]",
            f"  source delivery: await {r['source_await']:#x}",f"  save {r['store']:#x} -> FP{r['slot']:+d} -> suspend {r['suspension']:#x} -> load {r['site']:#x}",
            '  conditions: '+', '.join(r['conditions'])+', normal_call_fallthrough, successful_intervening_resumes',
            '  saved reference only; heap-field contents and source parameter identity remain unproved'])
    return '\n'.join(lines)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('graph',type=Path);p.add_argument('--site',required=True,type=lambda s:int(s,0));p.add_argument('--json',action='store_true');args=p.parse_args()
    try:r=query(load_graph(args.graph),args.site)
    except (ValueError,KeyError,TypeError,OSError,EOFError) as e:p.error(str(e))
    print(json.dumps(r,indent=2) if args.json else render(r))


if __name__=='__main__':main()
