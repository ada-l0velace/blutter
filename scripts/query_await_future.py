#!/usr/bin/env python3
"""Show the checked producer/call/await relation and conditional value evidence.

Run the original-byte/VM audit checker before interpreting exported facts.
"""
import argparse
import json
from pathlib import Path
from graph_io import load_graph
from async_future_bindings import CONDITIONS


def query(graph,site):
    row=next((v for v in graph.get('await_future_bindings',[]) if v['site']==site),None)
    if row is None:raise ValueError('No Future binding observation for this await site')
    if row['status']=='conditional_delivery' and (row['conditions']!=CONDITIONS or row['resume_site'] is None or type(row['class_id']) is not int or row['class_id']<=0):
        raise ValueError('Conditional delivery lacks its scope or class evidence')
    by_entry={v['entry']:v for v in graph['future_producers']};seen=set();pending=[row['producer']] if row['producer'] is not None else []
    while pending:
        entry=pending.pop()
        if entry in seen or entry not in by_entry:continue
        seen.add(entry);pending.extend(v['producer'] for v in by_entry[entry]['forwards'])
    return dict(await_binding=row,producers=[by_entry[entry] for entry in sorted(seen)])


def render(result):
    row=result['await_binding'];lines=[f"Await {row['site']:#x}: {row['status']}"]
    if row['call'] is not None:
        lines.append(f"  input X0 from call {row['call']:#x} to producer {row['producer']:#x} [local normal fallthrough]")
    if row['status']=='conditional_delivery':
        value='null' if row['value']=='null' else f"heap class {row['class_id']:#x}"
        lines.append(f"  successful continuation {row['resume_site']:#x}: X0 -> {value} [conditional]")
        lines.append('  conditions: '+', '.join(row['conditions']))
    else:
        lines.append('  delivered value unproved')
    by_entry={p['entry']:p for p in result['producers']}
    for p in result['producers']:
        for f in p['forwards']:
            target=by_entry.get(f['producer'])
            if target and target['status']=='matched_async_frame':
                lines.append(f"  producer {p['entry']:#x} completion {f['completion']:#x} chains Future from call {f['call']:#x} to {f['producer']:#x}; separate Future instances")
            else:
                lines.append(f"  completion {f['completion']:#x} operand from call {f['call']:#x} to {f['producer']:#x}; Future identity unproved")
    lines.append('No ordinary return type or heap-field preservation claim. Saved references across suspension are outside this local link.')
    return '\n'.join(lines)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('graph',type=Path)
    parser.add_argument('--site',required=True,type=lambda text:int(text,0));parser.add_argument('--json',action='store_true');args=parser.parse_args()
    try:result=query(load_graph(args.graph),args.site)
    except (OSError,EOFError,ValueError,KeyError,TypeError,AssertionError) as error:parser.error(str(error))
    print(json.dumps(result,indent=2) if args.json else render(result))


if __name__=='__main__':main()
