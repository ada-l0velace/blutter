#!/usr/bin/env python3
"""Summarize GCC/gcov counters from an optional native coverage build."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[2] / 'blutter/src'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build_dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gcov', default='gcov', help='gcov matching the instrumenting GCC version')
    args = parser.parse_args()
    counters = sorted(args.build_dir.resolve().rglob('*.gcda'))
    if not counters:
        parser.error('no execution counters found; build and run the native coverage profile first')
    files = {}
    with tempfile.TemporaryDirectory(prefix='native-gcov-') as temporary:
        for index, counter in enumerate(counters):
            directory = Path(temporary) / str(index)
            directory.mkdir()
            subprocess.run([args.gcov, '--json-format', '--branch-probabilities', str(counter)],
                           cwd=directory, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for report in directory.glob('*.gcov.json.gz'):
                with gzip.open(report, 'rt') as stream:
                    data = json.load(stream)
                for file in data['files']:
                    path = Path(file['file'])
                    if not path.is_absolute():
                        path = Path(data['current_working_directory']) / path
                    path = path.resolve()
                    if not path.is_relative_to(SOURCE):
                        continue
                    name = str(path.relative_to(SOURCE))
                    item = files.setdefault(name, {'lines': {}, 'compiled_branch_outcomes': 0,
                                                   'covered_compiled_branch_outcomes': 0})
                    for line in file['lines']:
                        number = line['line_number']
                        item['lines'][number] = item['lines'].get(number, False) or line['count'] > 0
                        branches = line.get('branches', [])
                        item['compiled_branch_outcomes'] += len(branches)
                        item['covered_compiled_branch_outcomes'] += sum(b['count'] > 0 for b in branches)
    summary = {}
    for name, item in sorted(files.items()):
        lines = item.pop('lines')
        summary[name] = dict(item, instrumented_lines=len(lines), covered_lines=sum(lines.values()),
                             uncovered_lines=sorted(n for n, hit in lines.items() if not hit))
        print(f'{name}: lines {sum(lines.values())}/{len(lines)}; '
              f'compiled branch outcomes {item["covered_compiled_branch_outcomes"]}/'
              f'{item["compiled_branch_outcomes"]}')
    if not summary:
        parser.error('coverage counters contain no project source')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'files': summary,
        'scope': 'Source lines are unioned across translation units; branch outcomes count '
                 'each compiled instance, including exception paths. This is test execution '
                 'coverage, not snapshot payload completeness or semantic correctness.',
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
