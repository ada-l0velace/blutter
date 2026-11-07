"""Read checked native payload sections across library and fallback listings."""
import bisect
from collections import defaultdict
from pathlib import Path, PurePosixPath
import re

HEADER = re.compile(r'^\s*// (?:Native payload|Payload) (0x[0-9a-f]+)\.\.(0x[0-9a-f]+)\b')
WORD = re.compile(r'^\s*//\s*(0x[0-9a-f]+):\s+([a-z][a-z0-9.]*|\.word)(?:\s|$)')
END = '// End native payload'


def native_assembly_streams(output, manifest):
    """Yield (path, checked line iterator); consume each iterator completely.

    Layout 2 records each payload's destination. Every payload must appear once,
    with every original word in order. Declarations and IL observations are not
    machine instruction rows. Legacy exports keep their complete native file.
    """
    if not __debug__:
        raise RuntimeError('Native output checks require assertions; run Python without optimization')
    if 'assembly_layout' not in manifest:
        path = output / 'asm/snapshot_code.asm'
        with path.open() as stream:
            yield path, stream
        return
    assert manifest['assembly_layout'] == 2, 'Unsupported native assembly layout'
    root = (output / 'asm').resolve()
    ranges = manifest['ranges']
    starts = [r['start'] for r in ranges]
    assert all(r['start'] < r['end'] and r['start'] % 4 == r['end'] % 4 == 0 and
               (i == 0 or ranges[i-1]['end'] <= r['start']) for i, r in enumerate(ranges))
    expected = defaultdict(dict)
    for i, row in enumerate(ranges):
        name = PurePosixPath(row['assembly_file'])
        assert not name.is_absolute() and name.parts and '..' not in name.parts, 'Invalid assembly output path'
        path = root.joinpath(*name.parts).resolve()
        assert path.is_relative_to(root) and path.is_file(), 'Missing or escaping assembly output path'
        span = row['start'], row['end']
        assert span not in expected[path], 'Duplicate native payload inventory'
        expected[path][span] = i
    paths = set(expected) | {p.resolve() for p in root.rglob('*') if p.suffix in {'.dart', '.asm'} and p.is_file()}
    seen = set()

    def checked_lines(path, stream):
        active = None
        cursor = None
        for line in stream:
            if header := HEADER.match(line):
                assert active is None, 'Unterminated or nested native payload'
                span = int(header[1], 16), int(header[2], 16)
                assert span in expected[path], 'Native payload is in the wrong output file'
                active = expected[path][span]
                assert active not in seen, 'Duplicate native payload section'
                seen.add(active)
                cursor = span[0]
            if line.strip() == END:
                assert active is not None, 'Unexpected native payload terminator'
                assert cursor == ranges[active]['end'], 'Missing native instructions in payload'
                yield line
                active = None
                continue
            if word := WORD.match(line):
                address = int(word[1], 16)
                if active is not None:
                    assert address == cursor and address < ranges[active]['end'], 'Missing, duplicate or reordered native instruction'
                    cursor += 4
                else:
                    index = bisect.bisect_right(starts, address) - 1
                    assert index < 0 or address >= ranges[index]['end'], 'Native instruction outside its recorded payload section'
            if active is not None:
                yield line
        assert active is None, 'Unterminated native payload section'

    for path in sorted(paths):
        with path.open() as stream:
            yield path, checked_lines(path, stream)
    assert seen == set(range(len(ranges))), 'A native payload section was not exported'
