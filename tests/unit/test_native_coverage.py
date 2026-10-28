"""Check export completeness against authored ELF/table bytes, without a Dart VM."""
from pathlib import Path
import json
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Fixture:
    def __init__(self, directory, merged=True, vm=False):
        self.library = directory / 'synthetic.so'
        self.output = directory / 'output'
        (self.output / 'asm').mkdir(parents=True)
        (self.output / 'ida_script').mkdir()
        self.raw = bytearray(0x1000)
        ident = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<16sHHIQQQIHHHHHH', self.raw, 0, ident, 3, 183, 1,
                         0, 64, 0x800, 0, 64, 56, 1, 64, 4, 3)
        struct.pack_into('<IIQQQQQQ', self.raw, 64, 1, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000)
        symbol = '_kDartSnapshotText' if merged else '_kDartIsolateSnapshotInstructions'
        data_symbol = '_kDartSnapshotData' if merged else '_kDartIsolateSnapshotData'
        strings = ('\0' + symbol + '\0' + data_symbol + '\0').encode()
        vm_name_offset = len(strings)
        if vm: strings += b'_kDartVmSnapshotInstructions\0'
        self.raw[0x200:0x200 + len(strings)] = strings
        struct.pack_into('<IBBHQQ', self.raw, 0x280 + 24, 1, 0x11, 0, 1, 0x400, 0x98)
        struct.pack_into('<IBBHQQ', self.raw, 0x280 + 48, len(symbol) + 2, 0x11, 0, 1, 0x500, 0x180)
        if vm:
            struct.pack_into('<IBBHQQ', self.raw, 0x280 + 72, vm_name_offset, 0x11, 0, 1, 0x100, 0x60)
            struct.pack_into('<QQ', self.raw, 0x100, 0x60, 64)
            struct.pack_into('<I', self.raw, 0x140, 0xd65f03c0)
        section_names = b'\0.dynstr\0.dynsym\0.shstrtab\0'
        self.raw[0x300:0x300 + len(section_names)] = section_names
        for i, values in enumerate([
            (1, 3, 0, 0x200, 0x200, len(strings), 0, 0, 1, 0),
            (9, 11, 0, 0x280, 0x280, 96 if vm else 72, 1, 0, 8, 24),
            (17, 3, 0, 0x300, 0x300, len(section_names), 0, 0, 1, 0),
        ], 1):
            struct.pack_into('<IIQQQQIIQQ', self.raw, 0x800 + i * 64, *values)
        struct.pack_into('<QQ', self.raw, 0x400, 0x98, 64)
        self.raw[0x500:0x504] = b'\xf5\xf5\xdc\xdc'
        struct.pack_into('<QQ', self.raw, 0x504, 124, 2)
        self.raw[0x514:0x534] = b'0' * 32
        features = b'product compressed-pointers\0'
        self.raw[0x534:0x534 + len(features)] = features
        position = 0x534 + len(features)
        self.raw[position:position + 5] = bytes([0x80, 0x83, 0x81, 0x82, 0xf0])
        words = [0xd503201f, 0xd503201f, 0xd65f03c0, 0xd503201f, 0xd65f03c0, 0xd65f03c0]
        for i, word in enumerate(words):
            struct.pack_into('<I', self.raw, 0x480 + i * 4, word)
        struct.pack_into('<IIII', self.raw, 0x600, 44, 3, 1, 0)
        for i, pc in enumerate([0x80, 0x8c, 0x94]):
            struct.pack_into('<II', self.raw, 0x610 + i * 8, pc, 40 + i)
        self.library.write_bytes(self.raw)
        self.manifest = {'image_start': 0x400, 'image_end': 0x498,
                         'table_data_address': 0x600, 'table_length': 3,
                         'first_entry_with_code': 1, 'payload_count': 3,
                         'additional_exports': 1, 'undecoded_words': 0,
                         'ranges': [{'table': 0, 'index': i, 'start': a, 'end': b,
                                     'discarded_code': i == 0, 'has_metadata_name': i != 1}
                                    for i, (a, b) in enumerate([(0x480, 0x48c), (0x48c, 0x494), (0x494, 0x498)])]}
        self.naming = self.output / 'ida_script/addNames.py'
        self.naming.write_text(''.join(f'ida_funcs.add_func({row["start"]}, {row["end"]})\n'
                                      for row in self.manifest['ranges']) +
                               'idaapi.set_name(0x484, "authored_checked_alias")\n'
                               'idaapi.set_name(0x48c, "unattributed_code_48c")\n'
                               'idaapi.set_name(0x494, "authored_last")\n')
        if vm:
            with self.naming.open('a') as stream:
                stream.write('ida_funcs.add_func(0x140, 0x144)\nidaapi.set_name(0x140, "authored_vm_stub")\n')
        self.assembly = self.output / 'asm/snapshot_code.asm'
        self.assembly.write_text(''.join(f'// {0x480 + i * 4:#x}: {"nop" if word == 0xd503201f else "ret"} \n'
                                       for i, word in enumerate(words)))

    def run(self, wrapper=False, optimize=False, audit=None):
        (self.output / 'snapshot_code.json').write_text(json.dumps(self.manifest))
        script = 'check_shorebird_coverage.py' if wrapper else 'check_native_coverage.py'
        more = []
        if audit is not None:
            path = self.output / 'vm-audit.json'
            path.write_text(json.dumps(audit))
            more = ['--vm-audit', str(path)]
        return subprocess.run([sys.executable, *(['-O'] if optimize else []),
                               str(ROOT / 'scripts' / script), str(self.library), str(self.output), *more],
                              capture_output=True, text=True, timeout=15)


class NativeCoverageTests(unittest.TestCase):
    def test_separate_vm_stub_ranges_are_preserved(self):
        for defect in (None, 'lost', 'outside'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary), merged=False, vm=True)
                if defect == 'lost':
                    fixture.naming.write_text(fixture.naming.read_text().replace('ida_funcs.add_func(0x140, 0x144)\n', ''))
                elif defect == 'outside':
                    fixture.naming.write_text(fixture.naming.read_text().replace('0x144', '0x164'))
                # A minimal numerical VM audit independently records retained stubs.
                entries = [{'entry': pc, 'pc_offset': pc - 0x400, 'stack_map_offset': 40 + i,
                            'payload': pc, 'code_entry': pc, 'size': end - pc}
                           for i, (pc, end) in enumerate([(0x480, 0x48c), (0x48c, 0x494), (0x494, 0x498)])]
                audit = {'tables': [{'data_address': 0x600, 'retained_code_count': 2, 'entries': entries}],
                         'known_functions': [], 'known_stubs': [{'entry': 0x140, 'size': 4}], 'heap_functions': []}
                result = fixture.run(audit=audit)
                self.assertEqual(result.returncode == 0, defect is None, result.stderr)
                if defect is None:
                    self.assertEqual(json.loads(result.stdout)['separate_vm_stub_ranges'], 1)

    def test_vm_audit_accounts_for_retained_heap_entries(self):
        for defect in (None, 'missing-function', 'missing-record'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                entries = [{'entry': pc, 'pc_offset': pc - 0x400, 'stack_map_offset': 40 + i,
                            'payload': pc, 'code_entry': pc, 'size': end - pc}
                           for i, (pc, end) in enumerate([(0x480, 0x48c), (0x48c, 0x494), (0x494, 0x498)])]
                audit = {'tables': [{'data_address': 0x600, 'retained_code_count': 2, 'entries': entries}],
                         'known_functions': [{'entry': 0x484}], 'known_stubs': [{'entry': 0x494}],
                         'heap_functions': [{'entry': 0x484, 'has_code': True},
                                            {'entry': 0x490, 'has_code': False},
                                            {'entry': 0x30, 'has_code': True}]}
                if defect == 'missing-function': audit['known_functions'].clear()
                elif defect == 'missing-record': entries.pop()
                result = fixture.run(audit=audit)
                self.assertEqual(result.returncode == 0, defect is None, result.stderr)
                if defect is None:
                    self.assertEqual(json.loads(result.stdout)['retained_heap_function_entries_checked'], 1)

    def test_both_symbol_layouts_and_legacy_entry_point(self):
        for merged in (False, True):
            for wrapper in (False, True):
                with self.subTest(merged=merged, wrapper=wrapper), tempfile.TemporaryDirectory() as temporary:
                    result = Fixture(Path(temporary), merged).run(wrapper=wrapper)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['payload_count'], 3)
                    self.assertEqual(report['payload_bytes_checked'], 24)
                    self.assertEqual(report['anonymous_exports'], 1)

    def test_missing_or_duplicate_ranges_cannot_pass(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                lines = fixture.naming.read_text().splitlines()
                fixture.naming.write_text('\n'.join(lines + lines[:1] if duplicate else lines[1:]))
                self.assertNotEqual(fixture.run().returncode, 0)

    def test_corrupt_original_table_and_export_claims_are_rejected(self):
        for defect in ('first', 'order', 'last', 'names', 'count', 'location', 'header', 'features'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if defect in ('first', 'order'):
                    struct.pack_into('<I', fixture.raw, 0x610 if defect == 'first' else 0x618, 0x84 if defect == 'first' else 0x80)
                    fixture.library.write_bytes(fixture.raw)
                elif defect == 'last': fixture.manifest['ranges'][-1]['end'] -= 4
                elif defect == 'names': fixture.manifest['ranges'][0]['has_metadata_name'] = False
                elif defect == 'location': fixture.manifest['table_data_address'] += 8
                elif defect == 'header':
                    fixture.raw[0x534 + len(b'product compressed-pointers\0') + 3] = 0x83
                    fixture.library.write_bytes(fixture.raw)
                elif defect == 'features':
                    fixture.raw = fixture.raw.replace(b'compressed-pointers', b'xompressed-pointers')
                    fixture.library.write_bytes(fixture.raw)
                else: fixture.manifest['payload_count'] -= 1
                self.assertNotEqual(fixture.run().returncode, 0)

    def test_missing_or_changed_original_instruction_is_rejected(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                text = fixture.assembly.read_text()
                fixture.assembly.write_text('\n'.join(text.splitlines()[:-1]) if missing else text.replace('nop', 'ret', 1))
                self.assertNotEqual(fixture.run().returncode, 0)

    def test_optimized_python_cannot_disable_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = Fixture(Path(temporary)).run(optimize=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('without optimization', result.stderr)


if __name__ == '__main__':
    unittest.main()
