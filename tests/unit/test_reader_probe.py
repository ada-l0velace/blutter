"""Authored native tables and ARM64 guard evidence; no application inputs."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import reader_probe as probe
from test_runtime_evidence import elf_fixture, guard_words, pack_words


class ReaderProbe(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app, self.engine = self.root / 'app.so', self.root / 'engine.so'
        self.names = ['AuthoredFirst', 'AuthoredLast']
        self.engine.write_bytes(bytes(64) + b'AuthoredFirst\0AuthoredLast\0')
        self.app.write_bytes(elf_fixture(pack_words(guard_words() + guard_words(native=True))))
        self.report = {'schema': 1, 'status': 'deserialized', 'vm_stubs': self.names,
                       'vm_tag_offset': 0x100, 'native_call_state_offset': 0x80,
                       'payload_count': 2, 'first_with_code': 0, 'table_address': 0x310,
                       'image_start': 0x1000, 'image_end': 0x1200}

    def validate(self, report=None):
        with patch.object(probe, '_original_table', return_value=2):
            return probe.validate_probe(report or self.report, self.app, self.engine)

    def test_ordered_engine_stubs_and_both_guard_forms_are_required(self):
        result = self.validate()
        self.assertEqual(result['guard_sites_checked'], 2)
        self.assertEqual(result['vm_stub_count'], 2)
        with self.assertRaisesRegex(RuntimeError, 'stub order'):
            self.validate(dict(self.report, vm_stubs=list(reversed(self.names))))

    def test_missing_conflicting_partial_or_changed_guard_evidence_is_rejected(self):
        cases = [([], 'not_observed'), (guard_words(), 'both leaf and native'),
                 (guard_words(tag=None) + guard_words(native=True), 'partial'),
                 (guard_words(state=0x180) + guard_words(native=True), 'conflicting'),
                 (guard_words(state=0x180) + guard_words(native=True, state=0x180), 'Thread offsets')]
        for words, message in cases:
            with self.subTest(message=message):
                self.app.write_bytes(elf_fixture(pack_words(words)))
                with self.assertRaisesRegex(RuntimeError, message):
                    self.validate()

    def test_bad_report_and_offsets_are_rejected(self):
        for update in [{'schema': 2}, {'status': 'partial'}, {'vm_stubs': []},
                       {'vm_stubs': ['bad\x00name']}, {'vm_stubs': ['Same', 'Same']},
                       {'vm_tag_offset': True}, {'vm_tag_offset': 1}, {'native_call_state_offset': 0}]:
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                self.validate(dict(self.report, **update))

    def table_fixture(self):
        raw = bytearray(0x1200)
        raw[0x200:0x204] = b'\xf5\xf5\xdc\xdc'
        struct.pack_into('<Q', raw, 0x204, 0xfc)
        features = b'product arm64 android compressed-pointers\0'
        raw[0x234:0x234 + len(features)] = features
        position = 0x234 + len(features)
        raw[position:position + 5] = bytes([0x80, 0x80, 0x80, 0x82, 0x80])
        struct.pack_into('<IIII', raw, 0x310, 48, 2, 0, 0)
        struct.pack_into('<IIII', raw, 0x320, 128, 32, 256, 36)
        struct.pack_into('<QQ', raw, 0x1000, 0x200, 64)
        self.app.write_bytes(raw)
        symbols = {'_kDartIsolateSnapshotInstructions': [{'st_value': 0x1000, 'st_size': 0x200}],
                   '_kDartIsolateSnapshotData': [{'st_value': 0x200, 'st_size': 0x400}]}
        fake = SimpleNamespace(elfclass=64, little_endian=True,
                               iter_segments=lambda: iter([{'p_type': 'PT_LOAD', 'p_vaddr': 0,
                                                           'p_offset': 0, 'p_filesz': len(raw)}]),
                               get_section_by_name=lambda _: SimpleNamespace(get_symbol_by_name=lambda n: symbols.get(n)))

        class Elf:
            elfclass, little_endian = fake.elfclass, fake.little_endian
            iter_segments = staticmethod(fake.iter_segments)
            get_section_by_name = staticmethod(fake.get_section_by_name)
            def __getitem__(self, name): return 'EM_AARCH64'
        return raw, Elf()

    def test_table_locations_counts_and_original_records_are_independent_checks(self):
        raw, elf = self.table_fixture()
        with patch.object(probe, 'ELFFile', return_value=elf):
            self.assertEqual(probe._original_table(self.app, self.report), 2)
            for field in ['table_address', 'payload_count', 'first_with_code', 'image_end']:
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    probe._original_table(self.app, dict(self.report, **{field: self.report[field] + 4}))
            for address, value in [(0x314, 3), (0x318, 3), (0x31c, 1), (0x328, 127), (0x32c, 0)]:
                changed = bytearray(raw)
                struct.pack_into('<I', changed, address, value)
                self.app.write_bytes(changed)
                with self.subTest(address=address), self.assertRaises(RuntimeError):
                    probe._original_table(self.app, self.report)
                self.app.write_bytes(raw)

    def test_native_crash_and_timeout_are_not_promoted_to_success(self):
        with patch.object(probe.subprocess, 'run', return_value=SimpleNamespace(returncode=-6)):
            with self.assertRaisesRegex(RuntimeError, 'exit code -6'):
                probe.run_probe('authored-reader', self.app, self.engine)
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('authored-reader', 1)):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                probe.run_probe('authored-reader', self.app, self.engine, timeout=1)

    def test_native_completion_marker_is_required(self):
        def run(command, **kwargs):
            output = Path(command[command.index('-o') + 1]); output.mkdir()
            (output / 'analysis_status.json').write_text(json.dumps({'status': 'partial', 'analysis_errors': 1}))
            Path(command[-1]).write_text(json.dumps(self.report))
            return SimpleNamespace(returncode=0)
        with patch.object(probe.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'did not finish cleanly'):
                probe.run_probe('authored-reader', self.app, self.engine)


if __name__ == '__main__':
    unittest.main()
