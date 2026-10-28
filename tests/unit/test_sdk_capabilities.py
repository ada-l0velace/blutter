"""Exercise table capability selection using authored SDK header fragments."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from blutter import has_instructions_table_rodata


class SdkCapabilities(unittest.TestCase):
    def probe(self, objects, layout, image='kHeaderSize = kObjectStartAlignment;'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'object.h').write_text(objects)
            (root / 'raw_object.h').write_text(layout)
            (root / 'image_snapshot.h').write_text(image)
            return has_instructions_table_rodata(root)

    def test_rodata_api_requires_the_matching_entry_layout(self):
        objects = 'UntaggedInstructionsTable::Data rodata() const; EntryPointAt(int index);'
        layout = 'struct DataEntry { uint32_t pc_offset; uint32_t stack_map_offset; }; uint32_t first_entry_with_code;'
        self.assertTrue(self.probe(objects, layout))
        for token in ('UntaggedInstructionsTable::Data', 'rodata() const', 'EntryPointAt('):
            with self.subTest(missing=token):
                self.assertFalse(self.probe(objects.replace(token, ''), layout))
        for token in ('struct DataEntry', 'uint32_t pc_offset;', 'uint32_t stack_map_offset;', 'uint32_t first_entry_with_code;'):
            with self.subTest(missing=token):
                self.assertFalse(self.probe(objects, layout.replace(token, '')))

    def test_legacy_tables_do_not_enable_rodata_recovery(self):
        self.assertFalse(self.probe('PayloadStartAt(int); EntryPointAt(int);', 'class UntaggedInstructionsTable {};'))

    def test_legacy_image_alignment_keeps_the_legacy_export_path(self):
        objects = 'UntaggedInstructionsTable::Data rodata() const; EntryPointAt(int index);'
        layout = 'struct DataEntry { uint32_t pc_offset; uint32_t stack_map_offset; }; uint32_t first_entry_with_code;'
        self.assertFalse(self.probe(objects, layout, 'kHeaderSize = kMaxObjectAlignment;'))


if __name__ == '__main__':
    unittest.main()
