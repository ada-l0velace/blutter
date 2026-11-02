"""Check source selection with authored local Git history, without network access."""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import dartvm_fetch_build as build


class SdkCheckout(unittest.TestCase):
    def git(self, directory, *arguments):
        return subprocess.check_output(
            ['git', '-C', str(directory), *arguments], text=True, stderr=subprocess.PIPE).strip()

    def create_sources(self, root):
        source = root / 'source'
        source.mkdir()
        self.git(source, 'init', '--quiet')
        for name in ('runtime/vm/layout.h', 'tools/reader.py',
                     'third_party/double-conversion/value.h', 'unused/large.txt'):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('authored base\n')
        self.git(source, 'add', '.')
        self.git(source, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'authored base')
        base = self.git(source, 'rev-parse', 'HEAD')
        (source / 'runtime/vm/layout.h').write_text('authored release\n')
        self.git(source, 'add', '.')
        self.git(source, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'authored release')
        self.git(source, 'tag', '3.0.0')
        return source, base, self.git(source, 'rev-parse', 'HEAD')

    def test_custom_reader_checks_out_its_base_not_the_version_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base, release = self.create_sources(root)
            target = root / 'custom'
            info = SimpleNamespace(version='3.0.0', reader_profile='authored-profile')
            with patch.object(build, 'DART_GIT_URL', source.as_uri()), \
                    patch.object(build, 'runtime_profile', return_value=SimpleNamespace(source_base=base)):
                build.checkout_dart_sources(info, str(target))
            self.assertNotEqual(base, release)
            self.assertEqual(self.git(target, 'rev-parse', 'HEAD'), base)
            self.assertEqual((target / 'runtime/vm/layout.h').read_text(), 'authored base\n')
            self.assertTrue((target / 'tools/reader.py').is_file())
            self.assertTrue((target / 'third_party/double-conversion/value.h').is_file())
            self.assertFalse((target / 'unused').exists())

    def test_ordinary_reader_keeps_the_release_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base, release = self.create_sources(root)
            target = root / 'ordinary'
            info = SimpleNamespace(version='3.0.0', reader_profile=None)
            with patch.object(build, 'DART_GIT_URL', source.as_uri()):
                build.checkout_dart_sources(info, str(target))
            self.assertEqual(self.git(target, 'rev-parse', 'HEAD'), release)
            self.assertEqual((target / 'runtime/vm/layout.h').read_text(), 'authored release\n')
            self.assertFalse((target / 'unused').exists())

    def test_missing_pinned_base_cannot_fall_back_to_the_version_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _ = self.create_sources(root)
            target = root / 'missing'
            info = SimpleNamespace(version='3.0.0', reader_profile='authored-profile')
            with patch.object(build, 'DART_GIT_URL', source.as_uri()), \
                    patch.object(build, 'runtime_profile', return_value=SimpleNamespace(source_base='1' * 40)):
                with self.assertRaises(subprocess.CalledProcessError):
                    build.checkout_dart_sources(info, str(target))
            self.assertFalse((target / 'runtime').exists())
            self.assertNotEqual(subprocess.run(['git', '-C', str(target), 'rev-parse', '--verify', 'HEAD'],
                                              capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
