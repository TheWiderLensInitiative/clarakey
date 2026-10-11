"""A distributable must never absorb credentials from an installed portable folder."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest

script = Path(__file__).resolve().parents[1]/'packaging/archive.py'
spec = importlib.util.spec_from_file_location('clarakey_archive', script)
archive_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive_module)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='clarakey-package-test-')
        self.base = Path(self.tmp.name)
        self.bundle = self.base/'bundle'
        (self.bundle/'app').mkdir(parents=True)
        (self.bundle/'vault').mkdir()
        (self.bundle/'backups').mkdir()
        self.app = self.bundle/'app/run.py'
        self.app.write_text('# test-only application file\n')
        self.digest = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.manifest = self.bundle/'MANIFEST.sha256'
        self.manifest.write_text(self.digest+'  app/run.py\n')
        self.output = self.base/'release.tar.gz'

    def tearDown(self):
        self.tmp.cleanup()

    def test_archive_excludes_vault_backups_lock_and_unlisted_exports(self):
        for name in ('vault/clarakey.vault', 'backups/test.vault', '.clarakey.lock', 'export.json'):
            (self.bundle/name).write_text('TEST-ONLY-private-material')
        archive_module.create_archive(self.bundle, self.output)
        with tarfile.open(self.output) as archive:
            self.assertEqual(set(archive.getnames()), {'ClaraKey', 'ClaraKey/vault', 'ClaraKey/backups',
                                                       'ClaraKey/app/run.py', 'ClaraKey/MANIFEST.sha256'})
            self.assertEqual(archive.extractfile('ClaraKey/app/run.py').read(), self.app.read_bytes())
        self.assertEqual(self.output.with_suffix('.gz.sha256').read_text().split()[0],
                         hashlib.sha256(self.output.read_bytes()).hexdigest())

    def test_tampered_build_does_not_replace_archive(self):
        self.output.write_bytes(b'previous-test-only-release')
        self.app.write_text('# changed after the manifest was created\n')
        with self.assertRaises(ValueError):
            archive_module.create_archive(self.bundle, self.output)
        self.assertEqual(self.output.read_bytes(), b'previous-test-only-release')

    def test_manifest_rejects_data_paths_traversal_and_symlinks(self):
        for name in ('vault/clarakey.vault', 'backups/test.vault', '../outside', '/absolute', '.clarakey.lock'):
            with self.subTest(name=name):
                self.manifest.write_text(self.digest+'  '+name+'\n')
                with self.assertRaises(ValueError):
                    archive_module.create_archive(self.bundle, self.output)
        (self.bundle/'app/alias.py').symlink_to(self.app)
        self.manifest.write_text(self.digest+'  app/alias.py\n')
        with self.assertRaises(ValueError):
            archive_module.create_archive(self.bundle, self.output)


if __name__ == '__main__':
    unittest.main()
