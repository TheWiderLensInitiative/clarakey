"""File entries: arbitrary binary files (signing keystores, certificates, GPG keys) inside the encrypted vault."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import secrets
import stat
import tempfile
import unittest

from clarakey.crypto import decrypt_with_key
from clarakey.errors import StorageError, ValidationError
from clarakey.model import (MAX_FILE_BYTES, MAX_TOTAL_FILE_BYTES, file_bytes, file_fields, new_entry,
                            payload_schema, safe_filename, search_entries, validate_entry, validate_vault)
from clarakey.session import Session
from clarakey.storage import PortableStore, read_external

PASSWORD = b'unit-test-only long master passphrase'


def keystore_bytes(n=4336):
    # Binary like a real .jks: NUL bytes, high bytes, a recognisable marker that must never reach disk in clear.
    return b'\x00\xfe\xed\xfe\xed' + b'TEST-ONLY-KEYSTORE-MARKER' + secrets.token_bytes(n - 30)


def file_entry(raw=None, name='release.jks', notes='test-only signing key notes'):
    return new_entry('file', 'Release signing key', file_fields(name, raw if raw is not None else keystore_bytes(), notes))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='clarakey-file-test-')
        self.root = Path(self.tmp.name)
        self.store = PortableStore(self.root)
        self.session = Session.create(self.store, PASSWORD)

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.tmp.cleanup()

    def stored_schema(self):
        return decrypt_with_key(self.store.read(), self.session.key)['schema']

    def test_binary_file_round_trip_after_reopen(self):
        raw = keystore_bytes()
        e = file_entry(raw)
        self.session.put(e)
        self.session.close()
        self.session = Session.open(self.store, PASSWORD)
        stored = self.session.entry(e['id'])
        self.assertEqual(bytes(file_bytes(stored)), raw)
        self.assertEqual(stored['fields']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(stored['fields']['size'], len(raw))
        self.assertEqual(stored['fields']['filename'], 'release.jks')

    def test_file_bytes_and_name_never_on_disk_in_clear(self):
        self.session.put(file_entry(name='TEST-ONLY-FILENAME.jks'))
        for path in self.root.rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                for marker in (b'TEST-ONLY-KEYSTORE-MARKER', b'TEST-ONLY-FILENAME', b'test-only signing key notes'):
                    self.assertNotIn(marker, data)

    def test_schema_is_2_only_while_files_exist(self):
        self.session.put(new_entry('note', 'Note', {'note': 'test-only'}))
        self.assertEqual(self.stored_schema(), 1)   # vaults without files still open in ClaraKey 1.0
        e = file_entry()
        self.session.put(e)
        self.assertEqual(self.stored_schema(), 2)
        self.session.delete(e['id'])
        self.assertEqual(self.stored_schema(), 1)

    def test_old_schema_and_unknown_schema_rejected(self):
        data = deepcopy(self.session.data)
        data['entries'] = [file_entry()]
        data['schema'] = 1
        with self.assertRaises(ValidationError):
            validate_vault(data)          # a file in a schema-1 payload is not allowed
        data['schema'] = 3
        with self.assertRaises(ValidationError):
            validate_vault(data)
        data['schema'] = 2
        validate_vault(data)

    def test_export_writes_exact_bytes_private_and_never_clobbers(self):
        raw = keystore_bytes()
        e = file_entry(raw)
        self.session.put(e)
        out = self.root / 'restored.jks'
        with self.assertRaises(StorageError):
            self.session.export(e['id'], out)              # needs explicit confirmation
        self.assertFalse(out.exists())
        self.session.export(e['id'], out, confirmed=True)
        self.assertEqual(out.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        with self.assertRaises(StorageError):
            self.session.export(e['id'], out, confirmed=True)
        self.assertEqual(out.read_bytes(), raw)

    def test_size_limits(self):
        with self.assertRaises(ValidationError):
            file_fields('empty.bin', b'')
        with self.assertRaises(ValidationError):
            file_fields('big.bin', b'\x01' * (MAX_FILE_BYTES + 1))
        file_fields('max.bin', b'\x01' * MAX_FILE_BYTES)
        per_file = MAX_FILE_BYTES
        for i in range(MAX_TOTAL_FILE_BYTES // per_file):
            self.session.put(file_entry(secrets.token_bytes(per_file), name=f'f{i}.bin'))
        before = deepcopy(self.session.data)
        with self.assertRaises(ValidationError):
            self.session.put(file_entry(b'\x01', name='one-too-many.bin'))
        self.assertEqual(self.session.data, before)       # a refused save changes nothing
        self.session.close()
        self.session = Session.open(self.store, PASSWORD)
        self.assertEqual(len(self.session.data['entries']), MAX_TOTAL_FILE_BYTES // per_file)

    def test_unsafe_filenames_rejected(self):
        for bad in ('', ' ', '.', '..', '../escape.jks', 'dir/key.jks', 'C:\\key.jks', 'new\nline.jks', 'nul\x00.jks',
                    'x' * 256):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                safe_filename(bad)
        for good in ('release.jks', 'clara-release.jks', 'my key (2026).p12', 'ключ.pem', '.gnupg-backup.asc'):
            self.assertEqual(safe_filename(good), good)

    def test_damaged_file_data_rejected(self):
        good = file_entry(keystore_bytes(300))
        cases = {
            'wrong fingerprint': dict(sha256='0' * 64),
            'uppercase fingerprint': dict(sha256=good['fields']['sha256'].upper()),
            'size mismatch': dict(size=good['fields']['size'] + 1),
            'not base64': dict(data='!' * len(good['fields']['data'])),
            'truncated data': dict(data=good['fields']['data'][:-4]),
            'size zero': dict(size=0),
            'size as text': dict(size='300'),
            'flipped byte': dict(data=('A' if good['fields']['data'][0] != 'A' else 'B') + good['fields']['data'][1:]),
        }
        for name, change in cases.items():
            bad = deepcopy(good)
            bad['fields'].update(change)
            with self.assertRaises(ValidationError, msg=name):
                validate_entry(bad)
        extra = deepcopy(good)
        extra['fields']['path'] = '/tmp/x'
        with self.assertRaises(ValidationError):
            validate_entry(extra)

    def test_backup_and_restore_keep_files(self):
        raw = keystore_bytes()
        e = file_entry(raw)
        self.session.put(e)
        backup = self.session.backup()
        self.session.delete(e['id'])
        candidate = Session.validate_backup(backup.read_bytes(), PASSWORD)
        self.session.restore(candidate, confirmed=True)
        self.assertEqual(bytes(file_bytes(self.session.entry(e['id']))), raw)
        self.assertEqual(self.stored_schema(), 2)

    def test_search_by_filename_not_contents(self):
        self.session.put(file_entry(name='clara-release.jks'))
        entries = self.session.data['entries']
        self.assertEqual(len(search_entries(entries, 'clara-release')), 1)
        self.assertEqual(len(search_entries(entries, 'TEST-ONLY-KEYSTORE-MARKER')), 0)
        self.assertEqual(len(search_entries(entries, 'signing key notes')), 0)

    def test_import_reader_enforces_the_file_limit(self):
        ok = self.root / 'ok.bin'
        ok.write_bytes(b'\x02' * MAX_FILE_BYTES)
        self.assertEqual(len(read_external(ok, MAX_FILE_BYTES)), MAX_FILE_BYTES)
        big = self.root / 'big.bin'
        big.write_bytes(b'\x02' * (MAX_FILE_BYTES + 1))
        with self.assertRaises(StorageError):
            read_external(big, MAX_FILE_BYTES)
        link = self.root / 'link.bin'
        os.symlink(ok, link)
        with self.assertRaises(StorageError):
            read_external(link, MAX_FILE_BYTES)

    def test_payload_schema_helper(self):
        self.assertEqual(payload_schema({'entries': []}), 1)
        self.assertEqual(payload_schema({'entries': [file_entry()]}), 2)


if __name__ == '__main__':
    unittest.main()
