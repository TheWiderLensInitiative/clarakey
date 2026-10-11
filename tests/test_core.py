import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import secrets
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from clarakey.crypto import (HEADER, MAX_FILE, encrypt, unlock, parse_header,
                             decrypt_with_key, decode_json, wipe)
from clarakey.errors import ClaraKeyError, AuthenticationError, InvalidVault, StorageError, ValidationError
from clarakey.model import (fresh_vault, new_entry, validate_vault, generate_password,
                            search_entries, password_strength)
from clarakey.policy import IdleLock, UnlockThrottle, ClipboardGuard
from clarakey.session import Session
from clarakey.storage import PortableStore, read_external, export_plaintext
from clarakey.totp import parse_uri, code_at, remaining, normalize_secret

PASSWORD = b'unit-test-only long master passphrase'
SECRET = base64.b32encode(b'12345678901234567890').decode().rstrip('=')


def account():
    return new_entry('totp', 'Example authenticator', dict(service='Example', account='test@example.invalid',
                    secret=SECRET, algorithm='SHA1', digits=6, period=30))


def password_entry():
    return new_entry('password', 'Example password', dict(service='Example', username='test-user',
                    password='TEST-ONLY-credential-never-use-913718', website='https://example.invalid', notes='private note'))


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='clarakey-test-')
        self.root = Path(self.tmp.name)
        self.store = PortableStore(self.root)
        self.session = Session.create(self.store, PASSWORD)

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.tmp.cleanup()

    def test_create_correct_unlock_and_persistence(self):
        self.session.put(password_entry())
        self.session.close()
        self.session = Session.open(self.store, PASSWORD)
        self.assertEqual(len(self.session.data['entries']), 1)

    def test_wrong_password_rejected(self):
        with self.assertRaises(AuthenticationError):
            Session.open(self.store, b'definitely the wrong password')

    def test_ciphertext_contains_no_credentials(self):
        e = password_entry()
        self.session.put(e)
        self.session.put(account())
        for path in self.root.rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                for marker in (PASSWORD, e['fields']['password'].encode(), SECRET.encode(), b'test-user', b'Example'):
                    self.assertNotIn(marker, data)

    def test_random_nonce_every_save(self):
        first = parse_header(self.store.read())
        self.session.settings(60, 15)
        second = parse_header(self.store.read())
        self.assertEqual(first.salt, second.salt)
        self.assertNotEqual(first.nonce, second.nonce)

    def test_tamper_all_header_regions_ciphertext_and_tag(self):
        original = self.store.read()
        for offset in (0, 8, 10, 11, 12, 16, 20, 24, 40, 52, HEADER.size, len(original)-1):
            changed = bytearray(original)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ClaraKeyError):
                unlock(changed, PASSWORD)

    def test_unsupported_version(self):
        blob = bytearray(self.store.read())
        struct.pack_into('>H', blob, 8, 999)
        with self.assertRaisesRegex(InvalidVault, 'version'):
            parse_header(blob)

    def test_kdf_bounds_before_derivation(self):
        blob = bytearray(self.store.read())
        struct.pack_into('>I', blob, 12, 0xffffffff)
        with patch('clarakey.crypto.derive_key', side_effect=AssertionError('must not derive')):
            with self.assertRaises(InvalidVault):
                unlock(blob, PASSWORD)

    def test_truncated_and_oversized_vault(self):
        for blob in (b'', b'CLARAKEY', self.store.read()[:-1], self.store.read()+b'junk', b'\x00'*(MAX_FILE+1)):
            with self.assertRaises(InvalidVault):
                parse_header(blob)

    def test_fuzz_envelope_fail_closed(self):
        for size in range(0, 150):
            with self.assertRaises(InvalidVault):
                parse_header(secrets.token_bytes(size))

    def test_invalid_authenticated_payload(self):
        blob = encrypt({'schema': 999}, self.session.key, self.session.salt)
        self.store.save(blob, lambda b: decrypt_with_key(b, self.session.key))
        with self.assertRaises(ValidationError):
            Session.open(self.store, PASSWORD)

    def test_duplicate_json_keys_and_deep_json(self):
        for value in (b'{"a":1,"a":2}', b'{"v":NaN}', b'['*2000+b']'*2000, b'\xff'):
            with self.assertRaises(InvalidVault):
                decode_json(value)

    def test_backup_restore_different_password_keeps_current_password(self):
        self.session.put(password_entry())
        path = self.session.backup()
        candidate = Session.validate_backup(read_external(path), PASSWORD)
        other_key = bytearray(secrets.token_bytes(32))
        # Also exercise foreign backup password, not only the active key.
        with tempfile.TemporaryDirectory() as directory:
            with PortableStore(directory) as other:
                foreign = Session.create(other, b'foreign-test-only-password')
                foreign.put(account())
                foreign_blob = other.read()
                foreign.close()
        candidate = Session.validate_backup(foreign_blob, b'foreign-test-only-password')
        self.session.restore(candidate, confirmed=True)
        reopened = Session.open(self.store, PASSWORD)
        self.assertEqual(reopened.data['entries'][0]['kind'], 'totp')
        reopened.close()
        with self.assertRaises(AuthenticationError):
            Session.open(self.store, b'foreign-test-only-password')
        wipe(other_key)

    def test_restore_confirmation_and_bad_backup_do_not_modify(self):
        before = self.store.read()
        with self.assertRaises(ValidationError):
            self.session.restore(fresh_vault())
        with self.assertRaises(AuthenticationError):
            Session.validate_backup(before[:-1] + bytes([before[-1] ^ 1]), PASSWORD)
        self.assertEqual(self.store.read(), before)

    def test_atomic_save_failed_replace_preserves_old_and_memory(self):
        before = self.store.read()
        replace = os.replace
        def fail(src, dst, **kwargs):
            if dst == 'clarakey.vault':
                raise OSError('simulated USB I/O failure')
            return replace(src, dst, **kwargs)
        with patch('clarakey.storage.os.replace', side_effect=fail), self.assertRaises(StorageError):
            self.session.put(password_entry())
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.session.data['entries'], [])
        self.assertEqual((self.store.vault_path.parent/'.previous.vault').read_bytes(), before)

    def test_fsync_failure_preserves_old(self):
        before = self.store.read()
        with patch('clarakey.storage.os.fsync', side_effect=OSError('simulated')), self.assertRaises(StorageError):
            self.session.put(password_entry())
        self.assertEqual(self.store.read(), before)

    def test_interrupted_pending_does_not_replace_valid_vault(self):
        before = self.store.read()
        (self.store.vault_path.parent/'.pending-crashed.vault').write_bytes(before[:40])
        reopened = Session.open(self.store, PASSWORD)
        reopened.close()
        self.assertEqual(self.store.read(), before)
        self.assertEqual(len(self.store.recovery_files()), 1)

    def test_external_change_prevents_overwrite(self):
        original = self.store.vault_path.read_bytes()
        self.store.vault_path.write_bytes(original + b'changed')
        with self.assertRaises(StorageError):
            self.session.put(password_entry())
        self.assertEqual(self.session.data['entries'], [])

    def test_second_instance_excluded(self):
        with self.assertRaises(StorageError):
            PortableStore(self.root)

    def test_removed_directory_detected(self):
        old = self.root/'vault'
        old.rename(self.root/'removed-vault')
        old.mkdir()
        with self.assertRaises(StorageError):
            self.session.put(password_entry())
        self.assertFalse((old/'clarakey.vault').exists())

    def test_symlink_and_hardlink_refused(self):
        self.store.vault_path.unlink()
        target = self.root/'target'
        target.write_bytes(b'unchanged')
        self.store.vault_path.symlink_to(target)
        with self.assertRaises(StorageError):
            self.store.read()
        self.assertEqual(target.read_bytes(), b'unchanged')
        self.store.vault_path.unlink()
        os.link(target, self.store.vault_path)
        with self.assertRaises(StorageError):
            self.store.read()

    def test_private_permissions(self):
        self.assertEqual(self.store.vault_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root/'vault').stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.session.backup().stat().st_mode & 0o777, 0o600)

    def test_export_explicit_no_clobber(self):
        e = password_entry()
        self.session.put(e)
        path = self.root/'export.json'
        with self.assertRaises(StorageError):
            self.session.export(e['id'], path)
        self.assertFalse(path.exists())
        self.session.export(e['id'], path, confirmed=True)
        self.assertIn(e['fields']['password'].encode(), path.read_bytes())
        with self.assertRaises(StorageError):
            self.session.export(e['id'], path, confirmed=True)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_lock_discards_state_and_wipes_mutable_key(self):
        key = self.session.key
        self.session.put(password_entry())
        self.session.close()
        self.assertEqual(key, bytearray())
        self.assertEqual(self.session.data, {})
        for call in (self.session.backup, lambda: self.session.entry('anything'), lambda: self.session.put(account())):
            with self.assertRaises(AuthenticationError):
                call()

    def test_all_credential_types_edit_delete_and_used_codes(self):
        entries = [account(), password_entry(),
            new_entry('recovery', 'Recovery', {'codes':[{'value':'unit-only-123', 'used':False}]}),
            new_entry('api', 'API', dict(service='Example', key_name='test', api_key='unit-token', notes='')),
            new_entry('ssh', 'SSH', dict(host='example.invalid', username='test', private_key='test-only-stored-text', public_key='', notes='')),
            new_entry('note', 'Note', {'note':'test-only note'})]
        for e in entries:
            self.session.put(e)
        self.assertEqual(len(self.session.data['entries']), 6)
        self.session.mark_code(entries[2]['id'], 0, True)
        self.assertTrue(self.session.entry(entries[2]['id'])['fields']['codes'][0]['used'])
        e = deepcopy(entries[-1]); e['title'] = 'Edited'; self.session.put(e)
        self.assertEqual(self.session.entry(e['id'])['title'], 'Edited')
        self.session.delete(e['id'])
        self.assertEqual(len(self.session.data['entries']), 5)

    def test_locked_restore_requires_confirmation_and_validates_before_write(self):
        blob = self.store.read()
        before = blob
        with self.assertRaises(ValidationError):
            Session.restore_locked(self.store, blob, PASSWORD)
        with self.assertRaises(AuthenticationError):
            Session.restore_locked(self.store, blob, b'wrong-password', confirmed=True)
        self.assertEqual(self.store.read(), before)
        self.session.close()
        Session.restore_locked(self.store, blob, PASSWORD, confirmed=True)
        self.session = Session.open(self.store, PASSWORD)

    def test_locked_restore_recovers_corrupt_current_vault(self):
        blob = self.store.read()
        self.session.close()
        self.store.vault_path.write_bytes(b'corrupted-test-only')
        Session.restore_locked(self.store, blob, PASSWORD, confirmed=True)
        self.assertEqual((self.store.vault_path.parent/'.previous.vault').read_bytes(), b'corrupted-test-only')
        self.session = Session.open(self.store, PASSWORD)

    def test_locked_restore_stops_on_backup_io_failure(self):
        blob = self.store.read()
        with patch.object(self.store, 'backup', side_effect=StorageError('test-only I/O failure')):
            with self.assertRaises(StorageError):
                Session.restore_locked(self.store, blob, PASSWORD, confirmed=True)
        self.assertEqual(self.store.read(), blob)

    def test_locked_restore_into_empty_portable_directory(self):
        blob = self.store.read()
        with tempfile.TemporaryDirectory() as directory:
            with PortableStore(directory) as store:
                Session.restore_locked(store, blob, PASSWORD, confirmed=True)
                session = Session.open(store, PASSWORD)
                session.close()

    def test_wipe_invalidates_borrowed_entry_collections(self):
        self.session.put(password_entry())
        borrowed = self.session.data['entries'][0]
        fields = borrowed['fields']
        self.session.close()
        self.assertEqual(borrowed, {})
        self.assertEqual(fields, {})

    def test_replacement_readback_failure_preserves_vault(self):
        before = self.store.read()
        original = self.store._read
        def bad_read(name, fd):
            result = original(name, fd)
            return result[:-1] if name.startswith('.pending-') else result
        with patch.object(self.store, '_read', side_effect=bad_read):
            with self.assertRaises(InvalidVault):
                self.session.put(password_entry())
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.session.data['entries'], [])

    def test_independent_vault_salts(self):
        first = parse_header(self.store.read()).salt
        with tempfile.TemporaryDirectory() as directory:
            with PortableStore(directory) as other:
                session = Session.create(other, PASSWORD)
                self.assertNotEqual(first, parse_header(other.read()).salt)
                session.close()

    def test_flat_layout(self):
        blob = self.store.read()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'clarakey.vault').write_bytes(blob)
            with PortableStore(directory) as store:
                session = Session.open(store, PASSWORD)
                self.assertTrue(store.flat)
                session.put(account())
                session.close()
                self.assertFalse(Path(directory, 'vault').exists())


class TotpTests(unittest.TestCase):
    def test_all_rfc6238_vectors_and_independent_pyca(self):
        times = [59,1111111109,1111111111,1234567890,2000000000,20000000000]
        vectors = {
            'SHA1': (b'12345678901234567890', hashes.SHA1(), ['94287082','07081804','14050471','89005924','69279037','65353130']),
            'SHA256': (b'12345678901234567890123456789012', hashes.SHA256(), ['46119246','68084774','67062674','91819424','90698825','77737706']),
            'SHA512': (b'1234567890123456789012345678901234567890123456789012345678901234', hashes.SHA512(), ['90693936','25091201','99943326','93441116','38618901','47863826']),
        }
        for algorithm, (key, digest, expected) in vectors.items():
            f = dict(secret=base64.b32encode(key).decode(), algorithm=algorithm, digits=8, period=30)
            independent = TOTP(key, 8, digest, 30)
            for stamp, code in zip(times, expected):
                with self.subTest(algorithm=algorithm, timestamp=stamp):
                    self.assertEqual(code_at(f, stamp), code)
                    self.assertEqual(code_at(f, stamp), independent.generate(stamp).decode())

    def test_six_digits_nondefault_period_boundaries(self):
        f = account()['fields']; f['period'] = 60
        self.assertEqual(code_at(f, 59), '755224')
        self.assertNotEqual(code_at(f, 59), code_at(f, 60))
        self.assertEqual(remaining(f, 59), 1)
        self.assertEqual(remaining(f, 60), 60)

    def test_uri_defaults_and_custom(self):
        f = parse_uri('otpauth://totp/Example:test%40example.invalid?secret='+SECRET+'&issuer=Example')
        self.assertEqual((f['service'],f['account'],f['digits'],f['period']), ('Example','test@example.invalid',6,30))
        f = parse_uri('otpauth://totp/user?secret='+SECRET+'&algorithm=SHA512&digits=8&period=60')
        self.assertEqual((f['algorithm'],f['digits'],f['period']), ('SHA512',8,60))

    def test_invalid_uris_and_secrets(self):
        prefix = 'otpauth://totp/Service:user?secret='+SECRET
        values = ['https://example.invalid', 'otpauth://hotp/user?secret='+SECRET,
                  prefix+'&issuer=Other', prefix+'&secret='+SECRET, prefix+'&digits=99',
                  prefix+'&algorithm=MD5', prefix+'&period=0', prefix+'&extra=ignored',
                  prefix+'#fragment', 'otpauth://totp/%XX?secret='+SECRET, prefix+'&issuer=%FF']
        for value in values:
            with self.subTest(uri_kind=value.split('?')[0]), self.assertRaises(ValidationError):
                parse_uri(value)
        for s in ('abc0', '', 'A', 'MZXW6', 'x'*2000):
            with self.assertRaises(ValidationError):
                normalize_secret(s)


class ModelPolicyTests(unittest.TestCase):
    def test_password_generator_groups_and_randomness(self):
        results = {generate_password(24) for _ in range(100)}
        self.assertEqual(len(results), 100)
        for password in results:
            self.assertEqual(len(password), 24)
            for check in (str.isupper, str.islower, str.isdigit):
                self.assertTrue(any(check(c) for c in password))
            self.assertTrue(any(not c.isalnum() for c in password))
        self.assertTrue(generate_password(8, False, False, True, False).isdigit())
        for args in [(7,), (129,), (20,False,False,False,False)]:
            with self.assertRaises(ValidationError):
                generate_password(*args)

    def test_search_only_metadata(self):
        entries = [account(), password_entry()]
        self.assertEqual(len(search_entries(entries, 'eXamPle')), 2)
        self.assertEqual(len(search_entries(entries, 'test-user', 'password')), 1)
        self.assertEqual(search_entries(entries, 'credential-never-use'), [])
        self.assertEqual(search_entries(entries, 'private note'), [])

    def test_schema_and_settings_rejected(self):
        for bad in ({}, {'schema':2,'entries':[],'settings':{}}, {'schema':1,'entries':'bad','settings':{}}):
            with self.assertRaises(ValidationError):
                validate_vault(bad)
        data = fresh_vault(); data['settings']['auto_lock'] = True
        with self.assertRaises(ValidationError):
            validate_vault(data)
        data = fresh_vault()
        entry = password_entry()
        entry['id'] = '+' + '0' * 31
        data['entries'] = [entry]
        with self.assertRaises(ValidationError):
            validate_vault(data)

    def test_auto_lock_activity_timeout_and_never(self):
        now = [0]; idle = IdleLock(60, lambda:now[0])
        now[0] = 59; self.assertFalse(idle.due())
        idle.touch(); now[0] = 118; self.assertFalse(idle.due())
        now[0] = 119; self.assertTrue(idle.due())
        idle.timeout = 0; now[0] = 100000; self.assertFalse(idle.due())

    def test_increasing_bounded_throttle_and_reset(self):
        now = [0]; throttle = UnlockThrottle(lambda: now[0])
        delays=[]
        for _ in range(10):
            throttle.failed(); delays.append(throttle.remaining())
            now[0] += 100
        self.assertEqual(delays[:5], [0,0,2,4,8])
        self.assertLessEqual(max(delays), 60)
        throttle.success(); self.assertEqual(throttle.failures, 0)

    def test_clipboard_ownership_new_identical_content_and_never(self):
        class Backend:
            token = None
            def set(self, text): self.token = object(); return self.token
            def owns(self, token): return self.token is token
            def clear(self): self.token = None
        now = [0]; backend = Backend(); guard = ClipboardGuard(backend, lambda:now[0])
        guard.copy('test-only', 30); now[0]=29; guard.tick(); self.assertIsNotNone(backend.token)
        now[0]=30; guard.tick(); self.assertIsNone(backend.token)
        guard.copy('test-only', 15); newer=backend.set('test-only'); now[0]=60; guard.tick()
        self.assertIs(backend.token, newer)
        guard.copy('test-only', 0); now[0]=999; guard.tick(); self.assertIsNotNone(backend.token)
        guard.clear(); self.assertIsNone(backend.token)

    def test_strength_is_length_hint(self):
        self.assertLess(password_strength('short')[0], password_strength('a long test-only passphrase')[0])


if __name__ == '__main__':
    unittest.main()
