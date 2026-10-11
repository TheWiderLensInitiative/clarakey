"""All edits are transactional: validate, encrypt, verify/write, then publish state."""
from copy import deepcopy
import gc
import secrets
import time
from .crypto import decrypt_with_key, derive_key, encrypt, unlock, wipe, encode_json, discard
from .errors import AuthenticationError, ValidationError, InvalidVault
from .model import fresh_vault, validate_vault, validate_entry, payload_schema, file_bytes
from .storage import export_plaintext


class Session:
    def __init__(self, store, data, key, salt):
        self.store, self.data, self.key, self.salt = store, data, key, salt
        self.active = True

    @classmethod
    def create(cls, store, password):
        if len(password) < 12:
            raise ValidationError('Use at least 12 UTF-8 bytes for the master password.')
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        try:
            data = fresh_vault()
            blob = encrypt(data, key, salt)
            store.save(blob, lambda b: validate_vault(decrypt_with_key(b, key)), create=True)
            return cls(store, data, key, salt)
        except Exception:
            wipe(key)
            raise

    @classmethod
    def open(cls, store, password):
        data, key, salt = unlock(store.read(), password)
        try:
            validate_vault(data)
            return cls(store, data, key, salt)
        except Exception:
            wipe(key)
            raise

    def require_active(self):
        if not self.active:
            raise AuthenticationError('Unlock the vault first.')

    def entry(self, entry_id):
        self.require_active()
        for entry in self.data['entries']:
            if entry['id'] == entry_id:
                return entry
        raise ValidationError('Entry no longer exists.')

    def commit(self, candidate):
        self.require_active()
        candidate['schema'] = payload_schema(candidate)
        validate_vault(candidate)
        blob = encrypt(candidate, self.key, self.salt)
        self.store.save(blob, lambda b: validate_vault(decrypt_with_key(b, self.key)))
        self.data = candidate

    def put(self, entry):
        self.require_active()
        validate_entry(entry)
        candidate = deepcopy(self.data)
        candidate['entries'] = [e for e in candidate['entries'] if e['id'] != entry['id']]
        candidate['entries'].append(deepcopy(entry))
        self.commit(candidate)

    def delete(self, entry_id):
        self.entry(entry_id)
        candidate = deepcopy(self.data)
        candidate['entries'] = [e for e in candidate['entries'] if e['id'] != entry_id]
        self.commit(candidate)

    def mark_code(self, entry_id, index, used):
        e = deepcopy(self.entry(entry_id))
        if e['kind'] != 'recovery' or type(index) is not int or not 0 <= index < len(e['fields']['codes']):
            raise ValidationError('Invalid recovery code selection.')
        e['fields']['codes'][index]['used'] = bool(used)
        e['modified'] = int(time.time())
        self.put(e)

    def settings(self, auto_lock, clipboard):
        self.require_active()
        candidate = deepcopy(self.data)
        candidate['settings'] = dict(auto_lock=auto_lock, clipboard=clipboard)
        self.commit(candidate)

    def backup(self):
        self.require_active()
        # Fresh encryption of authenticated in-memory state; disk edits cannot poison backups.
        blob = encrypt(self.data, self.key, self.salt)
        validate_vault(decrypt_with_key(blob, self.key))
        return self.store.backup(blob)

    @staticmethod
    def validate_backup(blob, password):
        candidate, key, _ = unlock(blob, password)
        try:
            return validate_vault(candidate)
        finally:
            wipe(key)

    def restore(self, candidate, *, confirmed=False):
        self.require_active()
        if not confirmed:
            raise ValidationError('Restoring requires confirmation after validation.')
        validate_vault(candidate)
        backup = self.backup()
        # Restore content under the current vault password, even for foreign backups.
        self.commit(deepcopy(candidate))
        return backup

    @staticmethod
    def restore_locked(store, blob, password, *, confirmed=False):
        if not confirmed:
            raise ValidationError('Validate and confirm the backup before replacing the vault.')
        candidate = Session.validate_backup(blob, password)
        discard(candidate)
        exists = store.exists()
        if exists:
            old = store.read()
            try:
                store.backup(old)
            except InvalidVault:
                # The save protocol retains even a malformed old file as .previous.vault.
                # Actual backup I/O errors must stop restoration, not be swallowed.
                pass
        def verify(data):
            validated = Session.validate_backup(data, password)
            discard(validated)
        store.save(blob, verify, create=not exists)

    def export(self, entry_id, path, *, confirmed=False):
        e = self.entry(entry_id)
        if e['kind'] == 'file':
            data = file_bytes(e)   # the original bytes, exactly as added
        elif e['kind'] == 'ssh':
            data = bytearray(e['fields']['private_key'].encode())
        else:
            data = encode_json(e)
        try:
            export_plaintext(path, data, confirmed=confirmed)
        finally:
            wipe(data)

    def close(self):
        self.active = False
        wipe(self.key)
        self.key.clear()
        discard(self.data)
        self.salt = b''
        gc.collect()
