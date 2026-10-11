"""Bounded schemas; JSON only, no executable object deserialization."""
import base64
import binascii
import hashlib
import secrets
import string
import time
import uuid
from .errors import ValidationError
from .totp import validate_totp, normalize_secret

KINDS = ('totp', 'recovery', 'api', 'ssh', 'password', 'note', 'file')
NAMES = {'totp': 'Authenticator', 'recovery': 'Recovery codes', 'api': 'API keys',
         'ssh': 'SSH keys', 'password': 'Passwords', 'note': 'Secure notes', 'file': 'Files'}
FIELDS = {
    'totp': {'service', 'account', 'secret', 'algorithm', 'digits', 'period'},
    'recovery': {'codes'},
    'api': {'service', 'key_name', 'api_key', 'notes'},
    'ssh': {'host', 'username', 'private_key', 'public_key', 'notes'},
    'password': {'service', 'username', 'password', 'website', 'notes'},
    'note': {'note'},
    'file': {'filename', 'size', 'sha256', 'data', 'notes'},
}
REQUIRED = {'api': 'api_key', 'ssh': 'private_key', 'password': 'password', 'note': 'note'}
# Files live inside the single encrypted payload (at most 8 MiB, base64 adds a third), so they are capped.
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_FILE_BYTES = 5 * 1024 * 1024
AUTO_LOCK = (60, 300, 600, 1800, 0)
CLIPBOARD = (15, 30, 60, 0)


def fresh_vault():
    return {'schema': 1, 'entries': [], 'settings': {'auto_lock': 300, 'clipboard': 30}}


def _text(value, limit=65536):
    if not isinstance(value, str) or len(value.encode('utf-8', errors='surrogatepass')) > limit or '\x00' in value:
        raise ValidationError('A field is invalid or too large.')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise ValidationError('Invalid text encoding.') from None


def safe_filename(name):
    """A plain file name to suggest on export: no folders, no control characters, no hidden-file tricks."""
    _text(name, 255)
    if (not name.strip() or name in ('.', '..') or '/' in name or '\\' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValidationError('Use a plain file name without folders or control characters.')
    return name


def file_fields(filename, raw, notes=''):
    """Fields for a file entry from its bytes. The SHA-256 lets every load prove the bytes are intact."""
    if not isinstance(raw, (bytes, bytearray)) or not 1 <= len(raw) <= MAX_FILE_BYTES:
        raise ValidationError('Files must be between 1 byte and 1 MiB.')
    return {'filename': safe_filename(filename), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'data': base64.b64encode(bytes(raw)).decode('ascii'), 'notes': notes}


def file_bytes(entry):
    return bytearray(base64.b64decode(entry['fields']['data'], validate=True))


def _validate_file(f):
    safe_filename(f['filename'])
    _text(f['notes'])
    if type(f['size']) is not int or not 1 <= f['size'] <= MAX_FILE_BYTES:
        raise ValidationError('Files must be between 1 byte and 1 MiB.')
    if not isinstance(f['data'], str) or len(f['data']) != 4 * ((f['size'] + 2) // 3):
        raise ValidationError('Stored file data is damaged.')
    if not isinstance(f['sha256'], str) or len(f['sha256']) != 64 or any(c not in '0123456789abcdef' for c in f['sha256']):
        raise ValidationError('Stored file fingerprint is invalid.')
    try:
        raw = base64.b64decode(f['data'], validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError('Stored file data is damaged.') from None
    if len(raw) != f['size'] or hashlib.sha256(raw).hexdigest() != f['sha256']:
        raise ValidationError('Stored file data does not match its fingerprint.')


def payload_schema(data):
    """Schema 2 only once the vault holds a file, so vaults without files still open in ClaraKey 1.0."""
    return 2 if any(e.get('kind') == 'file' for e in data.get('entries', [])) else 1


def validate_entry(entry):
    if not isinstance(entry, dict) or set(entry) != {'id', 'kind', 'title', 'created', 'modified', 'fields'}:
        raise ValidationError('Invalid entry schema.')
    if entry['kind'] not in KINDS:
        raise ValidationError('Unsupported entry type.')
    if not isinstance(entry['id'], str) or len(entry['id']) != 32:
        raise ValidationError('Invalid entry identifier.')
    if any(c not in '0123456789abcdef' for c in entry['id']):
        raise ValidationError('Invalid entry identifier.')
    _text(entry['title'], 512)
    if not entry['title'].strip():
        raise ValidationError('Enter a title or service name.')
    for field in ('created', 'modified'):
        if type(entry[field]) is not int or not 0 <= entry[field] <= 253402300799:
            raise ValidationError('Invalid entry timestamp.')
    f = entry['fields']
    if not isinstance(f, dict) or set(f) != FIELDS[entry['kind']]:
        raise ValidationError('Invalid credential fields.')
    if entry['kind'] == 'file':
        _validate_file(f)
    elif entry['kind'] == 'recovery':
        if not isinstance(f['codes'], list) or not 1 <= len(f['codes']) <= 1000:
            raise ValidationError('Enter 1–1000 recovery codes.')
        for c in f['codes']:
            if not isinstance(c, dict) or set(c) != {'value', 'used'} or type(c['used']) is not bool:
                raise ValidationError('Invalid recovery code.')
            _text(c['value'], 2048)
            if not c['value'].strip():
                raise ValidationError('Recovery codes cannot be empty.')
    else:
        for k, v in f.items():
            if entry['kind'] == 'totp' and k in ('digits', 'period'):
                continue
            _text(v)
        if entry['kind'] == 'totp':
            validate_totp(f)
        if entry['kind'] in REQUIRED and not f[REQUIRED[entry['kind']]].strip():
            raise ValidationError('The secret field cannot be empty.')
    return entry


def validate_vault(data):
    if not isinstance(data, dict) or set(data) != {'schema', 'entries', 'settings'} or type(data['schema']) is not int or data['schema'] not in (1, 2):
        raise ValidationError('Unsupported vault payload schema.')
    settings = data['settings']
    if not isinstance(settings, dict) or set(settings) != {'auto_lock', 'clipboard'}:
        raise ValidationError('Invalid settings.')
    if type(settings['auto_lock']) is not int or settings['auto_lock'] not in AUTO_LOCK or type(settings['clipboard']) is not int or settings['clipboard'] not in CLIPBOARD:
        raise ValidationError('Invalid security settings.')
    if not isinstance(data['entries'], list) or len(data['entries']) > 5000:
        raise ValidationError('Vault exceeds the 5000 entry limit.')
    ids = set()
    for entry in data['entries']:
        validate_entry(entry)
        if entry['id'] in ids:
            raise ValidationError('Duplicate entry identifier.')
        ids.add(entry['id'])
    files = [e for e in data['entries'] if e['kind'] == 'file']
    if files and data['schema'] != 2:
        raise ValidationError('Files need vault schema 2.')
    if sum(e['fields']['size'] for e in files) > MAX_TOTAL_FILE_BYTES:
        raise ValidationError('Files in one vault are limited to 5 MiB in total.')
    return data


def new_entry(kind, title, fields):
    now = int(time.time())
    return validate_entry(dict(id=uuid.uuid4().hex, kind=kind, title=title.strip(),
                               fields=fields, created=now, modified=now))


def search_entries(entries, query='', kind=None):
    terms = query.casefold().split()
    result = []
    for e in entries:
        if kind and e['kind'] != kind:
            continue
        # Only explicit metadata; never search notes, passwords, codes or key material.
        f = e['fields']
        haystack = ' '.join([e['title']] + [str(f.get(k, '')) for k in
                            ('service', 'account', 'username', 'host', 'key_name', 'website', 'filename')]).casefold()
        if all(t in haystack for t in terms):
            result.append(e)
    return sorted(result, key=lambda e: (e['title'].casefold(), e['id']))


def generate_password(length=24, uppercase=True, lowercase=True, numbers=True, symbols=True):
    groups = [chars for enabled, chars in [(uppercase, string.ascii_uppercase), (lowercase, string.ascii_lowercase),
              (numbers, string.digits), (symbols, '!@#$%^&*()-_=+[]{}:,.?')] if enabled]
    if type(length) is not int or not 8 <= length <= 128 or not groups:
        raise ValidationError('Select at least one character group and a length of 8–128.')
    # Rejection sampling gives uniform passwords conditional on containing each selected group.
    alphabet = ''.join(groups)
    while True:
        result = ''.join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in result) for group in groups):
            return result


def password_strength(password):
    # A transparent usability hint, not an entropy estimate or breach lookup.
    if len(password) < 12:
        return 0.15, 'Too short · use at least 12 characters'
    if len(password) < 16:
        return 0.45, 'Fair length · a longer unique passphrase is better'
    if len(password) < 24:
        return 0.7, 'Good length · avoid quotes and reused passwords'
    return 1.0, 'Long passphrase · use several randomly chosen words'
