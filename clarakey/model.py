"""Bounded schemas; JSON only, no executable object deserialization."""
import secrets
import string
import time
import uuid
from .errors import ValidationError
from .totp import validate_totp, normalize_secret

KINDS = ('totp', 'recovery', 'api', 'ssh', 'password', 'note')
NAMES = {'totp': 'Authenticator', 'recovery': 'Recovery codes', 'api': 'API keys',
         'ssh': 'SSH keys', 'password': 'Passwords', 'note': 'Secure notes'}
FIELDS = {
    'totp': {'service', 'account', 'secret', 'algorithm', 'digits', 'period'},
    'recovery': {'codes'},
    'api': {'service', 'key_name', 'api_key', 'notes'},
    'ssh': {'host', 'username', 'private_key', 'public_key', 'notes'},
    'password': {'service', 'username', 'password', 'website', 'notes'},
    'note': {'note'},
}
REQUIRED = {'api': 'api_key', 'ssh': 'private_key', 'password': 'password', 'note': 'note'}
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
    if entry['kind'] == 'recovery':
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
    if not isinstance(data, dict) or set(data) != {'schema', 'entries', 'settings'} or type(data['schema']) is not int or data['schema'] != 1:
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
                            ('service', 'account', 'username', 'host', 'key_name', 'website')]).casefold()
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
