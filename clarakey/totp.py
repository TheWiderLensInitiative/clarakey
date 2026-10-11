"""RFC 4226 / 6238 with standard-library HMAC; strict otpauth URI import."""
import base64
import binascii
import hashlib
import hmac
import re
import struct
import time
from urllib.parse import parse_qsl, unquote, urlsplit
from .errors import ValidationError

ALGORITHMS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


def normalize_secret(secret):
    if not isinstance(secret, str) or len(secret) > 1024:
        raise ValidationError('Invalid authenticator secret.')
    clean = ''.join(secret.split()).upper().rstrip('=')
    if not re.fullmatch('[A-Z2-7]+', clean):
        raise ValidationError('Secret must be Base32 (letters A–Z and digits 2–7).')
    try:
        decoded = base64.b32decode(clean + '=' * ((-len(clean)) % 8))
    except (ValueError, binascii.Error):
        raise ValidationError('Invalid Base32 secret.') from None
    if not 10 <= len(decoded) <= 128 or base64.b32encode(decoded).decode().rstrip('=') != clean:
        raise ValidationError('Use a canonical Base32 secret of 10–128 decoded bytes.')
    return clean


def validate_totp(fields):
    if not isinstance(fields.get('algorithm'), str) or fields['algorithm'] not in ALGORITHMS:
        raise ValidationError('TOTP algorithm must be SHA1, SHA256 or SHA512.')
    if type(fields.get('digits')) is not int or fields['digits'] not in (6, 7, 8):
        raise ValidationError('TOTP codes must have 6, 7 or 8 digits.')
    if type(fields.get('period')) is not int or not 15 <= fields['period'] <= 300:
        raise ValidationError('TOTP period must be 15–300 seconds.')
    normalize_secret(fields.get('secret'))


def code_at(fields, timestamp=None):
    validate_totp(fields)
    stamp = int(time.time() if timestamp is None else timestamp)
    if not 0 <= stamp <= 2**63 - 1:
        raise ValidationError('System time is outside the supported range.')
    secret = normalize_secret(fields['secret'])
    key = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
    counter = stamp // fields['period']
    digest = hmac.digest(key, struct.pack('>Q', counter), ALGORITHMS[fields['algorithm']])
    offset = digest[-1] & 15
    number = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return str(number % (10 ** fields['digits'])).zfill(fields['digits'])


def remaining(fields, timestamp=None):
    return fields['period'] - int(time.time() if timestamp is None else timestamp) % fields['period']


def parse_uri(uri):
    if not isinstance(uri, str) or len(uri) > 4096 or any(ord(c) < 32 for c in uri):
        raise ValidationError('Invalid authenticator URI.')
    if re.search(r'%(?![0-9a-fA-F]{2})', uri):
        raise ValidationError('Malformed percent encoding in URI.')
    try:
        parsed = urlsplit(uri)
        if parsed.scheme != 'otpauth' or parsed.netloc != 'totp' or parsed.fragment:
            raise ValueError()
        label = unquote(parsed.path[1:], encoding='utf-8', errors='strict')
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=16, encoding='utf-8', errors='strict')
        params = {}
        for k, v in pairs:
            if k in params or k not in {'secret', 'issuer', 'algorithm', 'digits', 'period'}:
                raise ValueError()
            params[k] = v
        if not label or len(label) > 512 or '/' in label or any(ord(c) < 32 for c in label):
            raise ValueError()
        prefix, sep, account = label.partition(':')
        issuer = params.get('issuer', prefix if sep else '')
        if sep and params.get('issuer', prefix) != prefix:
            raise ValidationError('URI label issuer and issuer parameter disagree.')
        account = account if sep else label
        if not account.strip() or len(issuer) > 256 or any(ord(c) < 32 for c in issuer):
            raise ValueError()
        result = dict(service=issuer or account, account=account, secret=normalize_secret(params['secret']),
                      algorithm=params.get('algorithm', 'SHA1').upper(),
                      digits=int(params.get('digits', '6')), period=int(params.get('period', '30')))
        validate_totp(result)
        return result
    except (ValueError, KeyError, UnicodeError):
        raise ValidationError('Invalid otpauth URI. Only standard TOTP parameters are accepted.') from None
