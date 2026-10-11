"""V1 envelope. All lengths and parameters are checked before expensive work."""
import json
import secrets
import struct
from dataclasses import dataclass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from .errors import AuthenticationError, InvalidVault, ValidationError

MAGIC = b'CLARAKEY'
VERSION = 1
# magic, version, KDF, AEAD, memory KiB, iterations, lanes, salt, nonce, ciphertext length
HEADER = struct.Struct('>8sHBBIII16s12sQ')
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_FILE = HEADER.size + MAX_PAYLOAD + 16
MEMORY_KIB, ITERATIONS, LANES = 65536, 3, 4


def wipe(value):
    """Best effort for owned mutable buffers; Python/GTK copies are not erasable."""
    if isinstance(value, bytearray):
        value[:] = b'\x00' * len(value)


def discard(value):
    """Invalidate borrowed collections too; immutable string copies remain a limitation."""
    if isinstance(value, dict):
        for child in value.values():
            discard(child)
        value.clear()
    elif isinstance(value, list):
        for child in value:
            discard(child)
        value.clear()
    elif isinstance(value, bytearray):
        wipe(value)
        value.clear()


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise InvalidVault('Duplicate fields in vault data.')
        result[k] = v
    return result


def decode_json(data):
    if len(data) > MAX_PAYLOAD:
        raise InvalidVault('Vault payload is too large.')
    depth, quoted, escaped = 0, False, False
    for c in data:
        if quoted:
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
        elif c == 34:
            quoted = True
        elif c in (91, 123):
            depth += 1
            if depth > 16:
                raise InvalidVault('Vault nesting exceeds the format limit.')
        elif c in (93, 125):
            depth -= 1
    try:
        return json.loads(data, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise InvalidVault('Invalid vault payload.') from None


def encode_json(data):
    try:
        result = bytearray(json.dumps(data, ensure_ascii=False, separators=(',', ':'),
                                     allow_nan=False).encode('utf-8'))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ValidationError('Invalid vault content.') from None
    if len(result) > MAX_PAYLOAD:
        wipe(result)
        raise ValidationError('Vault exceeds the 8 MiB size limit.')
    return result


@dataclass(frozen=True)
class Header:
    salt: bytes
    nonce: bytes
    size: int
    raw: bytes


def parse_header(blob):
    if not isinstance(blob, (bytes, bytearray)) or not HEADER.size + 16 <= len(blob) <= MAX_FILE:
        raise InvalidVault('Invalid vault size.')
    magic, version, kdf, aead, memory, iterations, lanes, salt, nonce, size = HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise InvalidVault('This is not a ClaraKey vault.')
    if version != VERSION:
        raise InvalidVault('Unsupported vault version; use a compatible ClaraKey release.')
    # V1 deliberately accepts a single audited parameter profile. No input-controlled KDF DoS.
    if (kdf, aead, memory, iterations, lanes) != (1, 1, MEMORY_KIB, ITERATIONS, LANES):
        raise InvalidVault('Unsupported cryptographic parameters.')
    if size != len(blob) - HEADER.size or not 16 <= size <= MAX_PAYLOAD + 16:
        raise InvalidVault('Invalid ciphertext length.')
    return Header(salt, nonce, size, bytes(blob[:HEADER.size]))


def derive_key(password, salt):
    if not isinstance(password, (bytes, bytearray)) or not 1 <= len(password) <= 1024:
        raise ValidationError('Password must contain 1–1024 UTF-8 bytes.')
    return bytearray(Argon2id(salt=salt, length=32, iterations=ITERATIONS,
                            lanes=LANES, memory_cost=MEMORY_KIB).derive(password))


def encrypt(data, key, salt):
    plain = encode_json(data)
    try:
        nonce = secrets.token_bytes(12)
        header = HEADER.pack(MAGIC, VERSION, 1, 1, MEMORY_KIB, ITERATIONS, LANES,
                             salt, nonce, len(plain) + 16)
        return header + AESGCM(key).encrypt(nonce, plain, header)
    finally:
        wipe(plain)


def decrypt_with_key(blob, key):
    h = parse_header(blob)
    try:
        plain = bytearray(AESGCM(key).decrypt(h.nonce, blob[HEADER.size:], h.raw))
    except InvalidTag:
        raise AuthenticationError('Incorrect password or damaged vault.') from None
    try:
        return decode_json(plain)
    finally:
        wipe(plain)


def unlock(blob, password):
    h = parse_header(blob)
    key = derive_key(password, h.salt)
    try:
        return decrypt_with_key(blob, key), key, h.salt
    except Exception:
        wipe(key)
        raise
