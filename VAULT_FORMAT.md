# ClaraKey vault format v1

All integers in the binary envelope are unsigned, big-endian. The header is
exactly 60 bytes, defined by Python struct `>8sHBBIII16s12sQ`:

* Offset 0, 8 bytes: ASCII `CLARAKEY`.
* Offset 8, 2 bytes: format version, `1`.
* Offset 10, 1 byte: KDF identifier, `1` = Argon2id v1.3.
* Offset 11, 1 byte: AEAD identifier, `1` = AES-256-GCM.
* Offset 12, 4 bytes: memory cost in KiB, `65536`.
* Offset 16, 4 bytes: iterations, `3`.
* Offset 20, 4 bytes: lanes, `4`.
* Offset 24, 16 bytes: random salt generated when the vault is created.
* Offset 40, 12 bytes: fresh random GCM nonce for each save or backup encryption.
* Offset 52, 8 bytes: ciphertext length including the 16-byte authentication tag.
* Offset 60 onward: ciphertext followed by the 16-byte GCM authentication tag.

The entire exact header is AEAD additional authenticated data. It is not encrypted;
format identifiers, costs, salt, nonce and ciphertext length are public. Entries,
metadata, notes, timestamps and user settings are inside the encrypted payload.
No password hash/verifier is stored: successful authenticated decryption verifies
possession of the key. The 32-byte key is derived directly from the UTF-8 master
password with Argon2id. Passwords are not silently Unicode-normalized or trimmed.

V1 accepts exactly the stated profile. Reject unsupported versions, algorithm
identifiers, KDF profiles and mismatching lengths before deriving a key. An input
file cannot request unbounded KDF memory or CPU. Maximum file size is 8,388,684
bytes: 60-byte header, up to 8 MiB plaintext, and a 16-byte tag. Reads are bounded
and reject nonregular files, symbolic links and hardlinked sensitive files.

## Authenticated payload

UTF-8 JSON contains exactly `schema: 1`, `entries` and `settings`. JSON duplicate
keys, NaN/Infinity, malformed UTF-8 and nesting over 16 levels are rejected. No
pickle, YAML objects, executable data, compressed payload or arbitrary type
instantiation is used. The payload has at most 5000 entries and each text field is
at most 65,536 UTF-8 bytes (titles 512 bytes; recovery codes 2048 bytes each).

Every entry has `id` (32 hex characters), `kind`, `title`, `created`, `modified`,
and `fields`. Timestamps are UTC Unix seconds. Kinds and their exact field sets:

* `totp`: service, account, secret, algorithm, digits, period.
* `recovery`: codes, a list of value/used objects (1–1000 codes).
* `api`: service, key_name, api_key, notes.
* `ssh`: host, username, private_key, public_key, notes.
* `password`: service, username, password, website, notes.
* `note`: note.

Settings contain `auto_lock` (60, 300, 600, 1800 or 0 seconds) and `clipboard`
(15, 30, 60 or 0 seconds); zero disables the corresponding idle timer. Explicit
lock/exit always clears owned clipboard content.

## Writes and recovery

Save creates a unique `.pending-<random>.vault` in the vault directory, with mode
0600 where supported. It writes ciphertext, flushes/fsyncs, rereads, compares bytes
and authenticates/decrypts/validates the replacement. The old ciphertext is copied
to a new encrypted temporary file, flushed/verified and atomically renamed to
`.previous.vault`. The pending replacement is then atomically renamed to
`clarakey.vault`; the directory is synced where supported. No plaintext temporary
file is part of this protocol.

A cooperating second process is excluded by `flock` on `.clarakey.lock`. A hash
of the loaded ciphertext and a final equality check detect external edits; this
is not protection against a malicious writer with access to the live process or
a hostile filesystem. Open directory descriptors plus device/inode checks detect
removed/replaced portable directories. No save fallback to a host directory is
allowed. A failure after rename but before sync is an uncertain commit: reopen
and authenticate the stored vault before continuing.

A process crash can leave encrypted pending files. They are never automatically
trusted or installed. The restore dialog offers them and `.previous.vault` as
recovery candidates; validation and confirmation are mandatory. A pending file
may be incomplete. The previous revision intentionally retains deleted or changed
secrets, as do older backups. Flash media and controller caches can defeat full
power-loss durability despite OS-level flushes; keep another encrypted backup.

## Migration

Version 1 has no legacy formats to migrate. Future incompatible envelopes require
a distinct version and a separately bounded parser. Authenticate and validate the
old format first, then migrate in memory and use the same safe replacement
protocol. Never reinterpret unknown versions as v1. Backups have the identical
format and are usable with the password active when they were created. Restore
while unlocked reencrypts backup content under the current vault key/password;
restore while locked installs the validated backup and uses its password.
