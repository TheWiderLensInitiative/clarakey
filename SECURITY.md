# Security policy

ClaraKey V1 is security-sensitive software in development. Its primitives come
from established libraries, but this application has not received an independent
security audit. Passing automated tests is not an assurance of absence of defects.
The exact release validation status is in [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).

## Responsible reporting

This local project has no public repository, security advisory URL or monitored
security email configured. Do not send reports to a guessed address. Contact the
person or organization that supplied your build through an existing private
channel and request a confidential reporting route. Before public distribution,
the maintainer should configure a monitored security contact or private repository
security advisories and update this document.

A useful private report includes the affected version/platform, impact, steps to
reproduce, and a minimal reproduction using **test-only** credentials. Do not send
a real vault, private key, master password, recovery code or screenshots of live
authenticator codes. Coordinate remediation and disclosure with the maintainer;
if private reporting is unavailable, a public request for a security contact should
contain no exploit details or secrets. No response-time promise or bounty program
has been established for this project.

## Cryptography actually used

* PyCA `cryptography` 46.0.5 in the supplied build, with its compiled Rust extension
  and OpenSSL backend. Python orchestrates operations; this is not a Rust
  application or a claim that all cryptographic code is Rust.
* Argon2id v1.3: 65,536 KiB, 3 iterations, 4 lanes, 16-byte random salt, 32-byte
  output. This follows RFC 9106's second recommended profile. V1 rejects any
  other profile before invoking the KDF. The build-host derivation measurement was
  approximately 0.074 seconds, not a promised performance result on other hosts.
* AES-256-GCM: 12-byte independently random nonce per encryption, 16-byte tag,
  complete header authenticated as additional data. Nonces use `secrets.token_bytes`
  and must never be replaced with timestamps, counters without durable state, or
  a simulation PRNG. Random 96-bit nonces have a nonzero collision probability;
  this design is intended for ordinary personal-vault write volumes, not billions
  of encryptions under one key.
* Python's `secrets` and OS entropy for passwords, salts, nonces and temporary-file
  names. Generator rejection sampling enforces the selected character classes.
* RFC 6238/4226 TOTP using standard-library `hmac`, SHA-1, SHA-256 or SHA-512.
  Algorithm, digits and period from an imported URI are validated and retained.
  Tests include all 18 published RFC 6238 vectors and PyCA's independent TOTP.
* `hashlib.sha256` is used only to detect changes to already encrypted disk bytes;
  it is not used as the password KDF or as a stored password verifier.

Reference documentation: [PyCA Argon2id](https://cryptography.io/en/46.0.5/hazmat/primitives/key-derivation-functions/),
[PyCA AESGCM](https://cryptography.io/en/46.0.5/hazmat/primitives/aead/),
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html),
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html).

## Operational boundaries

The master password, derived key and decrypted payload are never intentionally
written to disk. All application-managed temporary save/recovery files and backups
contain encrypted envelopes. Plaintext export is an explicit, confirmed user
operation and is never silently overwritten. Logs contain only fixed diagnostics;
unhandled production exceptions use a sanitized handler without exception objects
or tracebacks. Tests use generated/test-only secrets and may report assertion traces.

ClaraKey does not use browser storage, a keyring, persistent UI settings, native
recent-file databases or a service. The in-app file picker avoids OS recent-file
persistence. GSettings uses an in-memory backend. Font caches contain font metadata,
not vault data; the bundle directs those to its own runtime directory. The process
lock file is empty. GTK, the display server, accessibility services, input methods
and the host desktop remain trusted dependencies.

Mutable application key buffers are overwritten and cleared on lock. Collection
references are invalidated recursively and visible widgets/dialogs are cleared.
Python/GTK immutable strings, C libraries, GC and the allocator can leave copies;
**reliable complete memory zeroization is not provided**. Neither `mlockall` nor
full swap exclusion is claimed. The entry point disables core dumps and requests
Linux nondumpable status, but privileged malware is outside the protection boundary.

Files use 0600 and directories 0700 when supported. FAT/exFAT may not enforce these
permissions; encryption remains essential. Paths for generated files contain no
user entry names. Bounded reads reject symlinks, hardlinks and special files.
Atomic rename and directory synchronization reduce corruption risk but cannot
make an untrustworthy USB controller reliable. Previous revisions and backups
intentionally retain older secrets; deletion is not secure erasure.

No FIDO2/WebAuthn, TPM, hardware-backed storage or secure-element behavior is
implemented or claimed. Changing the master password is not a V1 UI feature.
Create a new vault and explicitly restore an old encrypted backup into it to
migrate to a new master password; protect/delete old backups according to your
threat model, remembering that flash deletion does not guarantee erasure.
