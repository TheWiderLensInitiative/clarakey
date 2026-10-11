# ClaraKey V1 threat model

## Assets and assumptions

Assets are the master password, derived key, TOTP seeds and codes, stored
credentials/notes, and identifying metadata. The vault encrypts the complete
payload. File existence, ciphertext length, version/profile, backup names, file
sizes and modification times remain observable.

The application binary, Python/GTK/PyCA runtime, host kernel, desktop and input
path must be trustworthy. The random-number generator and host clock must work.
A strong, unique master passphrase and an encrypted backup on another drive are
user responsibilities. The app has no remote recovery authority or online service.

## Lost or stolen USB drive

A locked vault and its backups expose only authenticated ciphertext and public
format parameters. Without the password, an attacker must attack the primitives
or guess the password. File permissions may be absent on USB filesystems, so they
are secondary. A drive removed while unlocked does not erase a compromised host's
memory; ClaraKey detects a missing/replaced directory and locks on its next timer
iteration. Physical disappearance without a changed mount identity can be noticed
only when the kernel reports an I/O failure.

A thief can delete, replace, copy or roll back entire encrypted vaults. AEAD detects
unauthenticated changes, but an old valid ciphertext is still valid. There is no
trusted hardware monotonic counter or cloud state to prevent rollback. An attacker
with write access can also replace the application executable for a later launch;
verify distribution integrity and keep the host/application trusted.

## Offline brute force

Argon2id (64 MiB, 3 passes, 4 lanes) imposes work per guess. It does not rescue a
weak, reused or disclosed password. Salt prevents precomputed work from being
shared between independently created vaults. UI delays after failed attempts are
only a convenience defense; they are process-local and do not slow an attacker
working on a copied file. No vault destruction, permanent lockout or backdoor is
used.

## Modified/corrupted vault and malicious input

Every encrypted byte and the exact header are authenticated by AES-GCM. Wrong
passwords and failed authentication produce the same generic message. Invalid
format/version/profile inputs are rejected before key derivation. File length,
KDF profile, JSON depth, duplicate keys, field types, entry counts and field sizes
are bounded. JSON cannot instantiate arbitrary objects. File reads refuse symbolic
links, hardlinks, pipes/devices and oversized files. No shell command is constructed
from an entry, filename or secret. URI parsers reject HOTP, unknown or duplicated
parameters, inconsistent issuers and invalid Base32.

Validation limits resource use but is not a formal parser proof or exhaustive
fuzz campaign. An attacker can deny availability by damaging/removing data or
exhausting storage. Header validation errors intentionally reveal public format
information. System filenames/file-picker labels are displayed as plain text,
never evaluated as HTML or shell commands.

## Clipboard and shoulder surfing

Secrets are masked in entry details; TOTP codes are intentionally visible. Explicit
reveal and edit operations expose the selected information. The clipboard is a
shared desktop channel. A provider-identity check prevents timeout cleanup from
clearing a newer owner's copy; explicit lock clears still-owned content. Native
copies inside editors also enter the clipboard policy. Clipboard managers, remote
desktop, other applications and screen-capture tools may retain data independently.
Timers cannot revoke a pasted secret. Use private screens and trusted clipboard
settings. Accessibility software has the privileges of the user's desktop and
must be trusted too.

## Swap, memory, keyloggers and compromised host

Core dumps are disabled and nondumpable status is requested. Mutable key buffers
are wiped and references/widgets cleared on lock. Python, GTK and cryptographic
libraries can create immutable or allocator-resident copies which cannot be
reliably scrubbed. Swap/pagefiles, hibernation images and privileged memory capture
can contain plaintext. Use encrypted swap and disk encryption. Lock before suspend
when possible; inactivity time includes suspend and is checked on resume.

ClaraKey cannot protect secrets from malware, keyloggers, a malicious input method,
a root attacker, compromised OS, hostile display server or tampered executable.
Those can capture the master password, current codes or decrypted content while
unlocked. Memory safety in orchestration code does not make these boundaries safe.
There is no hardware isolation, attestation, anti-keylogger mechanism or secure
attention path.

## Temporary files and logs

All routine vault writes, previous revisions and backups are encrypted before file
creation. No decrypted search index or browser persistence is created. GSettings
is in-memory; a built-in picker avoids persistent recent-file lists. Production
error logging excludes dynamic exception details, payloads, current codes and key
material. OS-level process inspection, crash facilities outside our control and
third-party diagnostic tools are host concerns. Test directories contain only
synthetic credentials, and test processes remove them normally.

Plaintext exports are deliberately outside vault protection. They require explicit
confirmation, use restrictive permissions and refuse existing filenames. Failed
exports may leave a partial plaintext file; the error warns about this. The
application cannot guarantee secure deletion from flash media, snapshots or backups.

## USB removal, concurrency and power failure

Encrypted replacements are flushed, read back, authenticated, schema-validated and
atomically renamed. A previous encrypted revision is retained. Directory identity
checks stop writes after the portable folder is removed/replaced; there is no
fallback to home or `/tmp`. An advisory file lock excludes another cooperating
ClaraKey process. Ciphertext comparisons detect outside edits between load and save.

Advisory locks and pathname checks cannot protect against a malicious process
racing with filesystem access. Filesystem/controller corruption, power loss and
lying write caches may lose even fsynced writes. Unsupported directory fsync is
handled explicitly. A failure after rename may mean the new version committed;
reopen and validate rather than assuming either version. Crash leftovers are
manually validated restore candidates. Test fault injection is not equivalent
to pulling a physical USB during a write.

## Backup theft and deletion

Backups have identical encryption/authentication and need the password used at
creation. Their filenames reveal creation time. Offline attack and weak-password
risks are the same as for the live vault. Backups and the previous revision can
contain secrets since deleted from the current vault. A stolen backup cannot be
revoked. Keep offline copies physically controlled; use a different physical drive
for resilience against lost/stolen/broken media.

## V1 exclusions

No network account, synchronization, telemetry or external API is required. No
FIDO2/WebAuthn hardware emulation, TPM, secure element, hardware-backed key, browser
extension or automated SSH-agent integration is implemented. These require their
own future threat models and are not implied by the product name.
