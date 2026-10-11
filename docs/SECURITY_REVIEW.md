# Implementation security review

Review date: 2026-10-03. Scope: application source, portable storage, credential
workflows, tests, launchers and bundler. This was an implementation review in the
same development session, not an independent audit or penetration test. No real
credentials were used. GUI dynamic validation is blocked by the sandbox's display
socket restrictions and remains an explicit release gate.

## Findings fixed during implementation

* **Unbounded JSON nesting:** Python 3.14 accepted deep arrays despite the assumed
  parser recursion bound. Added a string/escape-aware preparse depth limit of 16;
  malformed/duplicate/NaN/UTF-8 cases have regression tests.
* **Decrypted state borrowed by UI:** clearing only the top-level session dictionary
  could leave nested entry dictionaries reachable. Lock now recursively invalidates
  owned collections, wipes the mutable key, clears widgets, closes dialogs and
  drops session access before clearing widgets that can emit signals. Editor undo
  buffers are disabled. Immutable memory copies remain a documented limitation.
* **Staged restore secrets:** validating a backup on the locked screen retains
  temporary decrypted state. Those candidates now have a five-minute inactivity
  deadline and are discarded/wiped on invalidation, close or lock. Restoration
  always requires successful authentication plus an enabled confirmation checkbox.
* **Native editor clipboard copies:** native Ctrl+C/Ctrl+X could bypass explicit
  copy buttons. The GTK clipboard ownership-change signal now enrolls all copies
  originating in this process in the same timer policy. Tests cover newer copies,
  including identical text, without relying on a hash of a secret.
* **Locked restore error handling:** a generic backup exception handler could swallow
  an actual backup I/O failure. Moved locked restore into the tested session layer:
  authentication and confirmation precede writes, malformed prior content is
  retained as a previous revision, and backup I/O failures stop replacement.
  Regression tests cover empty/current/corrupt vaults, wrong passwords and failures.
* **Incomplete portable runtime:** the first runtime smoke test found the native
  `_cffi_backend` dependency missing even though `--version` succeeded. Bundling
  now includes it and typing extensions; build verification imports the actual
  UI/crypto stack and creates, saves, closes, reopens and backs up a test vault.
* **Blind graphical startup:** absence of an accessible display originally caused
  an application callback exception. Startup now reports the missing display and
  exits without opening a vault. The acceptance runner returns a blocked status,
  rather than reporting skipped graphical tests as passed.

## Review checklist and evidence

Hardcoded secret review found only explicit test fixtures and dependency-check
inputs. Production password generation, salts and nonces use OS-backed `secrets`;
there is no `random` PRNG. Each save/backup generates a fresh GCM nonce; tests verify
freshness across saves and authentication failure after header/ciphertext/tag edits.
V1 KDF inputs are fixed and rejected before derivation when altered. AES-GCM and
Argon2id are library calls, not application implementations.

All normal temporary write paths receive ciphertext. User-controlled service/title
fields never form paths. Directory-relative operations use `O_NOFOLLOW`, exclusive
creation, bounds and regular-file/link checks. Sensitive files/directories request
0600/0700, with explicit unsupported-filesystem behavior. Saves validate before
commit, retain encrypted recovery state, and detect outside edits. Tests inject
write/sync/rename failures, directory replacement, symbolic links, hardlinks and
concurrent instances. A malicious filesystem writer remains outside advisory-lock
protection.

Serialization is bounded UTF-8 JSON with exact schemas, no pickle/eval/exec/YAML
objects. There are no dynamic shell calls in normal application code. Packaging
uses argument arrays only with trusted installed binaries; user secrets never
enter its inputs. The application has no HTTP/socket/network client, webview,
browser/localStorage, keyring, logging framework or telemetry path. Native GTK and
OS dependencies still require host trust.

Backup creation encrypts authenticated in-memory state, not potentially replaced
on-disk bytes. Restore authenticates and schema-validates first, confirms explicitly,
keeps an encrypted pre-restore copy, and reencrypts under the current password when
unlocked. Tests cover wrong backup passwords, damaged backups, confirmation,
foreign-password backups and restoration without mutation on validation failure.
Plaintext export refuses pre-existing destinations and requires confirmation.

Inactivity uses Linux BOOTTIME so suspend does not reset the elapsed duration.
Clipboard policy checks ownership tokens and preserves newer copies. Key memory
is best-effort erased; no `mlock`/all-memory zeroization is claimed. No real secrets
appear in test fixtures. Production unhandled exceptions print a fixed diagnostic
without exception contents or stack traces.

## Remaining release gates and limits

Run real GTK acceptance (`./test.sh`) and manual desktop usability/clipboard tests
on a host that permits display sockets. Validate both Wayland and X11 behavior,
physical USB removal and recovery on ext4/FAT/exFAT, and multiple Linux versions.
No code audit can substitute for these missing dynamic tests. Obtain an independent
security review before recommending the app for important live credentials.

The build includes ABI-specific system libraries, so it requires ongoing dependency
updates. No online CVE/dependency scanner could be run against an installed Rust
crate tree because no Rust project is used and package downloads are blocked;
bundled dependency versions are recorded. Public redistribution also requires
third-party license/source compliance and a real vulnerability reporting channel.
AppImage generation and validation remain pending official packaging tooling.
