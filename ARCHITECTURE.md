# ClaraKey architecture

## Decision

V1 is a native GTK 4 desktop application in memory-safe Python. Security-sensitive
primitives come from PyCA `cryptography` 46.0.5 (its compiled Rust bindings and
OpenSSL backend), not application cryptographic implementations. There is no
browser, local HTTP server, account, network client, telemetry or persistence API.

Three candidates were considered before implementation:

* Rust + Tauri: strong backend, but adds a WebKit/browser surface and Linux
  WebKit development/packaging dependencies.
* Rust + egui: preferred eventual implementation for predictable secret ownership
  and compact distribution, but this environment has neither Rust nor cached crates,
  and DNS/network access for dependency installation is unavailable.
* Python + GTK 4 + PyCA: installed, mature native UI and established cryptography;
  permits building and testing the actual product offline. Selected for V1.

The tradeoff is explicit: Python and GTK make copies of strings that cannot be
reliably overwritten. ClaraKey clears widgets/references and wipes mutable key
buffers on lock; it cannot promise total RAM erasure. Process core dumps are
disabled. Use a trusted host with encrypted swap. A future Rust port can retain the
documented vault format without changing the user workflow.

## Boundaries

`crypto.py` defines the versioned encrypted envelope, validates bounded headers,
derives keys with Argon2id and authenticates the entire header with AES-256-GCM.
`storage.py` owns directory-relative, symlink-resistant I/O, locking, atomic
replacement, encrypted recovery snapshots and explicit exports. `model.py`
validates decrypted JSON, credential schemas and metadata-only search.
`totp.py` implements RFC 6238 using standard-library HMAC and strict URI parsing.
`session.py` coordinates transactions; memory changes commit only after a verified
encrypted save. `policy.py` implements monotonic inactivity/backoff and clipboard
ownership policy. `ui.py` is a native GTK interface with no persistent UI state.

The source launcher and packaged launcher resolve their own directory, never the
working directory or a user configuration directory. The default vault is
`vault/clarakey.vault`; a pre-existing `clarakey.vault` beside the launcher is also
supported. A process lock prevents two instances writing the same vault. The
runtime opens storage directories once and checks their device/inode identities
before operations to avoid falling back to a host directory after USB removal.

Normal operation does not require Internet access. Build scripts use installed
system packages and produce a self-contained application directory with its
Python runtime, GTK shared libraries and typelibs. Linux ABI requirements are
documented separately; a bundle is not evidence of compatibility with every
distribution. AppImage assembly is optional when an official runtime is available.

## References

* [PyCA Argon2id API](https://cryptography.io/en/46.0.5/hazmat/primitives/key-derivation-functions/)
* [PyCA AESGCM API](https://cryptography.io/en/46.0.5/hazmat/primitives/aead/)
* [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), section 4, second recommended profile
* [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)
* [GTK clipboard ownership](https://docs.gtk.org/gdk4/class.Clipboard.html)
