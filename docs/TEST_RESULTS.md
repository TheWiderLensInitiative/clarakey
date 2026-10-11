# ClaraKey verification results — 2026-10-03

**1.1.0, 2026-10-10 (file entries):** `./test.sh` on Ubuntu 26.04.1 (Python 3.14.4, GTK 4.22.4, Xvfb):

* **PASS: 65 automated tests**, including 12 for files: exact binary round trip after reopen;
  file bytes, name and notes absent from every file on disk; schema 2 only while files exist;
  file in a schema-1 payload and unknown schemas rejected; confirmed, private (0600),
  no-overwrite saving out; 1 MiB per-file and 5 MiB total caps (a refused save changes
  nothing); unsafe filenames; eight kinds of damaged file data; backup/restore; search by
  name but never contents; bounded, symlink-refusing import.
* **PASS: process acceptance** and **real GTK acceptance**, now seven entry types including a
  file added through the editor and saved back out byte-identical with mode 0600.
* **PASS: compatibility with the released 1.0.1 code:** a 1.1.0 vault without files opens in
  1.0.1; a vault with files is refused ("Unsupported vault payload schema") and left
  byte-identical on disk.
* **PASS: portable bundle:** `./build.sh` self-check plus a file round trip inside the bundled
  runtime; the archive contains no vault files.

**Update 2026-10-10:** the real GTK acceptance run now passes. `./test.sh` on Ubuntu 26.04.1
(Python 3.14.4, GTK 4.22.4, Xvfb with `GDK_BACKEND=x11 GSK_RENDERER=cairo`) ran:

* **PASS: 53 automated unit/security/desktop/packaging tests** (about 4.8 seconds).
* **PASS: process acceptance:** relocated backend, three processes,
  create/reopen/wrong-password/RFC TOTP/credentials/lock/backup/restore/encrypted-at-rest.
* **PASS: real GTK acceptance:** create/restart/wrong-password/TOTP/all-six-types/lock/
  backup/restore/restart, with real widgets and no mocked GUI API.

The "BLOCKED: real GTK acceptance" entry below is kept as the 2026-10-03 record. Still not covered:
physical USB behavior on other machines, other distributions, and the AppImage build.

**1.0.1 follow-up:** see [the desktop input fix](DESKTOP_FIX_1.0.1.md). The suite
now includes the original 43 tests, seven GTK input/diagnostic regressions and
three archive-safety regressions. Historical V1 results below remain relevant;
full display-driven acceptance still needs a normal desktop run.

**Status: V1 implementation and portable directory build delivered; complete V1
acceptance is not yet achieved.** The GUI acceptance run and AppImage build are
blocked by environment/tooling limits. They are not counted as passes.

Environment: Ubuntu 26.04.1 x86_64, Python 3.14.4, GTK 4.22.4,
PyCA cryptography 46.0.5, OpenSSL 3.5.5. No real credentials were used.

## Executed checks

* **PASS — 43 automated unit/security tests**, about 4.6 seconds on this host.
  Vault create/unlock/wrong-password, all credential schemas/edit/delete,
  authenticated encryption/tampering, malformed/unsupported envelopes and JSON,
  KDF bounds, random salt/nonce, all 18 RFC 6238 vectors plus independent PyCA TOTP,
  URI import, password generation, metadata-only search, clipboard/idle/backoff
  policies, encrypted backups, locked/unlocked restore, confirmation, permissions,
  no-clobber export, symlink/hardlink rejection, concurrent-instance exclusion,
  external changes, simulated removal, sync/rename/readback failures and lock cleanup.
* **PASS — process restart acceptance.** Three separate Python processes operate
  a relocated application copy under a temporary directory with spaces, from a
  different working directory. Create, close, wrong/correct password, TOTP,
  passwords, recovery codes, API credentials, lock/unlock, backup/restore and
  persistence all succeed. These directories and credentials are synthetic.
* **PASS — encrypted-at-rest checks.** Test master passwords, TOTP Base32 seeds,
  usernames and secret markers do not appear as readable bytes in generated
  vaults/recovery snapshots/backups. This is corroboration of tested encryption,
  not a statistical proof or a substitute for primitive review.
* **PASS — offline portable directory build and bundled runtime smoke test.**
  The bundled interpreter imports its own PyCA/GTK dependencies and performs
  encrypted create/save/close/reopen/backup. The first build test caught a missing
  CFFI module; that dependency was fixed. `--version` alone is no longer the build
  verification criterion. The directory is approximately 117 MiB; tar.gz about
  43 MiB. Exact file hashes are in the generated manifest/checksum.
* **PASS — all 43 unit/security tests under the bundled runtime**, approximately
  4.8 seconds. Imports resolve to the bundled application/Python/PyCA packages,
  not the system site-packages.
* **PASS — complete bundle relocation:** the whole release was copied into a
  temporary `USB Drive/ClaraKey` path and launched with working directory `/`.
  The relocated runtime smoke test and all 43 unit tests passed. This tests path
  portability, not physical USB behavior.
* **PASS — static source parsing and dedicated implementation review.**
  Findings, fixes and residual risks are recorded in SECURITY_REVIEW.md.
* **BLOCKED — real GTK acceptance.** Xvfb cannot create its local display sockets
  under this tool sandbox; GTK has no accessible display. The test reports
  `BLOCKED: no accessible GTK display; GUI acceptance did not run.` The application
  reports a missing desktop display and exits without opening a vault. No claim
  is made about successful rendering, mouse/keyboard behavior or actual desktop
  clipboard interoperability. `tests/gui_acceptance.py` exercises real widgets
  and is provided to run on a normal host, with no mocked GUI API.
* **BLOCKED — AppImage.** No official `appimagetool`/runtime is installed and shell
  network/DNS access is unavailable. `./build.sh --appimage` built the portable
  directory, then returned exit 2 with the missing-packager explanation. No file
  is mislabeled as an AppImage.

The complete `./test.sh` command returns nonzero because the graphical gate is
blocked, even though all 43 unit tests and process acceptance pass. The sanitized
full test output is in `test-output.txt`. No unit/security test remains failing.

## Requested 20-step acceptance sequence

1. Launch from removable directory: relocated backend launch passed; actual GUI
   launch and physical removable-media launch are unverified.
2. Create new vault: backend passed; first-run GUI workflow blocked.
3. Close: real test process exited normally; desktop close behavior unverified.
4. Inspect encrypted files: no readable test credentials found; passed.
5. Reopen: separate-process backend passed; GUI blocked.
6. Incorrect master password: authentication rejection passed.
7. Correct master password: authenticated unlock passed.
8. Add test TOTP: manual/schema and URI paths passed; GUI path blocked.
9. Independently verify TOTP: all 18 RFC vectors and PyCA comparison passed.
10. Add password: encrypted backend transaction passed; GUI path blocked.
11. Add recovery codes: encrypted backend transaction/edit/used markers passed;
    GUI path blocked.
12. Add API credential: encrypted backend transaction passed; GUI path blocked.
13. Lock: backend active-state denial, collection invalidation and mutable-key
    clearing passed; GUI lock workflow blocked.
14. Decrypted information inaccessible through UI: **not verified**. The GUI test
    asserts this after clearing/destroying secret dialogs when it can run.
15. Unlock again: backend passed; GUI blocked.
16. Information survives restart: separate-process reopen passed.
17. Encrypted backup: creation and readable-secret absence checks passed.
18. Restore backup: validated, confirmed, same/foreign-password, locked/unlocked,
    corrupt-current-file recovery and failure/no-mutation cases passed.
19. Complete automated suite: 43 unit tests plus process acceptance passed;
    graphical acceptance blocked, so the overall gate is incomplete.
20. Portable Linux build: directory/archive plus bundled runtime smoke passed;
    AppImage tooling missing. Cross-distribution compatibility unverified.

## What remains

Run `./test.sh` on a Linux desktop that permits display sockets, then manually
verify the UI on Wayland and X11. Test a real USB with safe eject and interrupted
writes on ext4/FAT/exFAT. Validate the bundle on additional distributions. Install
the official AppImage tooling and validate its output. Arrange an independent
security review and a monitored private security-reporting channel before public
release or recommending storage of important live credentials.
