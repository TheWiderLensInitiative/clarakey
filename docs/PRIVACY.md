# ClaraKey privacy

ClaraKey has no servers, no accounts, no telemetry and no analytics. It never connects to the internet. This page
lists every place your data goes.

## On your drive

Everything ClaraKey stores lives in the `ClaraKey` folder you run it from (usually on your USB drive):

- `vault/clarakey.vault`: your vault, encrypted with a key derived from your master password (Argon2id, then
  AES-256-GCM). Entries, titles, notes, files, timestamps and settings are all inside the encryption.
- `vault/.previous.vault`: the encrypted previous version, so a failed save can't lose your vault.
- `backups/`: encrypted backups you create.

Without your master password none of this can be read, including by us. There is no password recovery and no
backdoor: if you lose the master password, the vault can't be opened.

## On the computer you use it on

- ClaraKey keeps decrypted entries in memory only while the vault is unlocked, and locks itself after a period of
  inactivity (5 minutes by default).
- When you copy a secret, it goes to the system clipboard and ClaraKey clears it again after a timeout (30 seconds
  by default), if nothing else was copied since. Clipboard managers and the apps you paste into may keep their own
  copies; ClaraKey can't remove those.
- Exports and "Save file…" write exactly what you chose, unencrypted, to the place you chose, after a confirmation.
- The optional one-click icon (`add-to-this-pc.sh`) puts a small launcher, a desktop entry and an icon on the
  computer. Never the vault.

## Network

None. ClaraKey makes no network requests: no updates check, no time server, no crash reports. Authenticator codes
use your computer's clock.

## Contact

Questions: clarakey@thewiderlens.info · Security issues: see [SECURITY.md](../SECURITY.md)
