"""Directory-anchored Linux I/O. Every temporary vault file is encrypted."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time
from .crypto import MAX_FILE, parse_header
from .errors import StorageError

NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
CLOEXEC = getattr(os, 'O_CLOEXEC', 0)


def _regular(fd, limit):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit or st.st_nlink != 1:
        raise StorageError('File must be a bounded regular file without hard links.')
    return st


def read_external(path, limit=MAX_FILE):
    try:
        fd = os.open(path, os.O_RDONLY | NOFOLLOW | CLOEXEC | os.O_NONBLOCK)
        try:
            _regular(fd, limit)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                result = stream.read(limit + 1)
            if len(result) > limit:
                raise StorageError('File exceeds the size limit.')
            return result
        finally:
            os.close(fd)
    except OSError:
        raise StorageError('Cannot read this local file. Check its location and permissions.') from None


def _restrict(fd, mode):
    try:
        os.fchmod(fd, mode)
    except OSError as exc:
        # FAT/exFAT may not implement chmod. Encryption remains the primary boundary.
        if exc.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS):
            raise


def _sync_dir(fd):
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EOPNOTSUPP):
            raise


def export_plaintext(path, data, *, confirmed=False):
    if not confirmed:
        raise StorageError('Plaintext export requires explicit confirmation.')
    # O_EXCL never clobbers a key, vault, symlink, or pre-existing export.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC, 0o600)
        try:
            _restrict(fd, 0o600)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise StorageError('Export failed. Use a new filename on a writable drive. A partial plaintext file may remain.') from None


class PortableStore:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.root_fd = self.vault_fd = self.backup_fd = self.lock_fd = None
        self.expected = None
        self.loaded = False
        try:
            self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW | CLOEXEC)
            self.root_identity = self._identity(self.root_fd)
            self.lock_fd = os.open('.clarakey.lock', os.O_RDWR | os.O_CREAT | NOFOLLOW | CLOEXEC,
                                   0o600, dir_fd=self.root_fd)
            _regular(self.lock_fd, 1024)
            _restrict(self.lock_fd, 0o600)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Both documented USB layouts are supported. Never migrate silently.
            try:
                os.stat('clarakey.vault', dir_fd=self.root_fd, follow_symlinks=False)
                self.flat = True
            except FileNotFoundError:
                self.flat = False
            self.vault_fd = os.dup(self.root_fd) if self.flat else self._directory('vault')
            self.backup_fd = self._directory('backups')
            self.vault_identity = self._identity(self.vault_fd)
            self.backup_identity = self._identity(self.backup_fd)
        except (OSError, StorageError):
            self.close()
            raise StorageError('Portable folder unavailable, read-only, unsafe, or already open in another ClaraKey instance.') from None

    @staticmethod
    def _identity(fd):
        st = os.fstat(fd)
        return st.st_dev, st.st_ino

    def _directory(self, name):
        try:
            os.mkdir(name, 0o700, dir_fd=self.root_fd)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW | CLOEXEC, dir_fd=self.root_fd)
        _restrict(fd, 0o700)
        return fd

    @property
    def vault_path(self):
        return self.root / ('clarakey.vault' if self.flat else 'vault/clarakey.vault')

    def check_available(self):
        try:
            st = os.stat(self.root, follow_symlinks=False)
            if (st.st_dev, st.st_ino) != self.root_identity or not stat.S_ISDIR(st.st_mode):
                raise OSError()
            for name, identity in ([('backups', self.backup_identity)] +
                                   ([] if self.flat else [('vault', self.vault_identity)])):
                st = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
                if (st.st_dev, st.st_ino) != identity or not stat.S_ISDIR(st.st_mode):
                    raise OSError()
            lock_st = os.stat('.clarakey.lock', dir_fd=self.root_fd, follow_symlinks=False)
            if (lock_st.st_dev, lock_st.st_ino) != self._identity(self.lock_fd):
                raise OSError()
        except (OSError, TypeError):
            raise StorageError('Portable storage changed or was removed. Reconnect it and reopen ClaraKey.') from None

    def _read(self, name, fd):
        handle = os.open(name, os.O_RDONLY | NOFOLLOW | CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        try:
            _regular(handle, MAX_FILE)
            with os.fdopen(handle, 'rb', closefd=False) as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise StorageError('Vault exceeds the size limit.')
            return data
        finally:
            os.close(handle)

    def exists(self):
        self.check_available()
        try:
            os.stat('clarakey.vault', dir_fd=self.vault_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            raise StorageError('Cannot inspect the vault.') from None

    def read(self):
        self.check_available()
        try:
            data = self._read('clarakey.vault', self.vault_fd)
            self.expected = hashlib.sha256(data).digest()
            self.loaded = True
            return data
        except OSError:
            raise StorageError('Cannot read the vault. Reconnect storage or restore an encrypted backup.') from None

    def _write_new(self, name, blob, fd):
        handle = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC, 0o600, dir_fd=fd)
        try:
            _restrict(handle, 0o600)
            with os.fdopen(handle, 'wb', closefd=False) as stream:
                stream.write(blob)
                stream.flush()
                os.fsync(handle)
            os.lseek(handle, 0, os.SEEK_SET)
            with os.fdopen(handle, 'rb', closefd=False) as stream:
                check = stream.read(MAX_FILE + 1)
            if check != blob:
                raise StorageError('Encrypted write verification failed.')
        finally:
            os.close(handle)

    def _current(self):
        try:
            return self._read('clarakey.vault', self.vault_fd)
        except FileNotFoundError:
            return None

    def save(self, blob, verify, *, create=False):
        parse_header(blob)
        verify(blob)
        self.check_available()
        pending = '.pending-' + secrets.token_hex(12) + '.vault'
        previous = '.previous-' + secrets.token_hex(12) + '.vault'
        try:
            current = self._current()
            if create:
                if current is not None:
                    raise StorageError('A vault already exists. Unlock or restore it instead.')
            elif not self.loaded or current is None or hashlib.sha256(current).digest() != self.expected:
                raise StorageError('The vault changed outside ClaraKey. Lock and reopen before saving.')
            self._write_new(pending, blob, self.vault_fd)
            verify(self._read(pending, self.vault_fd))
            if current is not None:
                self._write_new(previous, current, self.vault_fd)
                os.replace(previous, '.previous.vault', src_dir_fd=self.vault_fd, dst_dir_fd=self.vault_fd)
                _sync_dir(self.vault_fd)
            self.check_available()
            # Recheck just before commit; advisory locking excludes cooperating writers.
            if self._current() != current:
                raise StorageError('Vault changed during save. Reopen before saving.')
            if create:
                # Atomic no-clobber commit; hard links unavailable on some USB filesystems.
                # Store process lock + recheck guard the portable create transaction.
                if self.exists():
                    raise StorageError('A vault already exists.')
            os.replace(pending, 'clarakey.vault', src_dir_fd=self.vault_fd, dst_dir_fd=self.vault_fd)
            _sync_dir(self.vault_fd)
            self.expected = hashlib.sha256(blob).digest()
            self.loaded = True
        except OSError:
            raise StorageError('Save could not be confirmed. Reconnect storage and reopen; encrypted recovery files may be available.') from None
        finally:
            for name in (pending, previous):
                try:
                    os.unlink(name, dir_fd=self.vault_fd)
                except OSError:
                    pass

    def backup(self, blob):
        parse_header(blob)
        self.check_available()
        name = time.strftime('clarakey-backup-%Y-%m-%d-%H%M%S', time.gmtime()) + '-' + secrets.token_hex(4) + '.vault'
        try:
            self._write_new(name, blob, self.backup_fd)
            _sync_dir(self.backup_fd)
            return self.root / 'backups' / name
        except OSError:
            raise StorageError('Encrypted backup could not be written or verified.') from None

    def recovery_files(self):
        self.check_available()
        try:
            names = [n for n in os.listdir(self.vault_fd) if n == '.previous.vault' or
                     (n.startswith('.pending-') and n.endswith('.vault'))]
            return [self.vault_path.parent / n for n in sorted(names)]
        except OSError:
            raise StorageError('Cannot list encrypted recovery files.') from None

    def close(self):
        for name in ('backup_fd', 'vault_fd', 'lock_fd', 'root_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
