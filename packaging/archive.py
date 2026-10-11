"""Archive only verified build files; never package a user's vault or exports."""
import argparse
from pathlib import Path, PurePosixPath
import hashlib
import tarfile


def create_archive(bundle, archive):
    manifest = bundle/'MANIFEST.sha256'
    files = []
    for line in manifest.read_text().splitlines():
        digest, name = line.split('  ', 1)
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] in ('vault', 'backups', '.clarakey.lock'):
            raise ValueError('Unsafe file in build manifest')
        path = bundle/name
        if path.is_symlink() or not path.resolve().is_relative_to(bundle.resolve()):
            raise ValueError('Unsafe build source path')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Build checksum mismatch')
        files.append((name, path))
    with tarfile.open(archive, 'w:gz') as tar:
        for name in ('ClaraKey', 'ClaraKey/vault', 'ClaraKey/backups'):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o700 if name != 'ClaraKey' else 0o755
            tar.addfile(directory)
        for name, path in files:
            tar.add(path, arcname='ClaraKey/'+name, recursive=False)
        tar.add(manifest, arcname='ClaraKey/MANIFEST.sha256', recursive=False)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix+'.sha256').write_text(checksum+'  '+archive.name+'\n')
    return checksum


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=root/'dist/ClaraKey')
    parser.add_argument('--output', type=Path, default=root/'dist/ClaraKey-linux-x86_64.tar.gz')
    args = parser.parse_args()
    checksum = create_archive(args.bundle, args.output)
    print('Archive:', args.output)
    print('SHA-256:', checksum)
