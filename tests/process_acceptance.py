#!/usr/bin/env python3
"""Backend acceptance across real process restarts in a relocated application copy.
Does not substitute for GUI tests or physical USB power-loss testing.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT))


def stage(root, action):
    from clarakey.session import Session
    from clarakey.storage import PortableStore, read_external
    from clarakey.errors import AuthenticationError
    from clarakey.model import new_entry
    from clarakey.totp import parse_uri, code_at
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.twofactor.totp import TOTP
    password=b'process-test-only long master passphrase'
    with PortableStore(root) as store:
        if action=='create':
            Session.create(store,password).close()
        elif action=='edit':
            try:
                Session.open(store,b'wrong-test-only-password')
                raise AssertionError('Wrong password was accepted')
            except AuthenticationError:
                pass
            session=Session.open(store,password)
            f=parse_uri('otpauth://totp/RFC:unit?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=RFC')
            assert code_at(f,59)=='287082'
            assert code_at(f,59)==TOTP(b'12345678901234567890',6,hashes.SHA1(),30).generate(59).decode()
            entries=[new_entry('totp','RFC account',f),
                new_entry('password','Process password',dict(service='Example',username='unit',password='process-secret-72374',website='',notes='')),
                new_entry('recovery','Recovery',dict(codes=[dict(value='process-recovery-code',used=False)])),
                new_entry('api','API',dict(service='Example',key_name='test',api_key='process-secret-api',notes=''))]
            for e in entries: session.put(e)
            entry=entries[-1]
            session.close()
            assert not session.active and not session.data and not session.key
            session=Session.open(store,password)
            assert len(session.data['entries'])==4
            backup=session.backup()
            session.delete(entry['id'])
            candidate=Session.validate_backup(read_external(backup),password)
            session.restore(candidate,confirmed=True)
            session.close()
        elif action=='reopen':
            session=Session.open(store,password)
            assert len(session.data['entries'])==4
            session.close()
            for path in Path(root).rglob('*.vault'):
                blob=path.read_bytes()
                for secret in [password,b'process-secret',b'process-recovery-code',b'GEZDGNBVGY3TQOJQ']:
                    assert secret not in blob


if __name__=='__main__':
    if len(sys.argv)==4:
        stage(Path(sys.argv[3]),sys.argv[2])
    else:
        with tempfile.TemporaryDirectory(prefix='clarakey-relocation-test-') as folder:
            root=Path(folder)/'Removable Drive'/ 'ClaraKey'; root.mkdir(parents=True)
            shutil.copytree(PROJECT/'clarakey',root/'clarakey',ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copy2(__file__,root/'acceptance.py')
            for action in ('create','edit','reopen'):
                subprocess.run([sys.executable,'-B',str(root/'acceptance.py'),'--stage',action,str(root)],cwd='/',check=True,
                               env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        print('PASS: relocated backend, three processes, create/reopen/wrong-password/RFC TOTP/credentials/lock/backup/restore/encrypted-at-rest.')
