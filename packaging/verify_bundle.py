"""Run with bundled interpreter/loader; no system site-packages fallback."""
from pathlib import Path
import sys
import tempfile

bundle=Path(sys.argv[1]).resolve()
sys.path[:0]=[str(bundle/'app'),str(bundle/'runtime/lib/python3/dist-packages')]
from clarakey.ui import ClaraKeyApp, Gtk
from clarakey.session import Session
from clarakey.storage import PortableStore
from clarakey.model import new_entry
from clarakey.errors import AuthenticationError
import cryptography
import gi
assert str(bundle) in cryptography.__file__
assert str(bundle) in gi.__file__
assert str(bundle) in sys.prefix
with tempfile.TemporaryDirectory(prefix='clarakey-bundle-test-') as folder:
    with PortableStore(folder) as store:
        s=Session.create(store,b'bundle-test-only long passphrase')
        s.put(new_entry('note','Bundle test',{'note':'bundle-only test data'}))
        s.close()
        s=Session.open(store,b'bundle-test-only long passphrase')
        assert len(s.data['entries'])==1
        backup=s.backup()
        assert backup.exists()
        s.close()
print('PASS: bundled Python, PyCA, GI/GTK imports and encrypted vault create/save/reopen/backup.')
if len(sys.argv)>2 and sys.argv[2]=='--full-suite':
    import unittest
    project=Path(__file__).resolve().parents[1]
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.discover(str(project/'tests')))
    raise SystemExit(not result.wasSuccessful())
