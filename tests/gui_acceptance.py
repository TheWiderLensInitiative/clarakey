#!/usr/bin/env python3
"""Real GTK widget acceptance test. Test-only credentials; no mocks of GUI APIs.
Run under xvfb-run or on a desktop. Returns 2 if no display can be opened.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['GSETTINGS_BACKEND'] = 'memory'
os.environ['GSK_RENDERER'] = 'cairo'
os.environ['GTK_A11Y'] = 'none'
os.environ['GDK_DEBUG'] = 'no-portals'
from clarakey.ui import ClaraKeyApp, Gtk, Gdk, GLib
from clarakey.totp import code_at
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP

PASSWORD = 'gui-test-only long master passphrase'
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
FILE_BYTES = b'\x00\xfe\xed\xfe\xedGUI-FILE-MARKER' + bytes(range(256)) * 16
callback_errors = []


def callback_error(kind, _value, _traceback):
    # Failing GTK callbacks must fail acceptance, even if GTK continues running.
    # No exception messages, frame locals or secret values enter diagnostics.
    callback_errors.append(kind.__name__)


sys.excepthook = callback_error


def pump(seconds=0.1):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
        time.sleep(0.01)
    assert not callback_errors, 'Unexpected GTK callback exception during acceptance'


def text_in_tree(widget):
    out=[]
    if isinstance(widget,Gtk.Label): out.append(widget.get_text())
    if isinstance(widget,(Gtk.Entry,Gtk.PasswordEntry)): out.append(widget.get_text())
    child=widget.get_first_child()
    while child:
        out.extend(text_in_tree(child)); child=child.get_next_sibling()
    return out


def add(app,kind,title,fields):
    app.navigate(kind)
    window=app.open_editor(kind)
    window.editor_title.set_text(title)
    for key,value in fields.items():
        widget=window.editor_fields[key]
        if isinstance(widget,Gtk.TextView): widget.get_buffer().set_text(str(value))
        else: widget.set_text(str(value))
    window.save_entry()
    pump()
    assert window not in app.dialogs, 'Editor did not save successfully'


def stage(root,number):
    app=ClaraKeyApp(root)
    app.register(None); app.activate(); pump()
    assert app.window.get_visible()
    if number == 'create':
        assert app.creating
        app.master.set_text(PASSWORD); app.confirm_master.set_text(PASSWORD)
        app.unlock_button.emit('clicked'); pump()
        assert app.session is not None
    else:
        assert not app.creating
        if number == 'edit':
            app.master.set_text('wrong-test-only-password'); app.unlock_button.emit('clicked'); pump()
            assert app.session is None
            assert 'Incorrect password' in app.login_message.get_text()
        app.master.set_text(PASSWORD); app.unlock_button.emit('clicked'); pump()
        assert app.session is not None
        if number == 'edit':
            add(app,'totp','RFC test authenticator',dict(service='RFC',account='unit@example.invalid',secret=SECRET,algorithm='SHA1',digits=6,period=30))
            fields=app.session.data['entries'][0]['fields']
            assert code_at(fields,59)=='287082'
            assert code_at(fields,59)==TOTP(b'12345678901234567890',6,hashes.SHA1(),30).generate(59).decode()
            add(app,'password','GUI password',dict(service='Example',username='test-user',password='GUI-test-only-secret-9172',website='example.invalid',notes=''))
            add(app,'recovery','GUI recovery',dict(codes='test-only-code-one\ntest-only-code-two'))
            add(app,'api','GUI API',dict(service='Example',key_name='unit test',api_key='GUI-test-only-api-token',notes=''))
            add(app,'note','GUI note',dict(note='GUI-test-only-private-note'))
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            key=ed25519.Ed25519PrivateKey.generate().private_bytes(Encoding.PEM,PrivateFormat.OpenSSH,NoEncryption()).decode()
            add(app,'ssh','GUI SSH',dict(host='example.invalid',username='test',private_key=key,public_key='',notes=''))
            # a binary file, like a signing keystore, added through the real editor and saved back out
            source=root/'gui-test-only-keystore.jks'
            source.write_bytes(FILE_BYTES)
            add(app,'file','',dict(path=str(source),notes='GUI-test-only file notes'))
            source.unlink()
            stored=next(e for e in app.session.data['entries'] if e['kind']=='file')
            assert stored['title']=='gui-test-only-keystore.jks' and stored['fields']['size']==len(FILE_BYTES)
            detail_file=app.open_detail(stored['id']); pump()
            assert 'GUI-test-only file notes' not in ' '.join(text_in_tree(detail_file))
            export=app.export_dialog(stored['id']); pump()
            target=root/'gui-test-only-restored.jks'
            export.export_path.set_text(str(target))
            export.export_confirm.set_active(True)
            export.export_commit(); pump()
            assert target.read_bytes()==FILE_BYTES and (target.stat().st_mode & 0o777)==0o600
            target.unlink()
            app.close_dialog(detail_file); pump()
            assert len(app.session.data['entries'])==7
            entry=next(e for e in app.session.data['entries'] if e['kind']=='password')
            detail=app.open_detail(entry['id'])
            app.copy_field(entry['id'],'password'); pump()
            assert app.clipboard_guard.owner is not None
            app.lock(); pump()
            assert app.session is None and not app.dialogs
            assert app.clipboard_guard.owner is None
            all_text=' '.join(text_in_tree(app.window))
            assert 'GUI-test-only' not in all_text
            assert 'GUI-test-only' not in ' '.join(text_in_tree(detail))
            app.master.set_text(PASSWORD); app.unlock_button.emit('clicked'); pump()
            assert len(app.session.data['entries'])==7
            backup=app.session.backup()
            restore=app.restore_dialog()
            restore.restore_path.set_text(str(backup))
            restore.restore_password_field.set_text(PASSWORD)
            restore.restore_validate()
            assert restore.restore_confirm.get_sensitive()
            restore.restore_confirm.set_active(True)
            restore.restore_commit(); pump()
            assert len(app.session.data['entries'])==7
            app.idle.last_activity=app.idle.clock()-301
            app.tick(); assert app.session is None
        else:
            assert len(app.session.data['entries'])==7
            stored=next(e for e in app.session.data['entries'] if e['kind']=='file')
            from clarakey.model import file_bytes
            assert bytes(file_bytes(stored))==FILE_BYTES
    app.close_requested(); app.window.destroy(); app.shutdown_app(); pump()


if __name__=='__main__':
    Gtk.init()
    if Gdk.Display.get_default() is None:
        print('BLOCKED: no accessible GTK display; GUI acceptance did not run.', file=sys.stderr)
        raise SystemExit(2)
    if len(sys.argv)==4 and sys.argv[1]=='--stage':
        stage(Path(sys.argv[3]),sys.argv[2]); raise SystemExit(0)
    with tempfile.TemporaryDirectory(prefix='clarakey-gui-usb-test-') as directory:
        for number in ('create','edit','reopen'):
            subprocess.run([sys.executable,'-B',__file__,'--stage',number,directory],check=True)
            if number=='edit':
                for path in Path(directory).rglob('*.vault'):
                    data=path.read_bytes()
                    for marker in (PASSWORD.encode(),SECRET.encode(),b'GUI-test-only',b'test-only-code',b'GUI-FILE-MARKER'):
                        assert marker not in data
    print('PASS: real GTK create/restart/wrong-password/TOTP/all-seven-types/file-add-and-save/lock/backup/restore/restart acceptance.')
