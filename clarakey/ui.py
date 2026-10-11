"""Native GTK UI. No webview, settings persistence, recent-file store or network."""
from copy import deepcopy
from datetime import datetime, timezone
import gc
import os
from pathlib import Path
import time
import gi
from cryptography.exceptions import UnsupportedAlgorithm

gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
from gi.repository import Gtk, Gdk, Gio, GLib

from . import __version__
from .activity import attach_activity_controllers
from .crypto import wipe, discard
from .errors import ClaraKeyError, ValidationError, StorageError
from .model import (KINDS, NAMES, AUTO_LOCK, CLIPBOARD, MAX_FILE_BYTES, generate_password, new_entry,
                    password_strength, search_entries, file_fields)
from .policy import IdleLock, UnlockThrottle, ClipboardGuard
from .session import Session
from .storage import PortableStore, read_external
from .totp import code_at, remaining, normalize_secret, parse_uri


ASSETS = Path(__file__).with_name('assets')
APP_ICON = 'org.clarakey.ClaraKey'


def picture(name, size):
    """A bundled brand image at a fixed size; missing artwork never stops the vault from opening."""
    widget = Gtk.Image.new_from_file(str(ASSETS / name))
    widget.set_pixel_size(size)
    widget.set_halign(Gtk.Align.CENTER)
    return widget


def box(vertical=True, spacing=12, css=None):
    widget = Gtk.Box(orientation=Gtk.Orientation.VERTICAL if vertical else Gtk.Orientation.HORIZONTAL, spacing=spacing)
    if css:
        widget.add_css_class(css)
    return widget


def label(text='', css=None, wrap=False):
    widget = Gtk.Label(label=text, xalign=0)
    widget.set_wrap(wrap)
    if css:
        widget.add_css_class(css)
    return widget


def button(text, callback, css=None):
    widget = Gtk.Button(label=text)
    if css:
        widget.add_css_class(css)
    widget.connect('clicked', lambda _b: callback())
    return widget


def human_size(n):
    return f'{n} bytes' if n < 1024 else (f'{n / 1024:.1f} KB' if n < 1024 * 1024 else f'{n / 1048576:.2f} MB')


def margins(widget, value=24):
    for side in ('top', 'bottom', 'start', 'end'):
        getattr(widget, 'set_margin_'+side)(value)
    return widget


def empty(widget):
    child = widget.get_first_child()
    while child:
        following = child.get_next_sibling()
        widget.remove(child)
        child = following


def scrub_widgets(widget):
    # Clear even widgets retained by GTK until the next main-loop iteration.
    if isinstance(widget, (Gtk.Entry, Gtk.PasswordEntry, Gtk.SearchEntry)):
        widget.set_text('')
    elif isinstance(widget, Gtk.TextView):
        widget.get_buffer().set_text('')
    elif isinstance(widget, Gtk.Label):
        widget.set_text('')
    child = widget.get_first_child()
    while child:
        scrub_widgets(child)
        child = child.get_next_sibling()


class GtkClipboard:
    def __init__(self, clipboard):
        self.clipboard = clipboard

    def set(self, text):
        provider = Gdk.ContentProvider.new_for_value(text)
        if not self.clipboard.set_content(provider):
            raise StorageError('The desktop clipboard could not accept this value.')
        return provider

    def owns(self, provider):
        return self.clipboard.is_local() and self.clipboard.get_content() == provider

    def clear(self):
        self.clipboard.set_content(None)


class ClaraKeyApp(Gtk.Application):
    def __init__(self, root):
        super().__init__(application_id='org.clarakey.ClaraKey', flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.root = Path(root)
        self.window = None
        self.store = None
        self.session = None
        self.dialogs = []
        self.idle = IdleLock()
        self.throttle = UnlockThrottle()
        self.clipboard_guard = None
        self.category = 'totp'
        self.query = ''
        self.cards = []
        self.timer = None
        self.connect('activate', self.activate_app)
        self.connect('shutdown', self.shutdown_app)

    def activate_app(self, *_):
        if self.window:
            self.window.present()
            return
        Gtk.Settings.get_default().set_property('gtk-application-prefer-dark-theme', True)
        css = Gtk.CssProvider()
        css.load_from_path(str(Path(__file__).with_name('theme.css')))
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        # The app icon ships with the code, so the window shows the ClaraKey logo even from a USB drive.
        Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(ASSETS))
        Gtk.Window.set_default_icon_name(APP_ICON)
        self.window = Gtk.ApplicationWindow(application=self, title='ClaraKey • Portable Authentication Vault')
        self.window.set_default_size(1100, 760)
        self.window.set_size_request(860, 600)
        self.window.connect('close-request', self.close_requested)
        self.watch_activity(self.window)
        self.clipboard_guard = ClipboardGuard(GtkClipboard(self.window.get_clipboard()))
        self.window.get_clipboard().connect('changed', self.clipboard_changed)
        try:
            self.store = PortableStore(self.root)
            self.show_login()
        except ClaraKeyError as exc:
            content = margins(box())
            content.append(label('ClaraKey cannot open this portable folder', 'heading'))
            content.append(label(str(exc), 'warning', True))
            content.append(button('Close', self.window.close))
            self.window.set_child(content)
        self.timer = GLib.timeout_add(250, self.tick)
        self.window.present()

    def watch_activity(self, window):
        # Resolve the current IdleLock on every event; lock() replaces the policy.
        return attach_activity_controllers(window, lambda: self.idle.touch())

    def clipboard_changed(self, clipboard):
        # Also track native Ctrl+C / Ctrl+X in editors, using ownership rather than secret hashes.
        if self.clipboard_guard:
            provider = clipboard.get_content()
            if clipboard.is_local() and provider is not None:
                self.clipboard_guard.owner = provider
                timeout = self.session.data['settings']['clipboard'] if self.session else 30
                self.clipboard_guard.deadline = self.clipboard_guard.clock() + timeout if timeout else None
            else:
                self.clipboard_guard.owner = self.clipboard_guard.deadline = None

    def tick(self):
        if self.clipboard_guard:
            self.clipboard_guard.tick()
        transient_input = self.dialogs or (hasattr(self, 'master') and self.master.get_text()) or (getattr(self, 'confirm_master', None) and self.confirm_master.get_text())
        if not self.session and transient_input and self.idle.due():
            self.lock('Sensitive input discarded after inactivity. Enter the password again.')
            return True
        if self.session:
            if self.idle.due():
                self.lock('Locked after inactivity.')
                return True
            try:
                self.store.check_available()
            except ClaraKeyError:
                self.lock('Portable storage changed or was removed. Close ClaraKey and reconnect the drive.')
                return True
            for entry_id, code_widget, progress, countdown in self.cards:
                try:
                    f = self.session.entry(entry_id)['fields']
                    code = code_at(f)
                    code_widget.set_text(code[:len(code)//2]+' '+code[len(code)//2:])
                    left = remaining(f)
                    progress.set_fraction(left / f['period'])
                    countdown.set_text(f'{left}s remaining')
                except ClaraKeyError:
                    code_widget.set_text('Unavailable')
        elif hasattr(self, 'unlock_button'):
            seconds = self.throttle.remaining()
            self.unlock_button.set_sensitive(seconds <= 0)
            if seconds > 0:
                self.login_message.set_text(f'Please wait {int(seconds)+1} seconds before trying again.')
        return True

    def status(self, message):
        if self.session and hasattr(self, 'status_label'):
            self.status_label.set_text(message)
        elif hasattr(self, 'login_message'):
            self.login_message.set_text(message)

    def safe(self, action, message=None):
        try:
            result = action()
            if message:
                self.status(message)
            return result
        except ClaraKeyError as exc:
            self.status(str(exc))
        except Exception:
            # Never print exception objects/tracebacks: libraries can embed input in them.
            self.status('The operation failed. Your last confirmed save is still on the drive; reopen before retrying.')
        return None

    def show_login(self, message=''):
        self.cards = []
        self.query = ''
        self.category = 'totp'
        try:
            self.creating = not self.store.exists()
        except ClaraKeyError:
            self.creating = False
        outer = box(spacing=20)
        outer.set_valign(Gtk.Align.CENTER)
        outer.set_halign(Gtk.Align.CENTER)
        outer.set_size_request(500, -1)
        outer.append(picture('logo.png', 240))
        card = box(spacing=18, css='login-card')
        card.set_size_request(480, -1)
        card.append(label('Create your vault' if self.creating else 'Unlock your vault', 'heading'))
        card.append(label('Everything stays encrypted on this drive.', 'muted'))
        card.append(label('Master Password', 'muted'))
        self.master = Gtk.PasswordEntry(show_peek_icon=True)
        self.master.set_property('enable-undo', False)
        self.master.set_hexpand(True)
        self.master.set_property('placeholder-text', 'Enter a unique master passphrase')
        self.master.connect('activate', lambda _: self.attempt_unlock())
        card.append(self.master)
        self.confirm_master = None
        if self.creating:
            self.strength = Gtk.ProgressBar()
            self.strength_label = label('Use a unique passphrase of at least 12 characters', 'muted', True)
            self.master.connect('changed', self.update_strength)
            card.append(self.strength)
            card.append(self.strength_label)
            card.append(label('Confirm Master Password', 'muted'))
            self.confirm_master = Gtk.PasswordEntry(show_peek_icon=True)
            self.confirm_master.set_property('enable-undo', False)
            self.confirm_master.connect('activate', lambda _: self.attempt_unlock())
            card.append(self.confirm_master)
            card.append(label('If you lose this password, ClaraKey cannot recover your vault.', 'warning', True))
        self.login_message = label(message, 'warning', True)
        self.login_message.set_max_width_chars(48)
        card.append(self.login_message)
        self.unlock_button = button('Create New Vault' if self.creating else 'Unlock Vault', self.attempt_unlock, 'primary')
        card.append(self.unlock_button)
        card.append(button('Restore or recover an encrypted vault', self.restore_dialog, 'flat'))
        outer.append(card)
        outer.append(label('OFFLINE  /  ENCRYPTED  /  ACCOUNT-FREE', 'eyebrow'))
        self.window.set_child(margins(outer))
        self.master.grab_focus()

    def update_strength(self, *_):
        amount, description = password_strength(self.master.get_text())
        self.strength.set_fraction(amount)
        self.strength_label.set_text(description)

    def attempt_unlock(self):
        if self.session or self.throttle.remaining() > 0:
            return
        password = bytearray(self.master.get_text().encode('utf-8'))
        try:
            if self.creating:
                if len(self.master.get_text()) < 12:
                    raise ValidationError('Use at least 12 characters; several random words are better.')
                if self.master.get_text() != self.confirm_master.get_text():
                    raise ValidationError('The master passwords do not match.')
                session = Session.create(self.store, password)
            else:
                session = Session.open(self.store, password)
            self.throttle.success()
            self.master.set_text('')
            if self.confirm_master:
                self.confirm_master.set_text('')
            self.session = session
            self.idle.timeout = session.data['settings']['auto_lock']
            self.idle.touch()
            self.show_dashboard()
        except ClaraKeyError as exc:
            self.throttle.failed()
            self.master.set_text('')
            if self.confirm_master:
                self.confirm_master.set_text('')
            self.login_message.set_text(str(exc))
        finally:
            wipe(password)

    def show_dashboard(self):
        main = box(spacing=0)
        row = box(False, 0)
        row.set_vexpand(True)
        sidebar = box(spacing=8, css='sidebar')
        sidebar.set_size_request(220, -1)
        brand = box(False, 10)
        brand.append(picture('icon.png', 40))
        brand.append(label('CLARAKEY', 'brand'))
        sidebar.append(brand)
        sidebar.append(label('PORTABLE VAULT', 'eyebrow'))
        sidebar.append(margins(label('YOUR COLLECTION', 'muted'), 10))
        self.nav = {}
        for kind in KINDS:
            nav = button(NAMES[kind], lambda kind=kind: self.navigate(kind))
            self.nav[kind] = nav
            sidebar.append(nav)
        spacer = box(); spacer.set_vexpand(True); sidebar.append(spacer)
        sidebar.append(button('Settings & backups', self.show_settings))
        sidebar.append(button('Lock Vault', lambda: self.lock('Vault locked.'), 'primary'))
        sidebar.append(label('No cloud. No account.\nv'+__version__, 'muted'))
        row.append(sidebar)
        right = margins(box(spacing=20), 30)
        right.set_hexpand(True)
        header = box(False, 20)
        titles = box(spacing=6)
        titles.append(label('Secure Portable Authentication Vault', 'muted'))
        self.section_title = label('', 'heading')
        titles.append(self.section_title)
        titles.set_hexpand(True)
        header.append(titles)
        header.append(button('+ Add entry', lambda: self.open_editor(self.category), 'primary'))
        right.append(header)
        self.search = Gtk.SearchEntry()
        self.search.set_property('placeholder-text', 'Search names, services, accounts and usernames')
        self.search.connect('search-changed', self.search_changed)
        right.append(self.search)
        self.content = box(spacing=14)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        scroll.set_child(self.content)
        right.append(scroll)
        row.append(right)
        main.append(row)
        self.status_label = label('Unlocked · Changes are encrypted and saved to your portable drive.', 'status')
        self.status_label.set_wrap(True)
        main.append(self.status_label)
        self.window.set_child(main)
        self.render_entries()

    def navigate(self, category):
        if self.session:
            self.category = category
            self.render_entries()

    def search_changed(self, *_):
        if self.session:
            self.query = self.search.get_text()
            self.render_entries()

    def render_entries(self):
        if not self.session:
            return
        empty(self.content)
        self.cards = []
        self.section_title.set_text(NAMES[self.category])
        for key, nav in self.nav.items():
            (nav.add_css_class if key == self.category else nav.remove_css_class)('active')
        entries = search_entries(self.session.data['entries'], self.query, self.category)
        if not entries:
            card = box(spacing=16, css='card')
            card.append(label('A quiet place for your important keys.', 'subheading'))
            card.append(label('Add your first entry to this collection.' if not self.query else 'No entries match this metadata search.', 'muted', True))
            card.append(button('Add '+NAMES[self.category].lower(), lambda: self.open_editor(self.category)))
            self.content.append(card)
        for e in entries:
            entry_id, kind, f = e['id'], e['kind'], e['fields']
            card = box(spacing=12, css='card')
            top = box(False, 10)
            title = label(e['title'], 'subheading'); title.set_hexpand(True); title.set_ellipsize(3)
            top.append(title)
            top.append(button('Open', lambda entry_id=entry_id: self.open_detail(entry_id), 'flat'))
            card.append(top)
            metadata = f.get('account') or f.get('username') or f.get('key_name') or f.get('host')
            if metadata:
                meta = label(metadata, 'muted'); meta.set_ellipsize(3); card.append(meta)
            if kind == 'totp':
                line = box(False, 16)
                code_widget = label('', 'code'); code_widget.set_hexpand(True)
                line.append(code_widget)
                line.append(button('Copy code', lambda entry_id=entry_id: self.copy_field(entry_id, 'totp')))
                card.append(line)
                progress = Gtk.ProgressBar()
                countdown = label('', 'muted')
                card.append(progress); card.append(countdown)
                self.cards.append((entry_id, code_widget, progress, countdown))
            else:
                info = (f"{len(f['codes'])} recovery codes · {sum(c['used'] for c in f['codes'])} used" if kind == 'recovery'
                        else f"{f['filename']} · {human_size(f['size'])} · encrypted" if kind == 'file'
                        else 'Encrypted · reveal or copy inside')
                card.append(label(info, 'muted'))
            self.content.append(card)
        self.tick()

    def copy_field(self, entry_id, field, index=None):
        def copy():
            f = self.session.entry(entry_id)['fields']
            value = code_at(f) if field == 'totp' else (f['codes'][index]['value'] if field == 'codes' else f[field])
            self.clipboard_guard.copy(value, self.session.data['settings']['clipboard'])
            self.status('Copied. Clipboard clearing follows your security settings; clipboard managers may retain copies.')
        self.safe(copy)

    def dialog(self, title, width=620):
        window = Gtk.Window(title=title, transient_for=self.window, modal=True)
        window.set_default_size(width, 500)
        self.watch_activity(window)
        content = margins(box(spacing=14))
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(content)
        window.set_child(scroll)
        self.dialogs.append(window)
        window.connect('close-request', lambda w: self.close_dialog(w))
        return window, content

    def close_dialog(self, window):
        if window in self.dialogs:
            self.dialogs.remove(window)
        if window.get_child():
            scrub_widgets(window.get_child())
        for name in ('restore_candidate', 'restore_password'):
            value = getattr(window, name, None)
            if value is not None:
                discard(value)
                setattr(window, name, None)
        if hasattr(window, 'restore_blob'):
            window.restore_blob = None
        window.destroy()
        gc.collect()
        return True

    def field(self, parent, name, value='', secret=False, multiline=False):
        parent.append(label(name, 'muted'))
        if multiline:
            widget = Gtk.TextView()
            widget.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            widget.set_monospace(True)
            widget.get_buffer().set_enable_undo(False)
            widget.get_buffer().set_text(value)
            scroll = Gtk.ScrolledWindow()
            scroll.set_min_content_height(120)
            scroll.set_child(widget)
            parent.append(scroll)
        else:
            widget = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry()
            widget.set_property('enable-undo', False)
            if not secret:
                widget.set_max_length(65536)
            widget.set_text(str(value))
            widget.set_hexpand(True)
            parent.append(widget)
        return widget

    @staticmethod
    def field_text(widget):
        if isinstance(widget, Gtk.TextView):
            buffer = widget.get_buffer()
            return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
        return widget.get_text()

    def open_editor(self, kind, entry_id=None):
        if not self.session:
            return
        e = self.session.entry(entry_id) if entry_id else None
        window, content = self.dialog(('Edit ' if e else 'Add ')+NAMES[kind])
        content.append(label(('Edit ' if e else 'Add ')+NAMES[kind], 'heading'))
        content.append(label('Saved only inside your encrypted portable vault.', 'muted'))
        fields = {}
        title = self.field(content, 'Title (optional: the file name is used if blank)' if kind == 'file' else 'Title / service',
                           e['title'] if e else '')
        values = e['fields'] if e else {}
        uri = None
        if kind == 'totp':
            uri = self.field(content, 'Paste an otpauth:// URI (optional)', secret=True)
            content.append(label('Or enter the account manually. QR image import is not included in V1.', 'muted', True))
            for key, name in [('service','Service / issuer'),('account','Account'),('secret','Base32 secret')]:
                fields[key] = self.field(content, name, values.get(key,''), secret=key=='secret')
            for key, name, default in [('algorithm','Algorithm: SHA1, SHA256 or SHA512','SHA1'),('digits','Digits: 6, 7 or 8',6),('period','Period in seconds: 15–300',30)]:
                fields[key] = self.field(content, name, values.get(key,default))
        elif kind == 'file':
            if values:
                content.append(label(f"Stored file: {values['filename']} ({human_size(values['size'])}). "
                                     'Choose a new file only to replace it.', 'muted', True))
            else:
                content.append(label('Any file up to 1 MB: a signing keystore, certificate, GPG key, wallet or '
                                     '2FA backup. The original stays where it is.', 'muted', True))
            fields['path'] = self.field(content, 'File to store' if not values else 'Replacement file (optional)')
            content.append(button('Browse files', lambda: self.file_picker(fields['path'], Path.home())))
            fields['notes'] = self.field(content, 'Notes', values.get('notes', ''), multiline=True)
        elif kind == 'recovery':
            content.append(label('One code per line. Prefix a used code with [used] .', 'muted'))
            codes = '\n'.join(('[used] ' if c['used'] else '')+c['value'] for c in values.get('codes',[]))
            fields['codes'] = self.field(content, 'Recovery codes', codes, multiline=True)
        else:
            specs = {
                'api':[('service','Service'),('key_name','Key name'),('api_key','API key / token'),('notes','Notes')],
                'ssh':[('host','Host (optional)'),('username','Username'),('private_key','Private key'),('public_key','Public key (optional)'),('notes','Notes')],
                'password':[('service','Service'),('username','Username'),('password','Password'),('website','Website'),('notes','Notes')],
                'note':[('note','Secure note')],
            }
            for key, name in specs[kind]:
                fields[key] = self.field(content, name, values.get(key,''), secret=key in ('password','api_key'),
                                         multiline=key in ('notes','note','private_key','public_key'))
                if key == 'password':
                    content.append(button('Generate password', lambda: self.generator_dialog(fields['password'])))
                if key == 'private_key':
                    content.append(button('Import private key from file', lambda: self.import_key_dialog(fields['private_key'])))
        error = label('', 'error', True); content.append(error)
        def save():
            try:
                if not self.session:
                    return
                f = {key:self.field_text(widget) for key,widget in fields.items()}
                if kind == 'totp':
                    if uri.get_text().strip():
                        f = parse_uri(uri.get_text().strip())
                    else:
                        f['secret'] = normalize_secret(f['secret'])
                        f['algorithm'] = f['algorithm'].strip().upper()
                        try:
                            f['digits'], f['period'] = int(f['digits']), int(f['period'])
                        except ValueError:
                            raise ValidationError('Digits and period must be whole numbers.') from None
                elif kind == 'recovery':
                    f = {'codes':[{'value':line.removeprefix('[used] ').strip(), 'used':line.startswith('[used] ')}
                                  for line in f['codes'].splitlines() if line.strip()]}
                elif kind == 'file':
                    source = f['path'].strip()
                    if source:
                        path = Path(source).expanduser()
                        raw = bytearray(read_external(path, MAX_FILE_BYTES))
                        try:
                            f = file_fields(path.name, raw, f['notes'])
                        finally:
                            wipe(raw)
                    elif values:
                        f = dict(values, notes=f['notes'])
                    else:
                        raise ValidationError('Choose the file to store.')
                    if not title.get_text().strip():
                        title.set_text(f['filename'])
                entry = new_entry(kind, title.get_text() or f.get('service',''), f)
                if entry_id:
                    original = self.session.entry(entry_id)
                    entry['id'], entry['created'] = entry_id, original['created']
                self.session.put(entry)
                self.close_dialog(window)
                self.render_entries()
                self.status('Entry saved and encrypted on your drive.')
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        actions = box(False)
        actions.append(button('Cancel', lambda:self.close_dialog(window)))
        actions.append(button('Save encrypted entry', save, 'primary'))
        content.append(actions)
        # Named references also make real widget integration tests stable and readable.
        window.editor_fields, window.editor_title, window.editor_uri = fields, title, uri
        window.save_entry = save
        window.present()
        return window

    def open_detail(self, entry_id):
        if not self.session:
            return
        e = self.session.entry(entry_id)
        window, content = self.dialog('ClaraKey • Entry')
        content.append(label(e['title'], 'heading'))
        content.append(label(NAMES[e['kind']], 'eyebrow'))
        stamp = lambda value:datetime.fromtimestamp(value,timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        content.append(label('Created '+stamp(e['created'])+' · Modified '+stamp(e['modified']), 'muted', True))
        if e['kind'] == 'recovery':
            for index, code in enumerate(e['fields']['codes']):
                line = box(False)
                masked = label('•••• •••• ••••', 'secret'); masked.set_hexpand(True)
                line.append(masked)
                line.append(button('Reveal', lambda index=index, target=masked:self.reveal(entry_id,'codes',target,index)))
                line.append(button('Copy', lambda index=index:self.copy_field(entry_id,'codes',index)))
                used = Gtk.CheckButton(label='Used'); used.set_active(code['used'])
                def toggle(widget, index=index):
                    if self.session:
                        self.safe(lambda:self.session.mark_code(entry_id,index,widget.get_active()), 'Recovery code updated.')
                        if self.session:
                            widget.set_active(self.session.entry(entry_id)['fields']['codes'][index]['used'])
                            self.render_entries()
                used.connect('toggled', toggle)
                line.append(used); content.append(line)
        elif e['kind'] == 'file':
            f = e['fields']
            for name, value in (('File name', f['filename']), ('Size', human_size(f['size'])),
                                ('SHA-256 fingerprint', f['sha256'])):
                content.append(label(name, 'muted'))
                content.append(label(value, None, True))
            content.append(label('The file itself stays encrypted. Use “Save file…” to write a copy outside the vault.', 'muted', True))
            if f['notes']:
                content.append(label('Notes', 'muted'))
                masked = label('•••• •••• ••••', 'secret', True)
                content.append(masked)
                content.append(button('Reveal', lambda target=masked:self.reveal(entry_id,'notes',target)))
        else:
            secrets_by_kind = {'totp':{'secret'},'api':{'api_key','notes'},'ssh':{'private_key','notes'},
                               'password':{'password','notes'},'note':{'note'}}
            for key, value in e['fields'].items():
                if value == '':
                    continue
                content.append(label(key.replace('_',' ').title(), 'muted'))
                if key in secrets_by_kind[e['kind']]:
                    masked = label('•••• •••• ••••', 'secret', True)
                    masked.set_max_width_chars(64)
                    content.append(masked)
                    actions = box(False)
                    actions.append(button('Reveal', lambda key=key,target=masked:self.reveal(entry_id,key,target)))
                    actions.append(button('Copy', lambda key=key:self.copy_field(entry_id,key)))
                    content.append(actions)
                else:
                    content.append(label(str(value), None, True))
                    if key == 'username':
                        content.append(button('Copy Username', lambda:self.copy_field(entry_id,'username')))
        actions = box(False)
        kind = e['kind']
        actions.append(button('Edit', lambda:(self.close_dialog(window),self.open_editor(kind,entry_id))))
        actions.append(button('Save file…' if kind == 'file' else 'Export…', lambda:self.export_dialog(entry_id)))
        actions.append(button('Delete', lambda:self.confirm_delete(entry_id,window), 'danger'))
        content.append(actions)
        content.append(button('Close', lambda:self.close_dialog(window)))
        window.present()
        return window

    def reveal(self, entry_id, field, target, index=None):
        if not self.session:
            return
        if target.get_text() != '•••• •••• ••••':
            target.set_text('•••• •••• ••••')
        else:
            f = self.session.entry(entry_id)['fields']
            target.set_text(f['codes'][index]['value'] if field == 'codes' else str(f[field]))

    def confirm_delete(self, entry_id, detail):
        window, content = self.dialog('Delete entry', 480)
        content.append(label('Delete this entry?', 'heading'))
        content.append(label('It will be removed from the current vault. Encrypted backups and the previous revision may still contain it.', 'warning', True))
        def remove():
            if self.session:
                try:
                    self.session.delete(entry_id)
                    self.close_dialog(window); self.close_dialog(detail); self.render_entries()
                    self.status('Entry deleted from current vault.')
                except ClaraKeyError as exc:
                    self.status(str(exc))
        content.append(button('Delete entry', remove, 'danger'))
        content.append(button('Cancel', lambda:self.close_dialog(window)))
        window.present()

    def generator_dialog(self, target):
        window, content = self.dialog('Password generator', 480)
        content.append(label('Create a random password', 'heading'))
        length = Gtk.SpinButton.new_with_range(8,128,1); length.set_value(24)
        content.append(label('Length', 'muted')); content.append(length)
        checks=[]
        for name in ('Uppercase','Lowercase','Numbers','Symbols'):
            check=Gtk.CheckButton(label=name); check.set_active(True); content.append(check); checks.append(check)
        preview=Gtk.PasswordEntry(show_peek_icon=True); content.append(preview)
        preview.set_property('enable-undo', False)
        error=label('', 'error', True); content.append(error)
        def generate():
            try:
                preview.set_text(generate_password(length.get_value_as_int(),*[c.get_active() for c in checks]))
                error.set_text('')
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        content.append(button('Generate',generate))
        content.append(button('Use this password',lambda:(target.set_text(preview.get_text()),self.close_dialog(window)), 'primary'))
        generate(); window.present()

    def file_picker(self, target, directory=None):
        # In-app file browser avoids host recent-file databases and portal persistence.
        window, content = self.dialog('Choose local file', 680)
        path_field = self.field(content, 'Directory', str(directory or self.root))
        listing = box(spacing=4); content.append(listing)
        error = label('', 'error', True); content.append(error)
        def list_path():
            empty(listing)
            try:
                directory_path = Path(path_field.get_text()).expanduser().absolute()
                items=[]
                with os.scandir(directory_path) as scan:
                    for item in scan:
                        if not item.is_symlink():
                            items.append((item.is_dir(follow_symlinks=False),item.name))
                        if len(items)>1000:
                            raise StorageError('This folder has too many entries. Enter the file path directly instead.')
                def open_dir(path):
                    path_field.set_text(str(path)); list_path()
                listing.append(button('↑ Parent folder',lambda:open_dir(directory_path.parent)))
                for is_dir,name in sorted(items,key=lambda v:(not v[0],v[1].casefold())):
                    path=directory_path/name
                    if is_dir:
                        listing.append(button('▸ '+name,lambda path=path:open_dir(path),'flat'))
                    else:
                        listing.append(button(name,lambda path=path:(target.set_text(str(path)),self.close_dialog(window)),'flat'))
                error.set_text('')
            except (OSError, ClaraKeyError):
                error.set_text('Cannot list this directory. Check the path and permissions.')
        content.prepend(button('Open directory',list_path))
        path_field.connect('activate',lambda _:list_path())
        list_path(); window.present()

    def import_key_dialog(self, target):
        window, content = self.dialog('Import SSH private key', 560)
        content.append(label('Import a local private key', 'heading'))
        content.append(label('The original file remains in place. ClaraKey will not install anything into ~/.ssh.', 'muted', True))
        path=self.field(content,'Private-key file path')
        content.append(button('Browse files',lambda:self.file_picker(path,Path.home()/'.ssh')))
        error=label('', 'error', True); content.append(error)
        def import_key():
            try:
                raw=read_external(Path(path.get_text()).expanduser(),65536)
                from cryptography.hazmat.primitives.serialization import load_ssh_private_key, load_pem_private_key
                loader=load_ssh_private_key if raw.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----') else load_pem_private_key
                try:
                    loader(raw,password=None)
                except TypeError:
                    # Library recognized encrypted material; preserve its additional passphrase protection.
                    if b'ENCRYPTED' not in raw and not raw.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----'):
                        raise ValueError()
                target.get_buffer().set_text(raw.decode('utf-8'))
                self.close_dialog(window)
            except (ValueError, UnicodeError, UnsupportedAlgorithm):
                error.set_text('This is not a supported OpenSSH or PEM private key.')
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        content.append(button('Import into entry',import_key,'primary'))
        window.present()

    def export_dialog(self, entry_id):
        e = self.session.entry(entry_id) if self.session else None
        is_file = bool(e) and e['kind'] == 'file'
        window, content = self.dialog('Save file outside the vault' if is_file else 'Export plaintext secret', 600)
        content.append(label('This copy will be unencrypted', 'heading'))
        content.append(label('The exported file will no longer have ClaraKey’s vault encryption protection. Anyone with access to that file may read or use the secret. Deleting files from a USB drive may not securely erase them.', 'warning', True))
        if is_file:
            content.append(label('ClaraKey never overwrites an existing file; choose a new name if this one is taken.', 'muted', True))
        suggestion = str(Path.home() / e['fields']['filename']) if is_file else ''
        path=self.field(content,'New destination file path', suggestion)
        confirm=Gtk.CheckButton(label='I understand that this file will contain plaintext secrets.')
        content.append(confirm)
        error=label('', 'error', True); content.append(error)
        def export():
            try:
                if not self.session or not confirm.get_active():
                    raise ValidationError('Confirm the plaintext export warning first.')
                if not path.get_text().strip():
                    raise ValidationError('Enter a new destination file path.')
                self.session.export(entry_id,Path(path.get_text()).expanduser(),confirmed=True)
                self.close_dialog(window)
                self.status('Plaintext export created at your chosen location. Protect this file.')
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        content.append(button('Save unencrypted copy' if is_file else 'Export plaintext',export,'danger'))
        content.append(button('Cancel',lambda:self.close_dialog(window)))
        window.export_path, window.export_confirm, window.export_commit = path, confirm, export
        window.present()
        return window

    def show_settings(self):
        if not self.session:
            return
        window,content=self.dialog('Settings & encrypted backups',640)
        content.append(label('Security settings', 'heading'))
        content.append(label('These preferences are stored inside your encrypted vault.', 'muted'))
        locks=Gtk.DropDown.new_from_strings(['1 minute','5 minutes','10 minutes','30 minutes','Never'])
        clips=Gtk.DropDown.new_from_strings(['15 seconds','30 seconds','60 seconds','Never automatically clear'])
        locks.set_selected(AUTO_LOCK.index(self.session.data['settings']['auto_lock']))
        clips.set_selected(CLIPBOARD.index(self.session.data['settings']['clipboard']))
        content.append(label('Lock after inactivity', 'muted')); content.append(locks)
        content.append(label('Clear clipboard after copying', 'muted')); content.append(clips)
        content.append(label('Locking or closing always clears ClaraKey-owned clipboard content. A clipboard manager may retain its own history.', 'warning', True))
        error=label('', 'error', True); content.append(error)
        def save():
            try:
                self.session.settings(AUTO_LOCK[locks.get_selected()],CLIPBOARD[clips.get_selected()])
                self.idle.timeout=self.session.data['settings']['auto_lock']; self.idle.touch()
                self.close_dialog(window); self.status('Security settings saved.')
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        content.append(button('Save settings',save,'primary'))
        content.append(Gtk.Separator())
        content.append(label('Encrypted backups', 'subheading'))
        def backup():
            try:
                result=self.session.backup()
                error.remove_css_class('error'); error.add_css_class('good')
                error.set_text('Encrypted backup created: '+result.name)
            except ClaraKeyError as exc:
                error.set_text(str(exc))
        content.append(button('Create Backup',backup))
        content.append(button('Restore Backup',self.restore_dialog))
        content.append(label('Backups use the password active when they were created. Keep a second encrypted copy on a different drive.', 'muted', True))
        content.append(label('Vault location: '+str(self.store.vault_path),'muted',True))
        content.append(label('Argon2id · 64 MiB / 3 passes / 4 lanes\nAES-256-GCM · authenticated encrypted vault','muted',True))
        window.present()
        return window

    def restore_dialog(self):
        if not self.store:
            return
        window,content=self.dialog('Validate and restore encrypted backup',660)
        content.append(label('Restore an encrypted vault', 'heading'))
        content.append(label('Validate with the backup’s master password before confirming replacement. An encrypted copy of the current vault is kept first.', 'warning',True))
        path=self.field(content,'Backup / recovery file path')
        content.append(button('Browse files',lambda:self.file_picker(path,self.root/'backups')))
        try:
            recovery=self.store.recovery_files()
        except ClaraKeyError:
            recovery=[]
        for recovery_path in recovery:
            content.append(button('Use recovery: '+recovery_path.name,lambda p=recovery_path:path.set_text(str(p))))
        password=self.field(content,'Backup master password',secret=True)
        info=label('', 'warning',True); content.append(info)
        confirmed=Gtk.CheckButton(label='Replace current vault with the validated backup contents.')
        confirmed.set_sensitive(False); content.append(confirmed)
        # Window-owned state is explicitly cleared on close/lock; no lingering secret closure.
        window.restore_candidate=None
        window.restore_blob=None
        window.restore_password=None
        def invalidate(*_):
            if window.restore_candidate is not None:
                discard(window.restore_candidate)
            window.restore_candidate=None; window.restore_blob=None
            if window.restore_password is not None:
                wipe(window.restore_password); window.restore_password=None
            confirmed.set_active(False); confirmed.set_sensitive(False)
        path.connect('changed',invalidate); password.connect('changed',invalidate)
        def validate():
            if self.throttle.remaining()>0:
                info.set_text('Please wait before another password attempt.'); return
            raw_password=bytearray(password.get_text().encode())
            try:
                blob=read_external(Path(path.get_text()).expanduser())
                candidate=Session.validate_backup(blob,raw_password)
                password.set_text('')
                window.restore_candidate=candidate
                window.restore_blob=blob
                window.restore_password=bytearray(raw_password)
                info.set_text(f"Validated {len(candidate['entries'])} entries. "+('The current master password will remain unchanged.' if self.session else 'The restored vault will use the backup’s master password.'))
                confirmed.set_sensitive(True)
                self.throttle.success()
            except ClaraKeyError as exc:
                invalidate(); self.throttle.failed(); info.set_text(str(exc))
            finally:
                wipe(raw_password)
        def restore():
            if not confirmed.get_active() or window.restore_candidate is None:
                info.set_text('Validate the backup and confirm replacement first.'); return
            try:
                if self.session:
                    self.session.restore(window.restore_candidate,confirmed=True)
                    self.idle.timeout=self.session.data['settings']['auto_lock']
                else:
                    Session.restore_locked(self.store,window.restore_blob,window.restore_password,confirmed=True)
                invalidate(); self.close_dialog(window)
                if self.session:
                    self.show_dashboard(); self.status('Backup restored. Current master password is unchanged.')
                else:
                    self.show_login('Backup restored. Unlock with its master password.')
            except ClaraKeyError as exc:
                info.set_text(str(exc))
        content.append(button('1. Validate Backup',validate))
        content.append(button('2. Restore validated backup',restore,'danger'))
        content.append(button('Cancel',lambda:self.close_dialog(window)))
        window.connect('destroy',lambda _:invalidate())
        window.restore_validate,window.restore_confirm,window.restore_commit=validate,confirmed,restore
        window.restore_path,window.restore_password_field=path,password
        window.present()
        return window

    def lock(self, message='Vault locked.'):
        self.cards=[]
        if self.session:
            session, self.session = self.session, None
            session.close()
        for dialog in list(self.dialogs):
            self.close_dialog(dialog)
        self.clipboard_guard.clear()
        primary=self.window.get_primary_clipboard()
        if primary.is_local():
            primary.set_content(None)
        if self.window.get_child():
            scrub_widgets(self.window.get_child())
        self.query=''
        self.idle = IdleLock(300)
        self.show_login(message)
        gc.collect()

    def close_requested(self, *_):
        if self.session:
            self.lock()
        else:
            for window in list(self.dialogs):
                self.close_dialog(window)
        if self.clipboard_guard:
            self.clipboard_guard.clear()
        return False

    def shutdown_app(self, *_):
        if self.timer:
            GLib.source_remove(self.timer); self.timer=None
        if self.clipboard_guard:
            self.clipboard_guard.clear()
        if self.session:
            self.session.close(); self.session=None
        if self.store:
            self.store.close(); self.store=None
