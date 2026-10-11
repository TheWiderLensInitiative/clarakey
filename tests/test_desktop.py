"""Desktop boundary regressions executable without a display server.
The controllers and GObject signal conversion are real GTK objects; only the
window's add_controller method is substituted because no window is realized.
"""
import io
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from clarakey.activity import attach_activity_controllers, Gtk
from gi.repository import Gdk
from clarakey.diagnostics import SafeExceptionReporter
import clarakey.diagnostics as diagnostics_module
from clarakey.ui import ClaraKeyApp

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = Path(diagnostics_module.__file__).resolve().parent.parent
UI_FILENAME = str(APP_ROOT/'clarakey/ui.py')


class ActivityControllerTests(unittest.TestCase):
    def test_native_keyboard_motion_scroll_and_click_signals(self):
        calls = []
        attached = []
        controllers = attach_activity_controllers(
            SimpleNamespace(add_controller=attached.append), lambda: calls.append(True))
        self.assertEqual(list(controllers), attached)
        keys, motion, scroll, clicks = controllers
        with patch.object(sys, 'excepthook') as errors:
            self.assertFalse(keys.emit('key-pressed', Gdk.KEY_a, 38, Gdk.ModifierType(0)))
            keys.emit('key-released', Gdk.KEY_a, 38, Gdk.ModifierType(0))
            motion.emit('motion', 12.5, 24.0)
            self.assertFalse(scroll.emit('scroll', 0.0, 1.0))
            clicks.emit('pressed', 1, 12.5, 24.0)
            clicks.emit('released', 1, 12.5, 24.0)
            errors.assert_not_called()
        self.assertEqual(len(calls), 6)
        self.assertEqual(clicks.get_button(), 0)
        self.assertFalse(clicks.get_exclusive())
        for controller in controllers:
            self.assertEqual(controller.get_propagation_phase(), Gtk.PropagationPhase.CAPTURE)
            self.assertNotIsInstance(controller, Gtk.EventControllerLegacy)

    def test_input_observes_replaced_inactivity_policy(self):
        calls = []
        app = SimpleNamespace(idle=SimpleNamespace(touch=lambda: calls.append('old')))
        attached = []
        ClaraKeyApp.watch_activity(app, SimpleNamespace(add_controller=attached.append))
        app.idle = SimpleNamespace(touch=lambda: calls.append('current'))
        attached[1].emit('motion', 1.0, 1.0)
        self.assertEqual(calls, ['current'])


class DiagnosticTests(unittest.TestCase):
    def test_reports_code_location_but_no_message_locals_or_paths(self):
        output = io.StringIO()
        reporter = SafeExceptionReporter(output)
        secret = 'TEST-ONLY-do-not-log-password-1273'
        try:
            exec(compile("raise ValueError(secret)", UI_FILENAME, 'exec'), {'secret': secret})
        except ValueError:
            reporter(*sys.exc_info())
        text = output.getvalue()
        self.assertIn('[ValueError at ui:1]', text)
        self.assertNotIn(secret, text)
        self.assertNotIn(str(ROOT), text)
        self.assertNotIn('raise ValueError', text)

    def test_unknown_exception_name_and_string_are_never_used(self):
        output = io.StringIO()
        reporter = SafeExceptionReporter(output)
        def forbidden(_self):
            raise AssertionError('Exception formatting must never run')
        custom = type('TEST_ONLY_SECRET_IN_CLASS_NAME', (Exception,), {'__str__': forbidden, '__repr__': forbidden})
        reporter(custom, custom(), None)
        self.assertIn('[Error at GTK callback]', output.getvalue())
        self.assertNotIn('TEST_ONLY_SECRET', output.getvalue())

    def test_signal_storm_is_deduplicated_and_ctrl_c_is_not_an_error(self):
        output = io.StringIO()
        reporter = SafeExceptionReporter(output)
        for _ in range(100):
            reporter(TypeError, TypeError('TEST-ONLY-secret'), None)
        reporter(KeyboardInterrupt, KeyboardInterrupt(), None)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(len(reporter.seen), 1)

    def test_distinct_error_sites_are_bounded(self):
        output = io.StringIO()
        reporter = SafeExceptionReporter(output)
        for line in range(40):
            try:
                exec(compile('\n'*line + 'raise ValueError()', UI_FILENAME, 'exec'))
            except ValueError:
                reporter(*sys.exc_info())
        self.assertEqual(len(reporter.seen), 20)
        self.assertEqual(len(output.getvalue().splitlines()), 20)

    def test_entrypoint_disables_portals_without_weakening_memory_protection(self):
        script = '''
import ctypes, os, resource, runpy, sys
os.environ['GDK_DEBUG'] = 'events,clipboard'
runpy.run_path(sys.argv[1], run_name='privacy_probe')
assert os.environ['GDK_DEBUG'] == 'no-portals'
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) == 0
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(APP_ROOT/'run.py')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, 'Launcher privacy settings regression')
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
