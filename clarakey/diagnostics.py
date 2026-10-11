"""Useful error coordinates without exception messages, locals or secret values."""
from pathlib import Path
import sys


class SafeExceptionReporter:
    def __init__(self, stream=None):
        self.stream = stream
        self.seen = set()
        package = Path(__file__).resolve().parent
        self.sources = {str(package / (name + '.py')): name for name in (
            'activity', 'crypto', 'diagnostics', 'errors', 'model', 'policy',
            'session', 'storage', 'totp', 'ui')}
        self.sources[str(package.parent / 'run.py')] = 'launcher'
        self.types = {cls: cls.__name__ for cls in (
            AttributeError, TypeError, ValueError, RuntimeError, OSError,
            ImportError, ModuleNotFoundError, NameError, KeyError, IndexError,
            RecursionError, AssertionError, MemoryError)}

    def __call__(self, kind, _value, traceback):
        if kind is KeyboardInterrupt:
            return
        category = self.types.get(kind, 'Error')
        location = 'GTK callback'
        while traceback is not None:
            module = self.sources.get(traceback.tb_frame.f_code.co_filename)
            if module is not None:
                location = f'{module}:{traceback.tb_lineno}'
            traceback = traceback.tb_next
        code = (category, location)
        # Keep both stderr output and bookkeeping bounded during signal storms.
        if code in self.seen or len(self.seen) >= 20:
            return
        self.seen.add(code)
        stream = self.stream if self.stream is not None else sys.stderr
        stream.write(f'ClaraKey error [{category} at {location}]. '
                     'No secret values logged; repeated occurrences suppressed.\n')
