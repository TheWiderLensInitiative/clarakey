"""Small injectable policies, independent of UI and wall-clock changes."""
import time


def elapsed_clock():
    # Linux BOOTTIME includes suspend; monotonic fallback is for future ports.
    return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, 'CLOCK_BOOTTIME') else time.monotonic()


class IdleLock:
    def __init__(self, timeout=300, clock=elapsed_clock):
        self.timeout, self.clock = timeout, clock
        self.last_activity = clock()

    def touch(self):
        self.last_activity = self.clock()

    def due(self):
        return bool(self.timeout and self.clock() - self.last_activity >= self.timeout)


class UnlockThrottle:
    def __init__(self, clock=elapsed_clock):
        self.clock, self.failures, self.ready_at = clock, 0, 0

    def failed(self):
        self.failures += 1
        delay = min(60, 2 ** min(6, self.failures - 2)) if self.failures >= 3 else 0
        self.ready_at = self.clock() + delay

    def remaining(self):
        return max(0, self.ready_at - self.clock())

    def success(self):
        self.failures, self.ready_at = 0, 0


class ClipboardGuard:
    """Uses provider identity, not text equality (newer identical copies are safe)."""
    def __init__(self, backend, clock=elapsed_clock):
        self.backend, self.clock = backend, clock
        self.owner, self.deadline = None, None

    def copy(self, text, timeout=30):
        self.owner = self.backend.set(text)
        self.deadline = self.clock() + timeout if timeout else None

    def tick(self):
        if self.owner is not None and not self.backend.owns(self.owner):
            self.owner, self.deadline = None, None
        elif self.deadline is not None and self.clock() >= self.deadline:
            self.clear()

    def clear(self):
        if self.owner is not None and self.backend.owns(self.owner):
            self.backend.clear()
        self.owner, self.deadline = None, None
