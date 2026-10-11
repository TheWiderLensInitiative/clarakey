"""Observe activity through typed GTK signals without consuming user input."""
import gi

gi.require_version('Gtk', '4.0')
from gi.repository import Gtk


def attach_activity_controllers(widget, touch):
    # EventControllerLegacy passes a raw fundamental GdkEvent through the Python
    # signal marshaller. Some PyGObject/GTK combinations cannot convert it. These
    # controllers expose ordinary numeric arguments and work without raw events.
    def observed(*_unused):
        touch()
        return False  # Let the focused widget receive keys and scrolling normally.

    keys = Gtk.EventControllerKey()
    keys.connect('key-pressed', observed)
    keys.connect('key-released', observed)
    motion = Gtk.EventControllerMotion()
    motion.connect('motion', observed)
    scroll = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.BOTH_AXES)
    scroll.connect('scroll', observed)
    clicks = Gtk.GestureClick()
    clicks.set_button(0)  # All pointer buttons; the gesture also handles touch.
    clicks.set_exclusive(False)
    clicks.connect('pressed', observed)
    clicks.connect('released', observed)
    controllers = (keys, motion, scroll, clicks)
    for controller in controllers:
        controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        widget.add_controller(controller)
    return controllers
