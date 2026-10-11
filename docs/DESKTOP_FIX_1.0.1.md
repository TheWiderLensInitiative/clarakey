# ClaraKey 1.0.1 desktop input fix

The first desktop launch displayed the welcome screen but repeatedly printed the
old generic exception message. The same process also reported portal access errors
for `/proc/PID/root`.

Investigation reproduced a signal-conversion error with the old
`Gtk.EventControllerLegacy` input observer: the installed GTK 4.22.4 / PyGObject
3.56.2 combination rejects a `Gdk.MotionEvent` when it crosses that raw signal
boundary. The old logger suppressed the original desktop exception detail, so
this reproduces a defective handler rather than proving the precise text of every
exception seen in that desktop session.

The inactivity observer now uses `Gtk.EventControllerKey`,
`Gtk.EventControllerMotion`, `Gtk.EventControllerScroll` and `Gtk.GestureClick`.
Their typed signals carry ordinary numeric arguments. Keyboard/scroll handlers
return false so normal editing and scrolling continue. Gestures observe all
pointer buttons and touch. Every event looks up the current inactivity policy,
including after the policy is replaced on lock.

The standalone launcher sets `GDK_DEBUG=no-portals` before GTK is imported. Its
private file browser, in-memory settings and inactivity handling do not need
optional desktop portal services, which conflict with the process's nondumpable
status when they inspect `/proc/PID/root`. Core-dump suppression and
`PR_SET_DUMPABLE=0` remain enabled; this fix does not weaken those protections.
GTK documents the flag in its
[runtime options](https://docs.gtk.org/gtk4/running.html).

Unexpected exceptions now report only an allowlisted exception category and an
application module/line coordinate, or a generic GTK callback label. No exception
messages, secret values, locals, source lines or full paths are printed. Identical
errors are deduplicated and diagnostic bookkeeping/output is bounded. Ctrl+C is
not reported as an application error. The GUI acceptance harness now fails on
unexpected callback exceptions instead of allowing GTK to print and continue.

Seven new headless regressions exercise real GTK key/motion/scroll/click signals,
input propagation, replacement of the idle policy, secret-free diagnostics,
error-storm suppression and retention of process-memory protections. Three
packaging tests ensure release archives contain only checksum-verified build
files and never include vaults, backups, the process lock or unlisted exports.
The original 43 security tests remain in the suite.

A fresh release is built separately from the installed portable folder. Deployment
updates only manifest-listed application/runtime/documentation files under an
exclusive process lock. Vault and backup directories and the lock file are
preserved. Release archives are produced from the fresh build, not user data.

Full display-driven acceptance remains blocked inside the development sandbox.
The real desktop launch must be retried to confirm the user-visible result.
