"""Testing helpers — opt-in submodules for cross-checking FloorVault's primitives.

Modules under ``hermes_vault.testing`` are NOT exported from
``hermes_vault.__init__``. They are reachable only by an explicit import, e.g.
``from hermes_vault.testing.siv_reference import siv_encrypt``.

Why opt-in
----------
FloorVault ships a single public API for application code. Anything a third
party might *also* want to import — for cross-checks, conformance harnesses,
or migration tooling — lives here, so the application API surface stays small
and grep-able. A test that pulls a submodule in is explicitly opting in; an
application that does not need the helper has no transitive surface to audit.
"""
