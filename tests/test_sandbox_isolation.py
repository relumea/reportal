"""No registry row may outlive the test that registered it.

The module snapshot is taken while the registries are still pristine, so a
failure here names the earlier file that left a row behind.  This file must
sort after ``test_sandbox.py`` to observe it.
"""

from reportal import debug, sandbox

_RUNNERS = [runner.name for runner in sandbox.registered_runners()]
_BACKENDS = [backend.name for backend in debug.registered_backends()]


def test_sandbox_runners_not_leaked() -> None:
    assert [runner.name for runner in sandbox.registered_runners()] == _RUNNERS


def test_debug_backends_not_leaked() -> None:
    assert [backend.name for backend in debug.registered_backends()] == _BACKENDS
