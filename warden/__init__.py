"""warden: a local guard and decision engine for AI agents, built on the lev decision model.

    from warden import inspect, redact, decide
"""
__version__ = "0.1.0"

import logging as _logging

_logging.getLogger("warden").addHandler(_logging.NullHandler())


def inspect(text, boundary="prompt", **kw):
    from .guard import inspect as _inspect
    return _inspect(text, boundary, **kw)


def redact(text):
    from .rules import redact as _redact
    return _redact(text)


def decide(question, kind="yes_no", items=(), **kw):
    from .decide import decide as _decide
    return _decide(question, kind, items, **kw)
