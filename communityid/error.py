"""
Exceptions/errors in the pycommunityid module.
"""

class Error(Exception):
    """Base class for Community ID errors."""

class FlowTupleError(Error):
    """Problems when creating/handling FlowTuple instances."""
