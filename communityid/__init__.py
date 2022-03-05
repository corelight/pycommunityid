"""
Toplevel module for the Community ID package.

We pull in all the objects and variables you'd commonly need. The user
should be fine just importing this, and not need any of the
submodules.
"""
import logging

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.NullHandler())

from communityid.error import Error, FlowTupleError
from communityid.algo import FlowTuple
from communityid.algo import CommunityID
from communityid.algo import (PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6,
                              PROTO_SCTP, PORT_PROTOS)

def get_proto(proto):
    """
    Returns a protocol number (in the /etc/protocols sense, e.g. 6 for
    TCP) for the given input value. For the protocols that have
    PROTO_xxx constants defined, this can be provided textually and
    case-insensitively, otherwise the provided value gets converted to
    an integer and returned.

    Returns None if this conversion failed.
    """
    protos = {
        "ICMP": PROTO_ICMP,
        "ICMP6": PROTO_ICMP6,
        "SCTP": PROTO_SCTP,
        "TCP": PROTO_TCP,
        "UDP": PROTO_UDP,
    }

    try:
        return protos[proto.upper()]
    except (KeyError, AttributeError):
        pass

    try:
        return int(proto)
    except ValueError:
        pass

    return None
