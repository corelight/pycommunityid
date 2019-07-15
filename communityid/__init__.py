"""
Toplevel module for the Community ID package.

We pull in all the objects and variables you'd commonly need. The user
should be fine just importing this, and not need any of the
submodules.
"""
from communityid.algo import FlowTuple
from communityid.algo import CommunityID
from communityid.algo import PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6, PROTO_SCTP

def get_proto(proto):
    """
    Returns the appropriate PROTO_xxx constant for the given protocol,
    or None if the protocol wasn't understood.

    The input type can either be a string ("TCP", "UDP", etc) or the
    IP protocol number (e.g., 6 for TCP)
    """
    try:
        if int(proto) in (PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6, PROTO_SCTP):
            return int(proto)
    except ValueError:
        pass

    protos = {
        "ICMP": PROTO_ICMP,
        "ICMP6": PROTO_ICMP6,
        "SCTP": PROTO_SCTP,
        "TCP": PROTO_TCP,
        "UDP": PROTO_UDP,
    }

    try:
        return protos[proto.upper()]
    except KeyError:
        return None
