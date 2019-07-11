"""
Toplevel module for the Community ID package.

We pull in all the objects and variables you'd commonly need. The user
should be fine just importing this, and not need any of the
submodules.
"""
from communityid.algo import FlowTuple
from communityid.algo import CommunityID
from communityid.algo import PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6, PROTO_SCTP
