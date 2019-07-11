"""
This module mirrors Zeek's logic for mapping ICMP6's message type and
codes into a port-like notion suitable for ordering request/response
into the same "flow".
"""
ECHO_REQUEST = 128
ECHO_REPLY = 129
MLD_LISTENER_QUERY = 130
MLD_LISTENER_REPORT = 131
ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136
WRU_REQUEST = 139
WRU_REPLY = 140
HAAD_REQUEST = 144
HAAD_REPLY = 145

TYPE_MAPPER = {
    ECHO_REQUEST:        ECHO_REPLY,
    ECHO_REPLY:          ECHO_REQUEST,
    MLD_LISTENER_QUERY:  MLD_LISTENER_REPORT,
    MLD_LISTENER_REPORT: MLD_LISTENER_QUERY,
    ND_ROUTER_SOLICIT:   ND_ROUTER_ADVERT,
    ND_ROUTER_ADVERT:    ND_ROUTER_SOLICIT,
    ND_NEIGHBOR_SOLICIT: ND_NEIGHBOR_ADVERT,
    ND_NEIGHBOR_ADVERT:  ND_NEIGHBOR_SOLICIT,
    WRU_REQUEST:         WRU_REPLY,
    WRU_REPLY:           WRU_REQUEST,
    HAAD_REQUEST:        HAAD_REPLY,
    HAAD_REPLY:          HAAD_REQUEST,
}

def get_port_equivalents(mtype, mcode):
    """
    Given a message type and code (as host-order ints), returns the
    port equivalents, and a Boolean that indicates whether this is a
    one-way interaction (in which case ordering does not apply) or not
    (in which case we can flip ordering).
    """
    try:
        return mtype, TYPE_MAPPER[mtype], False
    except KeyError:
        return mtype, mcode, True
