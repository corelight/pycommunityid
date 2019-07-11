"""
This module mirrors Zeek's logic for mapping ICMP's message type and
codes into a port-like notion suitable for ordering request/response
into the same "flow".
"""
ECHO_REPLY = 0
ECHO = 8
RTR_ADVERT = 9
RTR_SOLICIT = 10
TSTAMP = 13
TSTAMP_REPLY = 14
INFO = 15
INFO_REPLY = 16
MASK = 17
MASK_REPLY = 18

TYPE_MAPPER = {
    ECHO:            ECHO_REPLY,
    ECHO_REPLY:      ECHO,
    TSTAMP:          TSTAMP_REPLY,
    TSTAMP_REPLY:    TSTAMP,
    INFO:            INFO_REPLY,
    INFO_REPLY:      INFO,
    RTR_SOLICIT:     RTR_ADVERT,
    RTR_ADVERT:      RTR_SOLICIT,
    MASK:            MASK_REPLY,
    MASK_REPLY:      MASK,
}

def get_port_equivalents(mtype, mcode):
    """
    Given a message type and code (as host-order ints), returns the
    source and destination port equivalents, and a Boolean that
    indicates whether this is a one-way interaction (in which case
    ordering does not apply) or not (in which case we can flip
    ordering).
    """
    try:
        return mtype, TYPE_MAPPER[mtype], False
    except KeyError:
        return mtype, mcode, True
