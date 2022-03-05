"""
This module implements Community ID network flow hashing.
"""
import abc
import base64
import collections
import hashlib
import logging
import socket
import string
import struct

from communityid import error
from communityid import compat
from communityid import icmp
from communityid import icmp6

from . import LOG

# Proper enums here would be nice, but this aims to support Python
# 2.7+ and while there are ways to get "proper" enums pre-3.0, it just
# seems overkill. --cpk

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP6 = 58
PROTO_SCTP = 132

# The set of protocols we explicitly support as port-enabled:
# Community ID computations on those protocols should be based on a
# five-tuple.
PORT_PROTOS = set([PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6, PROTO_SCTP])

class FlowTuple:
    """
    Tuples of network flow endpoints, used as input for the Community
    ID computation. These tuple objects are flexible regarding the
    input data types -- for the addresses you can use NBO byte-strings
    or ASCII, for example. They usually are 5-tuples of address & port
    pairs, plus IP protocol number, but port-less tuples are supported
    for less common IP payloads.
    """
    Data = collections.namedtuple(
        'Data', ['proto', 'saddr', 'daddr', 'sport', 'dport'])

    def __init__(self, proto, saddr, daddr, sport=None, dport=None,
                 is_one_way=False):
        """Tuple initializer.

        The proto argument is a non-negative integer and represents an
        IP protocol number, e.g. 6 for TCP. You can use the PROTO_*
        constants if convenient, and communityid.get_proto() to help
        convert to integer.

        The saddr and daddr arguments are source & destination IP
        addresses, either IPv4 or IPv6. Multiple data types are
        supported, including bytes (as str in older Pythons, or the
        explicit bytes type), IPv4Address, IPv6Address, and string
        representations.

        The sport and dport arguments are numeric port numbers, either
        provided as ints or in packed 16-bit network byte order, of
        type "bytes". When the protocol number is one of PORT_PROTOS
        (TCP, UDP, etc), they are required. For other IP protocols
        they are optional.

        The optional Boolean is_one_way argument indicates whether the
        tuple captures a bidirectional flow (the default) or
        not. Setting this to true means that the computation will
        consider the tuple directional and not try to pair up with
        flipped-endpoint tuples. Normally you don't need to pass this.

        This can raise FlowTupleErrors when the input is inconsistent.

        """
        self.proto = proto
        self.saddr, self.daddr = saddr, daddr
        self.sport, self.dport = sport, dport

        if proto is None or type(proto) != int:
            raise error.FlowTupleError('Need numeric protocol number')

        if saddr is None or daddr is None:
            raise error.FlowTupleError('Need source and destination address')

        if not self.is_ipaddr(saddr):
            raise error.FlowTupleError('Unsupported format for source IP address "%s"' % saddr)
        if not self.is_ipaddr(daddr):
            raise error.FlowTupleError('Unsupported format for destination IP address "%s"' % daddr)

        if ((sport is None and dport is not None) or
            (dport is None and sport is not None)):
            raise error.FlowTupleError('Need either both or no port numbers')

        if sport is not None and not self.is_port(sport):
            raise error.FlowTupleError('Source port "%s" invalid' % sport)
        if dport is not None and not self.is_port(dport):
            raise error.FlowTupleError('Destination port "%s" invalid' % dport)

        if proto in PORT_PROTOS and sport is None:
            raise error.FlowTupleError('Need port numbers for port-enabled protocol %s' % proto)

        # Our ICMP handling directly mirrors that of Zeek, since it
        # tries hardest to map ICMP into traditional 5-tuples. For
        # this, it evaluates the message type & code to identify
        # whether the notion of two-way communication applies. If not,
        # tuple-flipping isn't an option either. The following flag
        # stores this result, assuming by default we're bidirectional.

        self.is_one_way = is_one_way

        # The rest of the constructor requires ports.
        if sport is None or dport is None:
            return

        # If we're explicitly told this is a one-way flow-tuple, we
        # don't need to consider directionality further.  And, testing
        # directionality only makes sense when the ports are integers,
        # not lower-level NBO representations.  Throughout we need to
        # keep track of the types of the ports, since the ICMP logic
        # works only with regular ints.
        if self.is_one_way is False:
            if self.proto == PROTO_ICMP:
                sport, dport, self.is_one_way = icmp.get_port_equivalents(
                    self._port_to_int(sport), self._port_to_int(dport))
                self.sport = self._port_to_same(sport, self.sport)
                self.dport = self._port_to_same(dport, self.dport)
            elif self.proto == PROTO_ICMP6:
                sport, dport, self.is_one_way = icmp6.get_port_equivalents(
                    self._port_to_int(sport), self._port_to_int(dport))
                self.sport = self._port_to_same(sport, self.sport)
                self.dport = self._port_to_same(dport, self.dport)

    def __repr__(self):
        data = self.get_data()

        if data.sport is None or data.dport is None:
            return '[%s] %s -> %s' % (data.proto, data.saddr, data.daddr)

        return '[%s] %s/%s -> %s/%s' % (data.proto, data.saddr, data.sport,
                                        data.daddr, data.dport)

    def get_data(self):
        """
        Returns a FlowTuple.Data namedtuple with this flow tuple's
        data. The protocol is an integer number (e.g. 6 for TCP),
        saddr and daddr are ASCII-rendered/unpacked, and the ports
        are integers or None, if absent.
        """
        # Absent good types, make it best-effort to get these
        # renderable. If all characters are printable, we assume this
        # in not NBO.
        saddr, daddr, sport, dport = self.saddr, self.daddr, self.sport, self.dport

        if compat.have_real_bytes_type() and isinstance(saddr, bytes):
            saddr = self._addr_to_ascii(saddr)
        elif compat.is_ipaddress_type(saddr):
            saddr = saddr.exploded
        elif not all(c in string.printable for c in saddr):
            saddr = self._addr_to_ascii(saddr)

        if compat.have_real_bytes_type() and isinstance(daddr, bytes):
            daddr = self._addr_to_ascii(daddr)
        elif compat.is_ipaddress_type(daddr):
            daddr = daddr.exploded
        elif not all(c in string.printable for c in daddr):
            daddr = self._addr_to_ascii(daddr)

        if sport is not None and not isinstance(sport, int):
            sport = struct.unpack('!H', sport)[0]
        if dport is not None and not isinstance(dport, int):
            dport = struct.unpack('!H', dport)[0]

        return FlowTuple.Data(self.proto, saddr, daddr, sport, dport)

    def is_ordered(self):
        """
        Predicate, returns True when this flow tuple is ordered.

        A flow tuple is ordered when any of the following are true:

        - It's marked as a one-way flow.

        - Its source IP address is smaller than its dest IP address, both in
          network byte order (NBO).

        - The IP addresses are equal and the source port is smaller than the
          dest port, in NBO.
        """
        nbo = self.in_nbo()
        return (nbo.is_one_way or nbo.saddr < nbo.daddr or
                (nbo.saddr == nbo.daddr and
                 nbo.sport is not None and nbo.dport is not None and
                 nbo.sport < nbo.dport))

    def has_ports(self):
        """
        Predicate, returns True when this tuple features port numbers.
        """
        return self.sport is not None and self.dport is not None

    def in_order(self):
        """
        Returns a copy of this tuple that is ordered canonically. Ie, regardless
        of the src/dest IP addresses and ports, the returned tuple will be be
        the same: the source side will contain the smaller endpoint (see
        FlowTuple.is_ordered() for details).
        """
        if self.is_ordered():
            return FlowTuple(self.proto, self.saddr, self.daddr,
                             self.sport, self.dport, self.is_one_way)
        return FlowTuple(self.proto, self.daddr, self.saddr,
                         self.dport, self.sport, self.is_one_way)

    def in_nbo(self):
        """
        Returns a copy of this tuple where the addresses and port are
        rendered into NBO byte strings.
        """
        saddr = self._addr_to_nbo(self.saddr)
        daddr = self._addr_to_nbo(self.daddr)

        if isinstance(self.sport, int):
            sport = struct.pack('!H', self.sport)
        else:
            sport = self.sport

        if isinstance(self.dport, int):
            dport = struct.pack('!H', self.dport)
        else:
            dport = self.dport

        return FlowTuple(self.proto, saddr, daddr, sport, dport, self.is_one_way)

    @staticmethod
    def is_ipaddr(val):
        return (FlowTuple.addr_is_text(val) or
                FlowTuple.addr_is_packed(val) or
                FlowTuple.addr_is_ipaddress_type(val))

    @staticmethod
    def addr_is_text(addr):
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, addr)
                return True
            except (socket.error, TypeError):
                pass

        return False

    @staticmethod
    def addr_is_packed(addr):
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_ntop(family, addr)
                return True
            except (socket.error, ValueError, TypeError):
                pass

        return False

    @staticmethod
    def addr_is_ipaddress_type(addr):
        return compat.is_ipaddress_type(addr)

    @staticmethod
    def is_port(val):
        if isinstance(val, bytes):
            try:
                port = struct.unpack('!H', val)[0]
                return 0 <= port <= 65535
            except (struct.error, IndexError, TypeError):
                pass

        if isinstance(val, int):
            return 0 <= val <= 65535

        return False

    @staticmethod
    def _port_to_int(port):
        """Convert a port number to regular integer."""
        if isinstance(port, int):
            return port
        # Assume it's two bytes in NBO:
        return struct.unpack('!H', port)[0]

    @staticmethod
    def _port_to_nbo(port):
        """Convert a port number to 2-byte NBO."""
        if isinstance(port, int):
            return struct.pack('!H', port)
        # Assume it's two bytes in NBO
        return port

    @staticmethod
    def _port_to_same(port, sample):
        """Convert a port number to the same type as that of another instance."""
        if isinstance(sample, int):
            return FlowTuple._port_to_int(port)
        return FlowTuple._port_to_nbo(port)

    @staticmethod
    def _addr_to_ascii(addr):
        if compat.is_ipaddress_type(addr):
            return addr.exploded

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                return socket.inet_ntop(family, addr)
            except (socket.error, ValueError, TypeError):
                pass

        return addr

    @staticmethod
    def _addr_to_nbo(addr):
        if compat.is_ipaddress_type(addr):
            return addr.packed

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                return socket.inet_pton(family, addr)
            except (socket.error, TypeError):
                pass

        return addr

    # Convenience wrappers for making protocol-specific tuple instances.

    @classmethod
    def make_tcp(cls, saddr, daddr, sport, dport):
        return cls(PROTO_TCP, saddr, daddr, int(sport), int(dport))

    @classmethod
    def make_udp(cls, saddr, daddr, sport, dport):
        return cls(PROTO_UDP, saddr, daddr, int(sport), int(dport))

    @classmethod
    def make_sctp(cls, saddr, daddr, sport, dport):
        return cls(PROTO_SCTP, saddr, daddr, int(sport), int(dport))

    @classmethod
    def make_icmp(cls, saddr, daddr, mtype, mcode):
        return cls(PROTO_ICMP, saddr, daddr, int(mtype), int(mcode))

    @classmethod
    def make_icmp6(cls, saddr, daddr, mtype, mcode):
        return cls(PROTO_ICMP6, saddr, daddr, int(mtype), int(mcode))

    @classmethod
    def make_ip(cls, saddr, daddr, proto):
        return cls(proto, saddr, daddr)


class CommunityIDBase:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_error(self):
        """
        Error handler. After something fails during the ID computation,
        this method should return an explanation why.
        """
        return None

    @abc.abstractmethod
    def calc(self, tpl):
        """
        Entrypoint to the ID computation, given a FlowTuple instance.
        Returns a string containing the Community ID value, or None on
        error.
        """
        return None

    @abc.abstractmethod
    def hash(self, tpl):
        """
        The tuple-hashing part of the computation. Returns hashlib
        algorithm instance ready for digesting, or None on error.
        """
        return None

    @abc.abstractmethod
    def render(self, hashstate):
        """
        The rendering part of the computation. Receives a hashlib
        algorithm instance and returns a string containing the
        community ID value according to this instance's configuration,
        or None on error.
        """
        return None


class CommunityID(CommunityIDBase):
    """
    An algorithm object that computes Community IDs on FlowTuple instances.
    """
    def __init__(self, seed=0, use_base64=True):
        self._version = 1
        self._seed = seed
        self._use_base64 = use_base64
        self._err = None

    def __repr__(self):
        return 'CommunityID(v=%s,seed=%s,base64=%s)' \
            % (self._version, self._seed, self._use_base64)

    def get_error(self):
        """
        Returns an error string when problems came up during the
        computation. This is only valid directly after calc() returned
        None, i.e., something went wrong during the calculation.
        """
        return self._err

    def calc(self, tpl):
        """
        The biggie: given a FlowTuple instance, returns a string
        containing the Community ID. In case of problems, returns
        None. In that case consider get_error() to learn more about
        what happened.
        """
        tpl = tpl.in_nbo().in_order()
        return self.render(self.hash(tpl))

    def hash(self, tpl):
        hashstate = hashlib.sha1()

        def hash_update(data):
            # Handy for troubleshooting: shows exact byte sequence hashed
            #hexbytes = ':'.join('%02x' % ord(b) for b in data)
            #print('XXX %s' % hexbytes)
            hashstate.update(data)
            return len(data)

        try:
            dlen = hash_update(struct.pack('!H', self._seed)) # 2-byte seed
            dlen += hash_update(tpl.saddr) # 4 bytes (v4 addr) or 16 bytes (v6 addr)
            dlen += hash_update(tpl.daddr) # 4 bytes (v4 addr) or 16 bytes (v6 addr)
            dlen += hash_update(struct.pack('B', tpl.proto)) # 1 byte for transport proto
            dlen += hash_update(struct.pack('B', 0)) # 1 byte padding
            if tpl.has_ports():
                dlen += hash_update(tpl.sport) # 2 bytes
                dlen += hash_update(tpl.dport) # 2 bytes
        except struct.error as err:
            self._err = 'Could not pack flow tuple: %s' % err
            return None

        # The data structure we hash should always align on 32-bit
        # boundaries.
        if dlen % 4 != 0:
            self._err = 'Unexpected hash input length: %s' % dlen
            return None

        return hashstate

    def render(self, hashstate):
        if hashstate is None:
            return None

        # Unless the user disabled the feature, base64-encode the
        # (binary) hash digest. Otherwise, print the ASCII digest.
        if self._use_base64:
            return str(self._version) + ':' + base64.b64encode(hashstate.digest()).decode('ascii')

        return str(self._version) + ':' + hashstate.hexdigest()
