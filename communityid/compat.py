"""
Helpers to help deal with both Python 2 and 3.
"""
# Provide a way to determine whether an object is an instance of the
# newer IP address abstractions. This currently does not support the
# older Google ipaddr package.
try:
    import ipaddress

    def ip_address(addr):
        """Return IPv4Address/IPv6Address instance."""
        # To make this work with the Python 2 backport we need to
        # convert the input to Unicode, portably.
        # http://python-future.org/compatible_idioms.html#unicode
        return ipaddress.ip_address(u"%s" % addr)

    def is_ipaddress_type(obj):
        """
        Predicate, returns True if given object is an ipaddress-based
        address object.
        """
        return isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address))
except ImportError:
    def ip_address(_):
        raise RuntimeError('ipaddress module not available')

    def is_ipaddress_type(_):
        return False

def have_real_bytes_type():
    # These differ in Python 3, but are the same in Python 2
    return bytes != str
