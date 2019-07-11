This package provides a Python implementation of the open
[Community ID](https://github.com/corelight/community-id-spec)
flow hashing standard.

It supports Python versions 2.7+ and 3+.

The API breaks the computation into two steps: (1) creation of a flow
tuple object, (2) computation of the Community ID string on this
object. It supports various input types in order to accommodate
network byte order representations of flow endpoints, high-level ASCII
representations, etc.

In practice, it looks e.g. as follows:

    import communityid

    cid = communityid.CommunityID()
    tpl = communityid.FlowTuple.make_tcp('127.0.0.1', '10.0.0.1', 1234, 80)

    print(cid.calc(tpl))

This will print "1:mgRgpIZSu0KHDp/QrtcWZpkJpMU=".

The package includes two sample applications:

- community-id-pcap, which iterates over a pcap via dpkt and renders
  Community ID values for each suitable packet in the trace. This
  exercices the package's "low-level" API, using flow tuple values as
  you'd encounter them in a typical network monitor.

- community-id-tcpdump, which takes tcpdump output on stdin and
  augments it with Community ID values on stdout. This exercices the
  package's "high-level" API, using ASCII representations of tuple
  values.

The package also contains a comprehensive testsuite that can serve as
reference values to verify the correctness of other
implementations. See the contents of the testing/ directory for
details.
