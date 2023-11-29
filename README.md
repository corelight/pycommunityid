pycommunityid
=============

This package provides a Python implementation of the open
[Community ID](https://github.com/corelight/community-id-spec)
flow hashing standard.

It supports Python versions 2.7+ (for not much longer) and 3+.

![example foobar](https://github.com/corelight/pycommunityid/actions/workflows/python.yaml/badge.svg)

Installation
------------

This package is available [on PyPI](https://pypi.org/project/communityid/), therefore:

    pip install communityid

To install locally from a git clone, you can use also use pip, e.g. by saying

    pip install -U .

Usage
-----

The API breaks the computation into two steps: (1) creation of a flow
tuple object, (2) computation of the Community ID string on this
object. It supports various input types in order to accommodate
network byte order representations of flow endpoints, high-level ASCII,
and ipaddress objects.

Here's what it looks like:

    import communityid

    cid = communityid.CommunityID()
    tpl = communityid.FlowTuple.make_tcp('127.0.0.1', '10.0.0.1', 1234, 80)

    print(cid.calc(tpl))

This will print "1:mgRgpIZSu0KHDp/QrtcWZpkJpMU=".

The package includes three sample applications:

- [community-id](https://github.com/corelight/pycommunityid/blob/master/scripts/community-id),
  which calculates the ID directly for given flow tuples. It supports
  a small but growing list of parsers. Example:

      $ community-id tcp 10.0.0.1 10.0.0.2 10 20
      1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=

- [community-id-pcap](https://github.com/corelight/pycommunityid/blob/master/scripts/community-id-pcap),
  which iterates over a pcap via dpkt and renders
  Community ID values for each suitable packet in the trace. This
  exercices the package's "low-level" API, using flow tuple values as
  you'd encounter them in a typical network monitor.

- [community-id-pcapfilter](https://github.com/corelight/pycommunityid/blob/master/scripts/community-id-pcapfilter),
  which iterates over a pcap via dpkt and produces a pcap of
  only those packets whose Community IDs have a specific value,
  filtering out all others.

- [community-id-tcpdump](https://github.com/corelight/pycommunityid/blob/master/scripts/community-id-tcpdump),
  which takes tcpdump output on stdin and
  augments it with Community ID values on stdout. This exercices the
  package's "high-level" API, using ASCII representations of tuple
  values.

Testing
-------

The package includes a unittest testsuite in the `tests` directory
that runs without installation of the module. After changing into that
folder you can invoke it e.g. via

    python -m unittest communityid_test

or

    nose2 -C --coverage ../communityid --coverage-report term-missing communityid_test

or by running `./communityid_test.py` directly.
