import os
import socket
import struct
import sys
import unittest

try:
    import pylint.epylint
except ImportError:
    pass # Pity!

LOCAL_DIR=os.path.dirname(__file__)
sys.path.append(os.path.abspath(os.path.join(LOCAL_DIR, '..')))

import communityid
import communityid.compat

class TestCommunityID(unittest.TestCase):

    def setUp(self):
        self.cids = [
            communityid.CommunityID(),
            communityid.CommunityID(use_base64=False),
            communityid.CommunityID(seed=1),
        ]

    def assertEqualID(self, cft, correct_results):
        """
        Helper for ID string correctness assertion. cft is a
        communityid.FlowTyple.
        """
        # Create a list of tuples, each containing a CommunityID
        # instance as first member, and the expected result as the
        # second:
        cid_result_pairs = zip(self.cids, correct_results)

        for cid, correct_res in cid_result_pairs:
            res = cid.calc(cft)
            self.assertEqual(res, correct_res,
                             msg='%s: %s result is %s, should be %s, err: %s'
                             % (cid, cft, res, correct_res, cid.get_error()))

    def verify_tuples(self, tuples, high_level_func, proto_num, af_family):
        """
        Verifies for each of the provided flow tuples and expected
        Community ID strings that the computation produces the
        expected result, trying the various supported types for the
        flow tuple coordinates.
        """
        for tpl in tuples:
            # Using the convenience wrapper:
            cft = high_level_func(tpl[0], tpl[1], tpl[2], tpl[3])
            self.assertEqualID(cft, tpl[4:])

            # Using specific protocol number:
            cft = communityid.FlowTuple(proto_num, tpl[0], tpl[1], tpl[2], tpl[3])
            self.assertEqualID(cft, tpl[4:])

            # Using packed NBO, as when grabbing from a packet header:
            cft = communityid.FlowTuple(
                proto_num,
                socket.inet_pton(af_family, tpl[0]),
                socket.inet_pton(af_family, tpl[1]),
                struct.pack('!H', tpl[2]),
                struct.pack('!H', tpl[3]))
            self.assertEqualID(cft, tpl[4:])

            # Using a mix, ewww.
            cft = communityid.FlowTuple(
                proto_num,
                socket.inet_pton(af_family, tpl[0]),
                socket.inet_pton(af_family, tpl[1]),
                tpl[2], tpl[3])
            self.assertEqualID(cft, tpl[4:])

            # Using Python 3.3+'s ipaddress types or their 2.x
            # backport:
            try:
                cft = communityid.FlowTuple(
                    proto_num,
                    communityid.compat.ip_address(tpl[0]),
                    communityid.compat.ip_address(tpl[1]),
                    tpl[2], tpl[3])
                self.assertEqualID(cft, tpl[4:])
            except RuntimeError:
                pass

    # All of the following tests would be tidier with the DDT module,
    # but I'm reluctant to add third-party dependencies for
    # testing. --cpk

    def test_icmp(self):
        self.verify_tuples(
            [
                ['192.168.0.89', '192.168.0.1', 8, 0,
                 '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
                 '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
                 '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],

                ['192.168.0.1', '192.168.0.89', 0, 8,
                 '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
                 '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
                 '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],

                # This is correct: message type 20 (experimental) isn't
                # one we consider directional, so the message code ends up
                # in the hash computation, and thus two different IDs result:
                ['192.168.0.89', '192.168.0.1', 20, 0,
                 '1:3o2RFccXzUgjl7zDpqmY7yJi8rI=',
                 '1:de8d9115c717cd482397bcc3a6a998ef2262f2b2',
                 '1:lCXHHxavE1Vq3oX9NH5ladQg02o='],

                ['192.168.0.89', '192.168.0.1', 20, 1,
                 '1:tz/fHIDUHs19NkixVVoOZywde+I=',
                 '1:b73fdf1c80d41ecd7d3648b1555a0e672c1d7be2',
                 '1:Ie3wmFyxiEyikbsbcO03d2nh+PM='],

                # Therefore the following does _not_ get treated as the
                # reverse direction, but _does_ get treated the same as
                # the first two tuples, because for message type 0 the
                # code is currently ignored.
                ['192.168.0.1', '192.168.0.89', 0, 20,
                 '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
                 '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
                 '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],
            ],
            communityid.FlowTuple.make_icmp,
            communityid.PROTO_ICMP,
            socket.AF_INET)

    def test_icmp6(self):
        self.verify_tuples(
            [
                ['fe80::200:86ff:fe05:80da', 'fe80::260:97ff:fe07:69ea', 135, 0,
                 '1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
                 '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
                 '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY='],

                ['fe80::260:97ff:fe07:69ea', 'fe80::200:86ff:fe05:80da', 136, 0,
                 '1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
                 '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
                 '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY='],

                ['3ffe:507:0:1:260:97ff:fe07:69ea', '3ffe:507:0:1:200:86ff:fe05:80da', 3, 0,
                 '1:NdobDX8PQNJbAyfkWxhtL2Pqp5w=',
                 '1:35da1b0d7f0f40d25b0327e45b186d2f63eaa79c',
                 '1:OlOWx9psIbBFi7lOCw/4MhlKR9M='],

                ['3ffe:507:0:1:200:86ff:fe05:80da', '3ffe:507:0:1:260:97ff:fe07:69ea', 3, 0,
                 '1:/OGBt9BN1ofenrmSPWYicpij2Vc=',
                 '1:fce181b7d04dd687de9eb9923d66227298a3d957',
                 '1:Ij4ZxnC87/MXzhOjvH2vHu7LRmE='],
            ],
            communityid.FlowTuple.make_icmp6,
            communityid.PROTO_ICMP6,
            socket.AF_INET6)

    def test_sctp(self):
        self.verify_tuples(
            [
                ['192.168.170.8', '192.168.170.56', 7, 80,
                 '1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
                 '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
                 '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU='],

                ['192.168.170.56', '192.168.170.8', 80, 7,
                 '1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
                 '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
                 '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU='],
            ],
            communityid.FlowTuple.make_sctp,
            communityid.PROTO_SCTP,
            socket.AF_INET)

    def test_tcp(self):
        self.verify_tuples(
            [
                ['128.232.110.120', '66.35.250.204', 34855, 80,
                 '1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
                 '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
                 '1:3V71V58M3Ksw/yuFALMcW0LAHvc='],

                ['66.35.250.204', '128.232.110.120', 80, 34855,
                 '1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
                 '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
                 '1:3V71V58M3Ksw/yuFALMcW0LAHvc='],
            ],
            communityid.FlowTuple.make_tcp,
            communityid.PROTO_TCP,
            socket.AF_INET)

    def test_udp(self):
        self.verify_tuples(
            [
                ['192.168.1.52', '8.8.8.8', 54585, 53,
                 '1:d/FP5EW3wiY1vCndhwleRRKHowQ=',
                 '1:77f14fe445b7c22635bc29dd87095e451287a304',
                 '1:Q9We8WO3piVF8yEQBNJF4uiSVrI='],

                ['8.8.8.8', '192.168.1.52', 53, 54585,
                 '1:d/FP5EW3wiY1vCndhwleRRKHowQ=',
                 '1:77f14fe445b7c22635bc29dd87095e451287a304',
                 '1:Q9We8WO3piVF8yEQBNJF4uiSVrI='],
            ],
            communityid.FlowTuple.make_udp,
            communityid.PROTO_UDP,
            socket.AF_INET)


class LintCommunityID(unittest.TestCase):

    def setUp(self):
        if 'pylint.epylint' not in sys.modules:
            self.skipTest('pylint module not available')

    def test_linting(self):
        rcfile = os.path.join(LOCAL_DIR, 'pylint.rc')
        (out, _) = pylint.epylint.py_run('communityid --rcfile=' + rcfile, return_std=True)

        for line in out.getvalue().splitlines():
            if line.find('Your code has been') > 0:
                print('\n' + line.strip())
                break

        self.assertTrue(out.getvalue().find(' error ') < 0,
                        msg='Pylint error: ' + out.getvalue())
