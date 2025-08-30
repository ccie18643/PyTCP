#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/tcp_fpa.py -  tests specific for TCP fpa module
#
# ver 3.0.2
#

from testslide import TestCase

from net_proto.lib.tracker import Tracker
from pytcp.protocols.ip4.ip4__base import IP4_PROTO_TCP
from pytcp.protocols.ip6.ip6__base import IP6_NEXT_TCP
from pytcp.protocols.tcp.tcp__assembler import (
    TcpAssembler,
    TcpOptEol,
    TcpOptMss,
    TcpOptNop,
    TcpOptSackPerm,
    TcpOptTimestamp,
    TcpOptWscale,
)
from pytcp.protocols.tcp.tcp__base import (
    TCP_HEADER_LEN,
    TCP_OPT_EOL_LEN,
    TCP_OPT_WSCALE_LEN,
)


class TestTcpAssembler(TestCase):
    """
    TCP protocol assembler unit test class.
    """

    def test_tcp_fpa__ip4_proto_tcp(self) -> None:
        """
        Make sure the 'TcpAssembler' class has the proper
        'ip4_proto' value assigned.
        """
        self.assertEqual(TcpAssembler.ip4_proto, IP4_PROTO_TCP)

    def test_tcp_fpa__ip6_next_tcp(self) -> None:
        """
        Make sure the 'TcpAssembler' class has the proper
        'ip6_next' value assigned.
        """
        self.assertEqual(TcpAssembler.ip6_next, IP6_NEXT_TCP)

    def test_tcp_fpa____init__(self) -> None:
        """
        Test the class constructor.
        """
        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_cwr=True,
            flag_ece=True,
            flag_urg=True,
            flag_ack=True,
            flag_psh=True,
            flag_rst=True,
            flag_syn=True,
            flag_fin=True,
            win=12345,
            urp=54321,
            options=[
                TcpOptMss(12345),
                TcpOptWscale(12),
                TcpOptSackPerm(),
                TcpOptTimestamp(12345678, 87654321),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptEol(),
            ],
            data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )
        self.assertEqual(
            packet._sport,
            12345,
        )
        self.assertEqual(
            packet._dport,
            54321,
        )
        self.assertEqual(
            packet._seq,
            12345678,
        )
        self.assertEqual(
            packet._ack,
            87654321,
        )
        self.assertEqual(
            packet._flag_ns,
            True,
        )
        self.assertEqual(
            packet._flag_cwr,
            True,
        )
        self.assertEqual(
            packet._flag_ece,
            True,
        )
        self.assertEqual(
            packet._flag_urg,
            True,
        )
        self.assertEqual(
            packet._flag_ack,
            True,
        )
        self.assertEqual(
            packet._flag_psh,
            True,
        )
        self.assertEqual(
            packet._flag_rst,
            True,
        )
        self.assertEqual(
            packet._flag_syn,
            True,
        )
        self.assertEqual(
            packet._flag_fin,
            True,
        )
        self.assertEqual(
            packet._win,
            12345,
        )
        self.assertEqual(
            packet._urp,
            54321,
        )
        self.assertEqual(
            packet._options,
            [
                TcpOptMss(12345),
                TcpOptWscale(12),
                TcpOptSackPerm(),
                TcpOptTimestamp(12345678, 87654321),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptEol(),
            ],
        )
        self.assertEqual(
            packet._data,
            b"0123456789ABCDEF",
        )
        self.assertTrue(
            repr(packet.tracker._echo_tracker).startswith(
                "Tracker(serial='<lr>TX"
            )
        )

    def test_tcp_fpa____init____defaults(self) -> None:
        """
        Test class constructor with default arguments.
        """
        packet = TcpAssembler()
        self.assertEqual(
            packet._sport,
            0,
        )
        self.assertEqual(
            packet._dport,
            0,
        )
        self.assertEqual(
            packet._seq,
            0,
        )
        self.assertEqual(
            packet._ack,
            0,
        )
        self.assertEqual(
            packet._flag_ns,
            False,
        )
        self.assertEqual(
            packet._flag_cwr,
            False,
        )
        self.assertEqual(
            packet._flag_ece,
            False,
        )
        self.assertEqual(
            packet._flag_urg,
            False,
        )
        self.assertEqual(
            packet._flag_ack,
            False,
        )
        self.assertEqual(
            packet._flag_psh,
            False,
        )
        self.assertEqual(
            packet._flag_rst,
            False,
        )
        self.assertEqual(
            packet._flag_syn,
            False,
        )
        self.assertEqual(
            packet._flag_fin,
            False,
        )
        self.assertEqual(
            packet._win,
            0,
        )
        self.assertEqual(
            packet._urp,
            0,
        )
        self.assertEqual(
            packet._options,
            [],
        )
        self.assertEqual(
            packet._data,
            b"",
        )

    def test_tcp_fpa____init____assert_sport__under(self) -> None:
        """
        Test assertion for the 'sport' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(sport=-1)

    def test_tcp_fpa____init____assert_sport__over(self) -> None:
        """
        Test assertion for the 'sport' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(sport=0x10000)

    def test_tcp_fpa____init____assert_dport__under(self) -> None:
        """
        Test assertion for the 'dport' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(dport=-1)

    def test_tcp_fpa____init____assert_dport__over(self) -> None:
        """
        Test assertion for the 'dport' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(dport=0x10000)

    def test_tcp_fpa____init____assert_seq__under(self) -> None:
        """
        Test assertion for the 'seq' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(seq=-1)

    def test_tcp_fpa____init____assert_seq__over(self) -> None:
        """
        Test assertion for the 'seq' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(seq=0x100000000)

    def test_tcp_fpa____init____assert_ack__under(self) -> None:
        """
        Test assertion for the 'ack' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(seq=-1)

    def test_tcp_fpa____init____assert_ack__over(self) -> None:
        """Test assertion for the ack"""

        with self.assertRaises(AssertionError):
            TcpAssembler(ack=0x100000000)

    def test_tcp_fpa____init____assert_win__under(self) -> None:
        """
        Test assertion for the 'win' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(win=-1)

    def test_tcp_fpa____init____assert_win__over(self) -> None:
        """
        Test assertion for the 'win' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(win=0x10000)

    def test_tcp_fpa____init____assert_urp__under(self) -> None:
        """
        Test assertion for the 'urp' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(urp=-1)

    def test_tcp_fpa____init____assert_urp__over(self) -> None:
        """
        Test assertion for the 'urp' argument.
        """
        with self.assertRaises(AssertionError):
            TcpAssembler(win=0x10000)

    def test_tcp_fpa____len__(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = TcpAssembler()
        self.assertEqual(len(packet), TCP_HEADER_LEN)

    def test_tcp_fpa____len____data(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = TcpAssembler(
            data=b"0123456789ABCDEF",
        )
        self.assertEqual(len(packet), TCP_HEADER_LEN + 16)

    def test_tcp_fpa____len____opts(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = TcpAssembler(
            options=[
                TcpOptWscale(0),
                TcpOptEol(),
            ]
        )
        self.assertEqual(
            len(packet), TCP_HEADER_LEN + TCP_OPT_WSCALE_LEN + TCP_OPT_EOL_LEN
        )

    def test_tcp_fpa____len____opts_data(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = TcpAssembler(
            options=[
                TcpOptWscale(0),
                TcpOptEol(),
            ],
            data=b"0123456789ABCDEF",
        )
        self.assertEqual(
            len(packet),
            TCP_HEADER_LEN + TCP_OPT_WSCALE_LEN + TCP_OPT_EOL_LEN + 16,
        )

    def test_tcp_fpa____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_cwr=True,
            flag_ece=True,
            flag_urg=True,
            flag_ack=True,
            flag_psh=True,
            flag_rst=True,
            flag_syn=True,
            flag_fin=True,
            win=12345,
            urp=54321,
            options=[
                TcpOptMss(12345),
                TcpOptWscale(12),
                TcpOptSackPerm(),
                TcpOptTimestamp(12345678, 87654321),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptEol(),
            ],
            data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )
        self.assertEqual(
            str(packet),
            "TCP 12345 > 54321, NCEUAPRSF, seq 12345678, ack 87654321, "
            "win 12345, dlen 16, mss 12345, wscale 12, sack_perm, "
            "ts 12345678/87654321, nop, nop, nop, nop, eol",
        )

    def test_tcp_fpa__tracker_getter(self) -> None:
        """
        Test the 'tracker' property getter.
        """
        packet = TcpAssembler()
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_tcp_fpa___raw_options(self) -> None:
        """
        Test the 'options' argument.
        """
        packet = TcpAssembler(
            options=[TcpOptWscale(0), TcpOptEol()],
        )

        self.assertEqual(packet._raw_options, b"\x03\x03\x00\x00")

    def test_tcp_fpa__assemble(self) -> None:
        """
        Test the 'assemble' method.
        """
        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_cwr=True,
            flag_ece=True,
            flag_urg=True,
            flag_ack=True,
            flag_psh=True,
            flag_rst=True,
            flag_syn=True,
            flag_fin=True,
            win=12345,
            urp=54321,
            options=[
                TcpOptMss(12345),
                TcpOptWscale(12),
                TcpOptSackPerm(),
                TcpOptTimestamp(12345678, 87654321),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptNop(),
                TcpOptEol(),
            ],
            data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 0x12345678)
        self.assertEqual(
            bytes(frame),
            b"09\xd41\x00\xbcaN\x059\x7f\xb1\xb1\xff09\xe2|\xd41\x02"
            b"\x0409\x03\x03\x0c\x04\x02\x08\n\x00\xbcaN\x059\x7f\xb1"
            b"\x01\x01\x01\x01\x000123456789ABCDEF",
        )


class TestTcpOptEol(TestCase):
    def test_tcp_fpa_opt_eol____str__(self) -> None:
        """Test the __str__ dunder"""

        option = TcpOptEol()

        self.assertEqual(str(option), "eol")

    def test_tcp_fpa_opt_eol____repr__(self) -> None:
        """Test the __repr__ dunder"""

        option = TcpOptEol()

        self.assertEqual(repr(option), "TcpOptEol()")

    def test_tcp_fpa_opt_eol____bytes__(self) -> None:
        """Test the __bytes__ dunder"""

        option = TcpOptEol()

        self.assertEqual(bytes(option), b"\x00")

    def test_tcp_fpa_opt_eol____eq__(self) -> None:
        """Test the __eq__ dunder"""

        option = TcpOptEol()

        self.assertEqual(option, TcpOptEol())


class TestTcpOptNop(TestCase):
    def test_tcp_fpa_opt_nop____str__(self) -> None:
        """Test the __str__ dunder"""

        option = TcpOptNop()

        self.assertEqual(str(option), "nop")

    def test_tcp_fpa_opt_nop____repr__(self) -> None:
        """Test the __repr__ dunder"""

        option = TcpOptNop()

        self.assertEqual(repr(option), "TcpOptNop()")

    def test_tcp_fpa_opt_nop____bytes__(self) -> None:
        """Test the __bytes__ dunder"""

        option = TcpOptNop()

        self.assertEqual(bytes(option), b"\x01")

    def test_tcp_fpa_opt_nop____eq__(self) -> None:
        """Test the __eq__ dunder"""

        option = TcpOptNop()

        self.assertEqual(option, TcpOptNop())


class TestTcpOptMss(TestCase):
    """
    The TCP MSS option unit test class.
    """

    def test_tcp_fpa_opt_mss____init__(self) -> None:
        """
        Test class constructor.
        """
        option = TcpOptMss(12345)
        self.assertEqual(option._mss, 12345)

    def test_tcp_fpa_opt_mss____init____assert_mss__under(self) -> None:
        """
        Test assertion for the 'mss' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptMss(-1)

    def test_tcp_fpa_opt_mss____init____assert_mss__over(self) -> None:
        """
        Test assertion for the 'mss' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptMss(0x10000)

    def test_tcp_fpa_opt_mss____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        option = TcpOptMss(12345)
        self.assertEqual(str(option), "mss 12345")

    def test_tcp_fpa_opt_mss____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = TcpOptMss(12345)
        self.assertEqual(repr(option), "TcpOptMss(12345)")

    def test_tcp_fpa_opt_mss____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = TcpOptMss(12345)
        self.assertEqual(bytes(option), b"\x02\x0409")

    def test_tcp_fpa_opt_mss____eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        option = TcpOptMss(12345)
        self.assertEqual(option, TcpOptMss(12345))


class TestTcpOptWscale(TestCase):
    """
    The TCP WSCALE option unit test class.
    """

    def test_tcp_fpa_opt_wscale____init__(self) -> None:
        """
        Test class constructor.
        """
        option = TcpOptWscale(123)
        self.assertEqual(option._wscale, 123)

    def test_tcp_fpa_opt_wscale____init____assert_wscale__under(self) -> None:
        """
        Test assertion for the 'wscale' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptWscale(-1)

    def test_tcp_fpa_opt_wscale____init____assert_wscale__over(self) -> None:
        """
        Test assertion for the 'wscale' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptWscale(0x100)

    def test_tcp_fpa_opt_wscale____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        option = TcpOptWscale(123)
        self.assertEqual(str(option), "wscale 123")

    def test_tcp_fpa_opt_wscale____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = TcpOptWscale(123)
        self.assertEqual(repr(option), "TcpOptWscale(123)")

    def test_tcp_fpa_opt_wscale____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = TcpOptWscale(123)
        self.assertEqual(bytes(option), b"\x03\x03{")

    def test_tcp_fpa_opt_wscale____eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        option = TcpOptWscale(123)
        self.assertEqual(option, TcpOptWscale(123))


class TestTcpOptSackPerm(TestCase):
    """
    The TCP Sack Permit option unit test class.
    """

    def test_tcp_fpa_opt_sack_perm____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        option = TcpOptSackPerm()
        self.assertEqual(str(option), "sack_perm")

    def test_tcp_fpa_opt_sack_perm____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = TcpOptSackPerm()
        self.assertEqual(repr(option), "TcpOptSackPerm()")

    def test_tcp_fpa_opt_sack_perm____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = TcpOptSackPerm()
        self.assertEqual(bytes(option), b"\x04\x02")

    def test_tcp_fpa_opt_sack_perm____eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        option = TcpOptSackPerm()
        self.assertEqual(option, TcpOptSackPerm())


class TestTcpOptTimestamp(TestCase):
    """
    The TCP Timestamp option unit test class.
    """

    def test_tcp_fpa_opt_timestamp____init__(self) -> None:
        """
        Test class constructor.
        """
        option = TcpOptTimestamp(12345678, 87654321)
        self.assertEqual(option._tsval, 12345678)
        self.assertEqual(option._tsecr, 87654321)

    def test_tcp_fpa_opt_timestamp____init____assert_tsval__under(self) -> None:
        """
        Test assertion for the 'tsval' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptTimestamp(-1, 0)

    def test_tcp_fpa_opt_timestamp____init____assert_tsval__over(self) -> None:
        """
        Test assertion for the 'tsval' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptTimestamp(0x100000000, 0)

    def test_tcp_fpa_opt_timestamp____init____assert_tsecr__under(self) -> None:
        """
        Test assertion for the 'tsecr' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptTimestamp(0, -1)

    def test_tcp_fpa_opt_timestamp____init____assert_tsecr__over(self) -> None:
        """
        Test assertion for the 'tsecr' argument.
        """
        with self.assertRaises(AssertionError):
            TcpOptTimestamp(0, 0x100000000)

    def test_tcp_fpa_opt_timestamp____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        option = TcpOptTimestamp(12345678, 87654321)
        self.assertEqual(str(option), "ts 12345678/87654321")

    def test_tcp_fpa_opt_timestamp____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = TcpOptTimestamp(12345678, 87654321)
        self.assertEqual(repr(option), "TcpOptTimestamp(12345678, 87654321)")

    def test_tcp_fpa_opt_timestamp____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = TcpOptTimestamp(12345678, 87654321)
        self.assertEqual(bytes(option), b"\x08\n\x00\xbcaN\x059\x7f\xb1")

    def test_tcp_fpa_opt_timestamp____eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        option = TcpOptTimestamp(12345678, 87654321)
        self.assertEqual(option, TcpOptTimestamp(12345678, 87654321))
