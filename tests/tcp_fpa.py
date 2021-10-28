#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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

from testslide import TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.ip4.ps import IP4_PROTO_TCP
from pytcp.protocols.ip6.ps import IP6_NEXT_TCP
from pytcp.protocols.tcp.fpa import (
    TcpAssembler,
    TcpOptEol,
    TcpOptMss,
    TcpOptNop,
    TcpOptSackPerm,
    TcpOptTimestamp,
    TcpOptWscale,
)
from pytcp.protocols.tcp.ps import (
    TCP_HEADER_LEN,
    TCP_OPT_EOL_LEN,
    TCP_OPT_MSS_LEN,
    TCP_OPT_NOP_LEN,
    TCP_OPT_SACKPERM_LEN,
    TCP_OPT_TIMESTAMP_LEN,
    TCP_OPT_WSCALE_LEN,
)


class TestTcpAssembler(TestCase):
    def test_tcp_fpa__ip4_proto_tcp(self):
        """Test the ip4_proto property of TcpAssembler class"""

        self.assertEqual(TcpAssembler.ip4_proto, IP4_PROTO_TCP)

    def test_tcp_fpa__ip6_next_tcp(self):
        """Test the ip6_next property of TcpAssembler class"""

        self.assertEqual(TcpAssembler.ip6_next, IP6_NEXT_TCP)

    def test_tcp_fpa__assert_sport(self):
        """Test assertion for the sport"""

        TcpAssembler(sport=12345)

    def test_tcp_fpa__assert_sport__bellow(self):
        """Test assertion for the sport"""

        with self.assertRaises(AssertionError):
            TcpAssembler(sport=-1)

    def test_tcp_fpa__assert_sport__above(self):
        """Test assertion for the sport"""

        with self.assertRaises(AssertionError):
            TcpAssembler(sport=0x10000)

    def test_tcp_fpa__assert_dport(self):
        """Test assertion for the dport"""

        TcpAssembler(dport=12345)

    def test_tcp_fpa__assert_dport__bellow(self):
        """Test assertion for the dport"""

        with self.assertRaises(AssertionError):
            TcpAssembler(dport=-1)

    def test_tcp_fpa__assert_dport__above(self):
        """Test assertion for the dport"""

        with self.assertRaises(AssertionError):
            TcpAssembler(dport=0x10000)

    def test_tcp_fpa__assert_seq(self):
        """Test assertion for the seq"""

        TcpAssembler(seq=12345678)

    def test_tcp_fpa__assert_seq__bellow(self):
        """Test assertion for the seq"""

        with self.assertRaises(AssertionError):
            TcpAssembler(seq=-1)

    def test_tcp_fpa__assert_seq__above(self):
        """Test assertion for the seq"""

        with self.assertRaises(AssertionError):
            TcpAssembler(seq=0x100000000)

    def test_tcp_fpa__assert_ack(self):
        """Test assertion for the ack"""

        TcpAssembler(ack=87654321)

    def test_tcp_fpa__assert_ack__bellow(self):
        """Test assertion for the ack"""

        with self.assertRaises(AssertionError):
            TcpAssembler(seq=-1)

    def test_tcp_fpa__assert_ack__above(self):
        """Test assertion for the ack"""

        with self.assertRaises(AssertionError):
            TcpAssembler(ack=0x100000000)

    def test_tcp_fpa__assert_win(self):
        """Test assertion for the win"""

        TcpAssembler(win=12345)

    def test_tcp_fpa__assert_win__bellow(self):
        """Test assertion for the win"""

        with self.assertRaises(AssertionError):
            TcpAssembler(win=-1)

    def test_tcp_fpa__assert_win__above(self):
        """Test assertion for the win"""

        with self.assertRaises(AssertionError):
            TcpAssembler(win=0x10000)

    def test_tcp_fpa__assert_urp(self):
        """Test assertion for the urp"""

        TcpAssembler(urp=54321)

    def test_tcp_fpa__assert_urp__bellow(self):
        """Test assertion for the urp"""

        with self.assertRaises(AssertionError):
            TcpAssembler(urp=-1)

    def test_tcp_fpa__assert_urp__above(self):
        """Test assertion for the urp"""

        with self.assertRaises(AssertionError):
            TcpAssembler(win=0x10000)

    def test_tcp_fpa__constructor(self):
        """Test class constructor"""

        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_crw=True,
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

        self.assertEqual(packet._sport, 12345)
        self.assertEqual(packet._dport, 54321)
        self.assertEqual(packet._seq, 12345678)
        self.assertEqual(packet._ack, 87654321)
        self.assertEqual(packet._flag_ns, True)
        self.assertEqual(packet._flag_crw, True)
        self.assertEqual(packet._flag_ece, True)
        self.assertEqual(packet._flag_urg, True)
        self.assertEqual(packet._flag_ack, True)
        self.assertEqual(packet._flag_psh, True)
        self.assertEqual(packet._flag_rst, True)
        self.assertEqual(packet._flag_syn, True)
        self.assertEqual(packet._flag_fin, True)
        self.assertEqual(packet._win, 12345)
        self.assertEqual(packet._urp, 54321)
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
        self.assertEqual(packet._data, b"0123456789ABCDEF")
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_tcp_fpa__constructor__defaults(self):
        """Test class constructor"""

        packet = TcpAssembler()

        self.assertEqual(packet._sport, 0)
        self.assertEqual(packet._dport, 0)
        self.assertEqual(packet._seq, 0)
        self.assertEqual(packet._ack, 0)
        self.assertEqual(packet._flag_ns, False)
        self.assertEqual(packet._flag_crw, False)
        self.assertEqual(packet._flag_ece, False)
        self.assertEqual(packet._flag_urg, False)
        self.assertEqual(packet._flag_ack, False)
        self.assertEqual(packet._flag_psh, False)
        self.assertEqual(packet._flag_rst, False)
        self.assertEqual(packet._flag_syn, False)
        self.assertEqual(packet._flag_fin, False)
        self.assertEqual(packet._win, 0)
        self.assertEqual(packet._urp, 0)
        self.assertEqual(packet._options, [])
        self.assertEqual(packet._data, b"")

    def test_tcp_fpa____len__(self):
        """Test class __len__ operator"""

        packet = TcpAssembler()

        self.assertEqual(len(packet), TCP_HEADER_LEN)

    def test_tcp_fpa____len____data(self):
        """Test class __len__ operator"""

        packet = TcpAssembler(
            data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), TCP_HEADER_LEN + 16)

    def test_tcp_fpa____len____opts(self):
        """Test class __len__ operator"""

        packet = TcpAssembler(
            options=[
                TcpOptWscale(0),
                TcpOptEol(),
            ]
        )

        self.assertEqual(len(packet), TCP_HEADER_LEN + TCP_OPT_WSCALE_LEN + TCP_OPT_EOL_LEN)

    def test_tcp_fpa____len____opts_data(self):
        """Test class __len__ operator"""

        packet = TcpAssembler(
            options=[
                TcpOptWscale(0),
                TcpOptEol(),
            ],
            data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), TCP_HEADER_LEN + TCP_OPT_WSCALE_LEN + TCP_OPT_EOL_LEN + 16)

    def test_tcp_fpa____str__(self):
        """Test class __str__ operator"""

        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_crw=True,
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
            "TCP 12345 > 54321, NCEUAPRSF, seq 12345678, ack 87654321, win 12345, dlen 16, "
            "mss 12345, wscale 12, sack_perm, ts 12345678/87654321, nop, nop, nop, nop, eol",
        )

    def test_tcp_fpa__tracker_getter(self):
        """Test tracker getter"""

        packet = TcpAssembler()
        self.assertTrue(repr(packet.tracker).startswith("Tracker(serial='<lr>TX"))

    def test_tcp_fpa___raw_options(self):
        """Test _raw_options getter"""

        packet = TcpAssembler(
            options=[TcpOptWscale(0), TcpOptEol()],
        )

        self.assertEqual(packet._raw_options, b"\x03\x03\x00\x00")

    def test_tcp_fpa__assemble(self):
        """Test assemble method"""

        packet = TcpAssembler(
            sport=12345,
            dport=54321,
            seq=12345678,
            ack=87654321,
            flag_ns=True,
            flag_crw=True,
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

        frame = memoryview(
            bytearray(
                TCP_HEADER_LEN
                + TCP_OPT_MSS_LEN
                + TCP_OPT_WSCALE_LEN
                + TCP_OPT_SACKPERM_LEN
                + TCP_OPT_TIMESTAMP_LEN
                + TCP_OPT_NOP_LEN
                + TCP_OPT_NOP_LEN
                + TCP_OPT_NOP_LEN
                + TCP_OPT_NOP_LEN
                + TCP_OPT_EOL_LEN
                + 16
            )
        )
        packet.assemble(frame, 0x12345678)
        self.assertEqual(
            bytes(frame),
            b"09\xd41\x00\xbcaN\x059\x7f\xb1\xb1\xff09\xe2|\xd41\x02\x0409\x03\x03\x0c\x04"
            b"\x02\x08\n\x00\xbcaN\x059\x7f\xb1\x01\x01\x01\x01\x000123456789ABCDEF",
        )


class TestTcpOptEol(TestCase):
    def test_tcp_opt_eol____str__(self):
        """Test the __str__ getter"""

        option = TcpOptEol()

        self.assertEqual(str(option), "eol")

    def test_tcp_opt_eol____repr__(self):
        """Test the __repr__ getter"""

        option = TcpOptEol()

        self.assertEqual(repr(option), "TcpOptEol()")

    def test_tcp_opt_eol____eq__(self):
        """Test the __eq__ getter"""

        option = TcpOptEol()

        self.assertEqual(option, option)

    def test_tcp_opt_eol__raw_option(self):
        """Test the raw_option getter"""

        option = TcpOptEol()

        self.assertEqual(option.raw_option, b"\x00")


class TestTcpOptNop(TestCase):
    def test_tcp_opt_nop____str__(self):
        """Test the __str__ getter"""

        option = TcpOptNop()

        self.assertEqual(str(option), "nop")

    def test_tcp_opt_nop____repr__(self):
        """Test the __repr__ getter"""

        option = TcpOptNop()

        self.assertEqual(repr(option), "TcpOptNop()")

    def test_tcp_opt_nop____eq__(self):
        """Test the __eq__ getter"""

        option = TcpOptNop()

    def test_tcp_opt_nop__raw_option(self):
        """Test the raw_option getter"""

        option = TcpOptNop()

        self.assertEqual(option.raw_option, b"\x01")
