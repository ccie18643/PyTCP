#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains tests for the TCP protocol packet assembling functionality.

net_proto/tests/unit/protocols/tcp/test__tcp__assembler__operation.py

ver 3.0.4
"""


from typing import Any

from net_proto import TcpAssembler, TcpHeader, TcpOptionNop, TcpOptions, Tracker
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "TCP packet with no payload and no options (I).",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 12345,
                "tcp__dport": 54321,
                "tcp__seq": 123456789,
                "tcp__ack": 987654321,
                "tcp__flag_ns": True,
                "tcp__flag_cwr": True,
                "tcp__flag_ece": True,
                "tcp__flag_urg": True,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": True,
                "tcp__flag_fin": False,
                "tcp__win": 11111,
                "tcp__urg": 22222,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "TCP 12345 > 54321, NCEUAPS, seq 123456789, ack 987654321, "
                    "win 11111, urg 22222, len 20 (20+0+0)"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=12345, dport=54321, "
                    "seq=123456789, ack=987654321, hlen=20, flag_ns=True, flag_cwr=True, "
                    "flag_ece=True, flag_urg=True, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=True, flag_fin=False, win=11111, cksum=0, urg=22222), "
                    "options=TcpOptions(options=[]), payload=b'')"
                ),
                "__bytes__": (
                    b"\x30\x39\xd4\x31\x07\x5b\xcd\x15\x3a\xde\x68\xb1\x51\xfa\x2b\x67"
                    b"\xaf\x64\x56\xce"
                ),
                "sport": 12345,
                "dport": 54321,
                "seq": 123456789,
                "ack": 987654321,
                "hlen": 20,
                "flag_ns": True,
                "flag_cwr": True,
                "flag_ece": True,
                "flag_urg": True,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": True,
                "flag_fin": False,
                "win": 11111,
                "cksum": 0,
                "urg": 22222,
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=123456789,
                    ack=987654321,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=True,
                    flag_ece=True,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=True,
                    flag_fin=False,
                    win=11111,
                    cksum=0,
                    urg=22222,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with no payload and no options (II).",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 2222,
                "tcp__seq": 3333,
                "tcp__ack": 4444,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": True,
                "tcp__flag_psh": False,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": True,
                "tcp__win": 5555,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "TCP 1111 > 2222, AF, seq 3333, ack 4444, "
                    "win 5555, len 20 (20+0+0)"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=2222, "
                    "seq=3333, ack=4444, hlen=20, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=True, flag_psh=False, flag_rst=False, "
                    "flag_syn=False, flag_fin=True, win=5555, cksum=0, urg=0), "
                    "options=TcpOptions(options=[]), payload=b'')"
                ),
                "__bytes__": (
                    b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3"
                    b"\x6e\xd5\x00\x00"
                ),
                "sport": 1111,
                "dport": 2222,
                "seq": 3333,
                "ack": 4444,
                "hlen": 20,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": True,
                "flag_psh": False,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": True,
                "win": 5555,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=True,
                    win=5555,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with no payload and options.",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 12345,
                "tcp__dport": 54321,
                "tcp__seq": 0,
                "tcp__ack": 0,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": False,
                "tcp__flag_psh": False,
                "tcp__flag_rst": True,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 11111,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(
                    *([TcpOptionNop()] * 8),
                ),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 28,
                "__str__": (
                    "TCP 12345 > 54321, R, seq 0, ack 0, "
                    "win 11111, len 28 (20+8+0), opts [nop, nop, nop, nop, nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=12345, dport=54321, "
                    "seq=0, ack=0, hlen=28, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=False, flag_psh=False, flag_rst=True, "
                    "flag_syn=False, flag_fin=False, win=11111, cksum=0, urg=0), "
                    "options=TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop()]), payload=b'')"
                ),
                "__bytes__": (
                    b"\x30\x39\xd4\x31\x00\x00\x00\x00\x00\x00\x00\x00\x70\x04\x2b\x67"
                    b"\x5c\x25\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
                ),
                "sport": 12345,
                "dport": 54321,
                "seq": 0,
                "ack": 0,
                "hlen": 28,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": False,
                "flag_psh": False,
                "flag_rst": True,
                "flag_syn": False,
                "flag_fin": False,
                "win": 11111,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=0,
                    ack=0,
                    hlen=28,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=True,
                    flag_syn=False,
                    flag_fin=False,
                    win=11111,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(
                    *([TcpOptionNop()] * 8),
                ),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with payload and options, no flags.",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 65535,
                "tcp__dport": 65535,
                "tcp__seq": 4294967295,
                "tcp__ack": 4294967295,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": False,
                "tcp__flag_psh": False,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 65535,
                "tcp__urg": 65535,
                "tcp__options": TcpOptions(
                    *([TcpOptionNop()] * 4),
                ),
                "tcp__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 40,
                "__str__": (
                    "TCP 65535 > 65535, seq 4294967295, ack 4294967295, "
                    "win 65535, len 40 (20+4+16), opts [nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=65535, dport=65535, "
                    "seq=4294967295, ack=4294967295, hlen=24, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=False, flag_psh=False, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=65535, cksum=0, urg=65535), "
                    "options=TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop()]), payload=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x60\x00\xff\xff"
                    b"\xcf\x26\xff\xff\x01\x01\x01\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "sport": 65535,
                "dport": 65535,
                "seq": 4294967295,
                "ack": 4294967295,
                "hlen": 24,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": False,
                "flag_psh": False,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 65535,
                "cksum": 0,
                "urg": 65535,
                "header": TcpHeader(
                    sport=65535,
                    dport=65535,
                    seq=4294967295,
                    ack=4294967295,
                    hlen=24,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=65535,
                    cksum=0,
                    urg=65535,
                ),
                "options": TcpOptions(
                    *([TcpOptionNop()] * 4),
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "TCP packet with maximum payload size and no options.",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 2222,
                "tcp__seq": 3333,
                "tcp__ack": 4444,
                "tcp__flag_ns": True,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": True,
                "tcp__flag_urg": False,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 5555,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"X" * 65515,
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "TCP 1111 > 2222, NEAP, seq 3333, ack 4444, "
                    "win 5555, len 65535 (20+0+65515)"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=2222, "
                    "seq=3333, ack=4444, hlen=20, flag_ns=True, flag_cwr=False, "
                    "flag_ece=True, flag_urg=False, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=5555, cksum=0, urg=0), "
                    f"options=TcpOptions(options=[]), payload=b'{"X" * 65515}')"
                ),
                "__bytes__": (
                    b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x51\x58\x15\xb3"
                    b"\xb5\x2d\x00\x00" + b"X" * 65515
                ),
                "sport": 1111,
                "dport": 2222,
                "seq": 3333,
                "ack": 4444,
                "hlen": 20,
                "flag_ns": True,
                "flag_cwr": False,
                "flag_ece": True,
                "flag_urg": False,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 5555,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=False,
                    flag_ece=True,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=5555,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"X" * 65515,
            },
        },
        {
            "_description": "TCP packet with maximum payload size and maximum options.",
            "_args": [],
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 3333,
                "tcp__seq": 5555,
                "tcp__ack": 7777,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": True,
                "tcp__flag_ece": False,
                "tcp__flag_urg": True,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 0,
                "tcp__urg": 9999,
                "tcp__options": TcpOptions(
                    *([TcpOptionNop()] * 40),
                ),
                "tcp__payload": b"X" * 65475,
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "TCP 1111 > 3333, CUAP, seq 5555, ack 7777, "
                    "win 0, urg 9999, len 65535 (20+40+65475), opts ["
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=3333, "
                    "seq=5555, ack=7777, hlen=60, flag_ns=False, flag_cwr=True, "
                    "flag_ece=False, flag_urg=True, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=0, cksum=0, urg=9999), "
                    "options=TcpOptions(options=["
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop()"
                    f"]), payload=b'{"X" * 65475}')"
                ),
                "__bytes__": (
                    b"\x04\x57\x0d\x05\x00\x00\x15\xb3\x00\x00\x1e\x61\xf0\xb8\x00\x00"
                    b"\xbd\x39\x27\x0f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    + b"X" * 65475
                ),
                "sport": 1111,
                "dport": 3333,
                "seq": 5555,
                "ack": 7777,
                "hlen": 60,
                "flag_ns": False,
                "flag_cwr": True,
                "flag_ece": False,
                "flag_urg": True,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 0,
                "cksum": 0,
                "urg": 9999,
                "header": TcpHeader(
                    sport=1111,
                    dport=3333,
                    seq=5555,
                    ack=7777,
                    hlen=60,
                    flag_ns=False,
                    flag_cwr=True,
                    flag_ece=False,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=0,
                    cksum=0,
                    urg=9999,
                ),
                "options": TcpOptions(
                    *([TcpOptionNop()] * 40),
                ),
                "payload": b"X" * 65475,
            },
        },
    ],
)
class TestTcpAssemblerOperation(TestCase):
    """
    The TCP packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP packet assembler object with testcase arguments.
        """

        self._tcp__assembler = TcpAssembler(*self._args, **self._kwargs)

    def test__tcp__assembler__len(self) -> None:
        """
        Ensure the TCP packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._tcp__assembler),
            self._results["__len__"],
        )

    def test__tcp__assembler__str(self) -> None:
        """
        Ensure the TCP packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._tcp__assembler),
            self._results["__str__"],
        )

    def test__tcp__assembler__repr(self) -> None:
        """
        Ensure the TCP packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._tcp__assembler),
            self._results["__repr__"],
        )

    def test__tcp__assembler__bytes(self) -> None:
        """
        Ensure the TCP packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._tcp__assembler),
            self._results["__bytes__"],
        )

    def test__tcp__assembler__sport(self) -> None:
        """
        Ensure the TCP packet assembler 'sport' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.sport,
            self._results["sport"],
        )

    def test__tcp__assembler__dport(self) -> None:
        """
        Ensure the TCP packet assembler 'dport' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.dport,
            self._results["dport"],
        )

    def test__tcp__assembler__seq(self) -> None:
        """
        Ensure the TCP packet assembler 'seq' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.seq,
            self._results["seq"],
        )

    def test__tcp__assembler__ack(self) -> None:
        """
        Ensure the TCP packet assembler 'ack' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.ack,
            self._results["ack"],
        )

    def test__tcp__assembler__hlen(self) -> None:
        """
        Ensure the TCP packet assembler 'hlen' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.hlen,
            self._results["hlen"],
        )

    def test__tcp__assembler__flag_ns(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_ns' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_ns,
            self._results["flag_ns"],
        )

    def test__tcp__assembler__flag_cwr(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_cwr' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_cwr,
            self._results["flag_cwr"],
        )

    def test__tcp__assembler__flag_ece(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_ece' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_ece,
            self._results["flag_ece"],
        )

    def test__tcp__assembler__flag_urg(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_urg' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_urg,
            self._results["flag_urg"],
        )

    def test__tcp__assembler__flag_ack(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_ack' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_ack,
            self._results["flag_ack"],
        )

    def test__tcp__assembler__flag_psh(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_psh' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_psh,
            self._results["flag_psh"],
        )

    def test__tcp__assembler__flag_rst(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_rst' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_rst,
            self._results["flag_rst"],
        )

    def test__tcp__assembler__flag_syn(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_syn' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_syn,
            self._results["flag_syn"],
        )

    def test__tcp__assembler__flag_fin(self) -> None:
        """
        Ensure the TCP packet assembler 'flag_fin' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.flag_fin,
            self._results["flag_fin"],
        )

    def test__tcp__assembler__win(self) -> None:
        """
        Ensure the TCP packet assembler 'win' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.win,
            self._results["win"],
        )

    def test__tcp__assembler__cksum(self) -> None:
        """
        Ensure the TCP packet assembler 'cksum' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.cksum,
            self._results["cksum"],
        )

    def test__tcp__assembler__urg(self) -> None:
        """
        Ensure the TCP packet assembler 'urg' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.urg,
            self._results["urg"],
        )

    def test__tcp__assembler__header(self) -> None:
        """
        Ensure the TCP packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.header,
            self._results["header"],
        )

    def test__tcp__assembler__options(self) -> None:
        """
        Ensure the TCP packet assembler 'options' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.options,
            self._results["options"],
        )

    def test__tcp__assembler__payload(self) -> None:
        """
        Ensure the TCP packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._tcp__assembler.payload,
            self._results["payload"],
        )


class TestTcpAssemblerMisc(TestCase):
    """
    The TCP packet assembler miscellaneous functions tests.
    """

    def test__tcp__assembler__echo_tracker(self) -> None:
        """
        Ensure the TCP packet assembler 'tracker' property returns
        a correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        tcp__assembler = TcpAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            tcp__assembler.tracker.echo_tracker,
            echo_tracker,
        )
