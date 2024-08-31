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
This module contains tests for the IPv4 packet assembler operation.

tests/unit/protocols/ip4/test__ip4__assembler__operation.py

ver 3.0.0
"""

from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip4_address import Ip4Address
from pytcp.protocols.ip4.ip4__assembler import Ip4Assembler, Ip4FragAssembler
from pytcp.protocols.ip4.ip4__enums import Ip4Proto
from pytcp.protocols.ip4.ip4__header import Ip4Header
from pytcp.protocols.ip4.options.ip4_option__nop import Ip4OptionNop
from pytcp.protocols.ip4.options.ip4_options import Ip4Options
from pytcp.protocols.raw.raw__assembler import RawAssembler


@parameterized_class(
    [
        {
            "_description": "The IPv4 packet (I).",
            "_args": {
                "ip4__src": Ip4Address("10.20.30.40"),
                "ip4__dst": Ip4Address("50.60.70.80"),
                "ip4__ttl": 255,
                "ip4__dscp": 63,
                "ip4__ecn": 3,
                "ip4__id": 65535,
                "ip4__flag_df": True,
                "ip4__options": Ip4Options(),
                "ip4__payload": RawAssembler(),
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "IPv4 10.20.30.40 > 50.60.70.80, proto 255 (Raw), id 65535, DF, offset 0, "
                    "ttl 255, len 20 (20+0+0)"
                ),
                "__repr__": (
                    "Ip4Assembler(header=Ip4Header(hlen=20, dscp=63, ecn=3, plen=20, "
                    "id=65535, flag_df=True, flag_mf=False, offset=0, ttl=255, proto=<Ip4Proto.RAW: 255>, "
                    "cksum=0, src=Ip4Address('10.20.30.40'), dst=Ip4Address('50.60.70.80')), "
                    "options=Ip4Options(options=[]), payload=RawAssembler(raw__payload=b''))"
                ),
                "__bytes__": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
                "ver": 4,
                "hlen": 20,
                "dscp": 63,
                "ecn": 3,
                "plen": 20,
                "id": 65535,
                "flag_df": True,
                "flag_mf": False,
                "offset": 0,
                "ttl": 255,
                "proto": Ip4Proto.RAW,
                "cksum": 0,
                "src": Ip4Address("10.20.30.40"),
                "dst": Ip4Address("50.60.70.80"),
                "header": Ip4Header(
                    hlen=20,
                    dscp=63,
                    ecn=3,
                    plen=20,
                    id=65535,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=0,
                    src=Ip4Address("10.20.30.40"),
                    dst=Ip4Address("50.60.70.80"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(),
            },
        },
        {
            "_description": "The IPv4 packet (II).",
            "_args": {
                "ip4__src": Ip4Address("1.2.3.4"),
                "ip4__dst": Ip4Address("5.6.7.8"),
                "ip4__ttl": 255,
                "ip4__dscp": 17,
                "ip4__ecn": 2,
                "ip4__id": 12345,
                "ip4__flag_df": True,
                "ip4__options": Ip4Options(),
                "ip4__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 36,
                "__str__": (
                    "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (Raw), id 12345, DF, offset 0, ttl 255, len 36 (20+0+16)"
                ),
                "__repr__": (
                    "Ip4Assembler(header=Ip4Header(hlen=20, dscp=17, ecn=2, plen=36, "
                    "id=12345, flag_df=True, flag_mf=False, offset=0, ttl=255, proto=<Ip4Proto.RAW: 255>, "
                    "cksum=0, src=Ip4Address('1.2.3.4'), dst=Ip4Address('5.6.7.8')), "
                    "options=Ip4Options(options=[]), payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "ver": 4,
                "hlen": 20,
                "dscp": 17,
                "ecn": 2,
                "plen": 36,
                "id": 12345,
                "flag_df": True,
                "flag_mf": False,
                "offset": 0,
                "ttl": 255,
                "proto": Ip4Proto.RAW,
                "cksum": 0,
                "src": Ip4Address("1.2.3.4"),
                "dst": Ip4Address("5.6.7.8"),
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=36,
                    id=12345,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=0,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "The IPv4 packet (III).",
            "_args": {
                "ip4__src": Ip4Address("1.1.1.1"),
                "ip4__dst": Ip4Address("2.2.2.2"),
                "ip4__ttl": 64,
                "ip4__dscp": 8,
                "ip4__ecn": 0,
                "ip4__id": 21212,
                "ip4__flag_df": False,
                "ip4__options": Ip4Options(
                    *([Ip4OptionNop()] * 40),
                ),
                "ip4__payload": RawAssembler(raw__payload=b"X" * 65475),
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "IPv4 1.1.1.1 > 2.2.2.2, proto 255 (Raw), id 21212, offset 0, ttl 64, len 65535 "
                    "(20+40+65475), opts [nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "Ip4Assembler(header=Ip4Header(hlen=60, dscp=8, ecn=0, plen=65535, id=21212, "
                    "flag_df=False, flag_mf=False, offset=0, ttl=64, proto=<Ip4Proto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('1.1.1.1'), dst=Ip4Address('2.2.2.2')), options=Ip4Options(options=["
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop()]), "
                    f"payload=RawAssembler(raw__payload=b'{"X" * 65475}'))"
                ),
                "__bytes__": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea\x01\x01\x01\x01"
                    b"\x02\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    + b"X" * 65475
                ),
                "ver": 4,
                "hlen": 60,
                "dscp": 8,
                "ecn": 0,
                "plen": 65535,
                "id": 21212,
                "flag_df": False,
                "flag_mf": False,
                "offset": 0,
                "ttl": 64,
                "proto": Ip4Proto.RAW,
                "cksum": 0,
                "src": Ip4Address("1.1.1.1"),
                "dst": Ip4Address("2.2.2.2"),
                "header": Ip4Header(
                    hlen=60,
                    dscp=8,
                    ecn=0,
                    plen=65535,
                    id=21212,
                    flag_df=False,
                    flag_mf=False,
                    offset=0,
                    ttl=64,
                    proto=Ip4Proto.RAW,
                    cksum=0,
                    src=Ip4Address("1.1.1.1"),
                    dst=Ip4Address("2.2.2.2"),
                ),
                "options": Ip4Options(
                    *([Ip4OptionNop()] * 40),
                ),
                "payload": RawAssembler(raw__payload=b"X" * 65475),
            },
        },
    ]
)
class TestIp4AssemblerOperation(TestCase):
    """
    The IPv4 packet assembler operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 packet assembler object with testcase arguments.
        """

        self._ip4__assembler = Ip4Assembler(**self._args)

    def test__ip4__assembler__len(self) -> None:
        """
        Ensure the IPv4 packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._ip4__assembler),
            self._results["__len__"],
        )

    def test__ip4__assembler__str(self) -> None:
        """
        Ensure the IPv4 packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._ip4__assembler),
            self._results["__str__"],
        )

    def test__ip4__assembler__repr(self) -> None:
        """
        Ensure the IPv4 packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._ip4__assembler),
            self._results["__repr__"],
        )

    def test__ip4__assembler__bytes(self) -> None:
        """
        Ensure the IPv4 packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._ip4__assembler),
            self._results["__bytes__"],
        )

    def test__ip4__assembler__ver(self) -> None:
        """
        Ensure the IPv4 packet assembler 'ver' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.ver,
            self._results["ver"],
        )

    def test__ip4__assembler__hlen(self) -> None:
        """
        Ensure the IPv4 packet assembler 'hlen' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.hlen,
            self._results["hlen"],
        )

    def test__ip4__assembler__dscp(self) -> None:
        """
        Ensure the IPv4 packet assembler 'dscp' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.dscp,
            self._results["dscp"],
        )

    def test__ip4__assembler__ecn(self) -> None:
        """
        Ensure the IPv4 packet assembler 'ecn' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.ecn,
            self._results["ecn"],
        )

    def test__ip4__assembler__plen(self) -> None:
        """
        Ensure the IPv4 packet assembler 'plen' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.plen,
            self._results["plen"],
        )

    def test__ip4__assembler__id(self) -> None:
        """
        Ensure the IPv4 packet assembler 'id' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.id,
            self._results["id"],
        )

    def test__ip4__assembler__flag_df(self) -> None:
        """
        Ensure the IPv4 packet assembler 'flag_df' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.flag_df,
            self._results["flag_df"],
        )

    def test__ip4__assembler__flag_mf(self) -> None:
        """
        Ensure the IPv4 packet assembler 'flag_mf' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.flag_mf,
            self._results["flag_mf"],
        )

    def test__ip4__assembler__offset(self) -> None:
        """
        Ensure the IPv4 packet assembler 'offset' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.offset,
            self._results["offset"],
        )

    def test__ip4__assembler__ttl(self) -> None:
        """
        Ensure the IPv4 packet assembler 'ttl' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.ttl,
            self._results["ttl"],
        )

    def test__ip4__assembler__proto(self) -> None:
        """
        Ensure the IPv4 packet assembler 'proto' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.proto,
            self._results["proto"],
        )

    def test__ip4__assembler__cksum(self) -> None:
        """
        Ensure the IPv4 packet assembler 'cksum' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.cksum,
            self._results["cksum"],
        )

    def test__ip4__assembler__src(self) -> None:
        """
        Ensure the IPv4 packet assembler 'src' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.src,
            self._results["src"],
        )

    def test__ip4__assembler__dst(self) -> None:
        """
        Ensure the IPv4 packet assembler 'dst' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.dst,
            self._results["dst"],
        )

    def test__ip4__assembler__header(self) -> None:
        """
        Ensure the IPv4 packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.header,
            self._results["header"],
        )

    def test__ip4__assembler__options(self) -> None:
        """
        Ensure the IPv4 packet assembler 'options' property returns a correct
        value.

        """

        self.assertEqual(
            self._ip4__assembler.options,
            self._results["options"],
        )

    def test__ip4__assembler__payload(self) -> None:
        """
        Ensure the IPv4 packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4__assembler.payload,
            self._results["payload"],
        )


@parameterized_class(
    [
        {
            "_description": "The IPv4 (Frag) packet (IV).",
            "_args": {
                "ip4_frag__src": Ip4Address("4.3.2.1"),
                "ip4_frag__dst": Ip4Address("8.7.6.5"),
                "ip4_frag__ttl": 128,
                "ip4_frag__dscp": 10,
                "ip4_frag__ecn": 1,
                "ip4_frag__id": 54321,
                "ip4_frag__flag_mf": False,
                "ip4_frag__offset": 32008,
                "ip4_frag__options": Ip4Options(),
                "ip4_frag__payload": RawAssembler(
                    raw__payload=b"0123456789ABCDEF"
                ),
            },
            "_header_bytes": (
                b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x00\x00\x04\x03\x02\x01"
                b"\x08\x07\x06\x05"
            ),
            "_results": {
                "__len__": 36,
                "__str__": (
                    "IPv4 4.3.2.1 > 8.7.6.5, proto 255 (Raw), id 54321, offset 32008, "
                    "ttl 128, len 36 (20+0+16)"
                ),
                "__repr__": (
                    "Ip4FragAssembler(header=Ip4Header(hlen=20, dscp=10, ecn=1, plen=36, "
                    "id=54321, flag_df=False, flag_mf=False, offset=32008, ttl=128, proto=<Ip4Proto"
                    ".RAW: 255>, cksum=0, src=Ip4Address('4.3.2.1'), dst=Ip4Address('8.7.6.5')), "
                    "options=Ip4Options(options=[]), payload=RawAssembler(raw__payload="
                    "b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0\x04\x03\x02\x01"
                    b"\x08\x07\x06\x05\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "ver": 4,
                "hlen": 20,
                "dscp": 10,
                "ecn": 1,
                "plen": 36,
                "id": 54321,
                "flag_df": False,
                "flag_mf": False,
                "offset": 32008,
                "ttl": 128,
                "proto": Ip4Proto.RAW,
                "cksum": 0,
                "src": Ip4Address("4.3.2.1"),
                "dst": Ip4Address("8.7.6.5"),
                "header": Ip4Header(
                    hlen=20,
                    dscp=10,
                    ecn=1,
                    plen=36,
                    id=54321,
                    flag_df=False,
                    flag_mf=False,
                    offset=32008,
                    ttl=128,
                    proto=Ip4Proto.RAW,
                    cksum=0,
                    src=Ip4Address("4.3.2.1"),
                    dst=Ip4Address("8.7.6.5"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "The IPv4 (Frag) packet (V).",
            "_args": {
                "ip4_frag__src": Ip4Address("1.2.3.4"),
                "ip4_frag__dst": Ip4Address("5.6.7.8"),
                "ip4_frag__ttl": 255,
                "ip4_frag__dscp": 17,
                "ip4_frag__ecn": 2,
                "ip4_frag__id": 12345,
                "ip4_frag__flag_mf": True,
                "ip4_frag__offset": 0,
                "ip4_frag__options": Ip4Options(),
                "ip4_frag__payload": RawAssembler(raw__payload=b"X" * 1466),
            },
            "_header_bytes": (
                b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x00\x00\x01\x02\x03\x04"
                b"\x05\x06\x07\x08"
            ),
            "_results": {
                "__len__": 1486,
                "__str__": (
                    "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (Raw), id 12345, MF, offset 0, ttl 255, "
                    "len 1486 (20+0+1466)"
                ),
                "__repr__": (
                    "Ip4FragAssembler(header=Ip4Header(hlen=20, dscp=17, ecn=2, plen=1486, "
                    "id=12345, flag_df=False, flag_mf=True, offset=0, ttl=255, proto=<Ip4Proto.RAW: 255>, "
                    "cksum=0, src=Ip4Address('1.2.3.4'), dst=Ip4Address('5.6.7.8')), "
                    f"options=Ip4Options(options=[]), payload=RawAssembler(raw__payload=b'{"X" * 1466}'))"
                ),
                "__bytes__": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08" + b"X" * 1466
                ),
                "ver": 4,
                "hlen": 20,
                "dscp": 17,
                "ecn": 2,
                "plen": 1486,
                "id": 12345,
                "flag_df": False,
                "flag_mf": True,
                "offset": 0,
                "ttl": 255,
                "proto": Ip4Proto.RAW,
                "cksum": 0,
                "src": Ip4Address("1.2.3.4"),
                "dst": Ip4Address("5.6.7.8"),
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=1486,
                    id=12345,
                    flag_df=False,
                    flag_mf=True,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=0,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(raw__payload=b"X" * 1466),
            },
        },
    ]
)
class TestIp4FragAssemblerOperation(TestCase):
    """
    The IPv4 (Frag) packet assembler operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 (Frag) packet assembler object with testcase arguments.
        """

        self._ip4_frag__assembler = Ip4FragAssembler(**self._args)

    def test__ip4_frag__assembler__len(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._ip4_frag__assembler),
            self._results["__len__"],
        )

    def test__ip4_frag__assembler__str(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._ip4_frag__assembler),
            self._results["__str__"],
        )

    def test__ip4_frag__assembler__repr(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._ip4_frag__assembler),
            self._results["__repr__"],
        )

    def test__ip4_frag__assembler__bytes(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_frag__assembler),
            self._results["__bytes__"],
        )

    def test__ip4_frag__assembler__ver(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'ver' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.ver,
            self._results["ver"],
        )

    def test__ip4_frag__assembler__hlen(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'hlen' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.hlen,
            self._results["hlen"],
        )

    def test__ip4_frag__assembler__dscp(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'dscp' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.dscp,
            self._results["dscp"],
        )

    def test__ip4_frag__assembler__ecn(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'ecn' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.ecn,
            self._results["ecn"],
        )

    def test__ip4_frag__assembler__plen(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'plen' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.plen,
            self._results["plen"],
        )

    def test__ip4_frag__assembler__id(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'id' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.id,
            self._results["id"],
        )

    def test__ip4_frag__assembler__flag_df(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'flag_df' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.flag_df,
            self._results["flag_df"],
        )

    def test__ip4_frag__assembler__flag_mf(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'flag_mf' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.flag_mf,
            self._results["flag_mf"],
        )

    def test__ip4_frag__assembler__offset(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'offset' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.offset,
            self._results["offset"],
        )

    def test__ip4_frag__assembler__ttl(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'ttl' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.ttl,
            self._results["ttl"],
        )

    def test__ip4_frag__assembler__proto(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'proto' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.proto,
            self._results["proto"],
        )

    def test__ip4_frag__assembler__cksum(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'cksum' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.cksum,
            self._results["cksum"],
        )

    def test__ip4_frag__assembler__src(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'src' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.src,
            self._results["src"],
        )

    def test__ip4_frag__assembler__dst(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'dst' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.dst,
            self._results["dst"],
        )

    def test__ip4_frag__assembler__header(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'header' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.header,
            self._results["header"],
        )

    def test__ip4_frag__assembler__options(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'options' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.options,
            self._results["options"],
        )

    def test__ip4_frag__assembler__payload(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler 'payload' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_frag__assembler.payload,
            self._results["payload"],
        )
