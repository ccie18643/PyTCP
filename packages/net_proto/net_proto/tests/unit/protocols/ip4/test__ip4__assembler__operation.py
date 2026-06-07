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

net_proto/tests/unit/protocols/ip4/test__ip4__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, IpVersion
from net_proto import (
    Ip4Assembler,
    Ip4FragAssembler,
    Ip4Header,
    Ip4OptionNop,
    Ip4Options,
    IpProto,
    RawAssembler,
)
from net_proto.lib.buffer import Buffer
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IPv4 packet with no options and empty payload.",
            "_kwargs": {
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
                    "IPv4 10.20.30.40 > 50.60.70.80, proto Raw, id 65535, DF, offset 0, " "ttl 255, len 20 (20+0+0)"
                ),
                "__repr__": (
                    "Ip4Assembler("
                    "header=Ip4Header("
                    "hlen=20, dscp=63, ecn=3, plen=20, id=65535, "
                    "flag_df=True, flag_mf=False, offset=0, ttl=255, "
                    "proto=<IpProto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('10.20.30.40'), dst=Ip4Address('50.60.70.80'))"
                    ", options=Ip4Options(options=[])"
                    ", payload=RawAssembler(raw__payload=b''))"
                ),
                # IPv4 wire format (20 bytes, no options, no payload):
                #   Byte  0     : 0x45 -> ver=4, hlen=5*4=20
                #   Byte  1     : 0xff -> dscp=63<<2 | ecn=3
                #   Bytes 2-3   : 0x0014 -> plen=20
                #   Bytes 4-5   : 0xffff -> id=65535
                #   Bytes 6-7   : 0x4000 -> flag_df=1, flag_mf=0, offset=0
                #   Byte  8     : 0xff   -> ttl=255
                #   Byte  9     : 0xff   -> proto=IpProto.RAW(255)
                #   Bytes 10-11 : 0xd923 -> inet checksum
                #   Bytes 12-15 : 0x0a141e28 -> src 10.20.30.40
                #   Bytes 16-19 : 0x323c4650 -> dst 50.60.70.80
                "__bytes__": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
                "ver": IpVersion.IP4,
                "hlen": 20,
                "dscp": 63,
                "ecn": 3,
                "plen": 20,
                "id": 65535,
                "flag_df": True,
                "flag_mf": False,
                "offset": 0,
                "ttl": 255,
                "proto": IpProto.RAW,
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
                    proto=IpProto.RAW,
                    cksum=0,
                    src=Ip4Address("10.20.30.40"),
                    dst=Ip4Address("50.60.70.80"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(),
            },
        },
        {
            "_description": "IPv4 packet with no options and a 16-byte payload.",
            "_kwargs": {
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
                "__str__": ("IPv4 1.2.3.4 > 5.6.7.8, proto Raw, id 12345, DF, offset 0, " "ttl 255, len 36 (20+0+16)"),
                "__repr__": (
                    "Ip4Assembler("
                    "header=Ip4Header("
                    "hlen=20, dscp=17, ecn=2, plen=36, id=12345, "
                    "flag_df=True, flag_mf=False, offset=0, ttl=255, "
                    "proto=<IpProto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('1.2.3.4'), dst=Ip4Address('5.6.7.8'))"
                    ", options=Ip4Options(options=[])"
                    ", payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                # IPv4 wire format (36 bytes, no options, 16-byte payload):
                #   Byte  0     : 0x45 -> ver=4, hlen=20
                #   Byte  1     : 0x46 -> dscp=17<<2 | ecn=2
                #   Bytes 2-3   : 0x0024 -> plen=36 (20+0+16)
                #   Bytes 4-5   : 0x3039 -> id=12345
                #   Bytes 6-7   : 0x4000 -> DF=1, MF=0, offset=0
                #   Byte  8     : 0xff   -> ttl=255
                #   Byte  9     : 0xff   -> proto=RAW
                #   Bytes 10-11 : 0x3a48 -> inet checksum
                #   Bytes 12-15 : 0x01020304 -> src 1.2.3.4
                #   Bytes 16-19 : 0x05060708 -> dst 5.6.7.8
                #   Bytes 20-35 : b"0123456789ABCDEF" (ASCII payload)
                "__bytes__": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48"
                    b"\x01\x02\x03\x04\x05\x06\x07\x08"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "ver": IpVersion.IP4,
                "hlen": 20,
                "dscp": 17,
                "ecn": 2,
                "plen": 36,
                "id": 12345,
                "flag_df": True,
                "flag_mf": False,
                "offset": 0,
                "ttl": 255,
                "proto": IpProto.RAW,
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
                    proto=IpProto.RAW,
                    cksum=0,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "IPv4 packet at maximum plen (65535) with 40 Nop options.",
            "_kwargs": {
                "ip4__src": Ip4Address("1.1.1.1"),
                "ip4__dst": Ip4Address("2.2.2.2"),
                "ip4__ttl": 64,
                "ip4__dscp": 8,
                "ip4__ecn": 0,
                "ip4__id": 21212,
                "ip4__flag_df": False,
                "ip4__options": Ip4Options(*([Ip4OptionNop()] * 40)),
                "ip4__payload": RawAssembler(raw__payload=b"X" * 65475),
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "IPv4 1.1.1.1 > 2.2.2.2, proto Raw, id 21212, offset 0, ttl 64, "
                    "len 65535 (20+40+65475), opts [" + ", ".join(["nop"] * 40) + "]"
                ),
                "__repr__": (
                    "Ip4Assembler("
                    "header=Ip4Header("
                    "hlen=60, dscp=8, ecn=0, plen=65535, id=21212, "
                    "flag_df=False, flag_mf=False, offset=0, ttl=64, "
                    "proto=<IpProto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('1.1.1.1'), dst=Ip4Address('2.2.2.2'))"
                    ", options=Ip4Options(options=["
                    + ", ".join(["Ip4OptionNop()"] * 40)
                    + "])"
                    + f", payload=RawAssembler(raw__payload=b'{'X' * 65475}'))"
                ),
                # IPv4 wire format (65535 bytes; 20-byte header + 40-byte Nop
                # options block + 65475-byte payload):
                #   Byte  0     : 0x4f -> ver=4, hlen=15*4=60
                #   Byte  1     : 0x20 -> dscp=8<<2 | ecn=0
                #   Bytes 2-3   : 0xffff -> plen=65535
                #   Bytes 4-5   : 0x52dc -> id=21212
                #   Bytes 6-7   : 0x0000 -> no flags, offset=0
                #   Byte  8     : 0x40   -> ttl=64
                #   Byte  9     : 0xff   -> proto=RAW
                #   Bytes 10-11 : 0x02ea -> inet checksum
                #   Bytes 12-15 : 0x01010101 -> src 1.1.1.1
                #   Bytes 16-19 : 0x02020202 -> dst 2.2.2.2
                #   Bytes 20-59 : forty 0x01 bytes (40 Ip4OptionType.NOP)
                #   Bytes 60+   : 65475 bytes of 'X' payload
                "__bytes__": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea"
                    b"\x01\x01\x01\x01\x02\x02\x02\x02" + b"\x01" * 40 + b"X" * 65475
                ),
                "ver": IpVersion.IP4,
                "hlen": 60,
                "dscp": 8,
                "ecn": 0,
                "plen": 65535,
                "id": 21212,
                "flag_df": False,
                "flag_mf": False,
                "offset": 0,
                "ttl": 64,
                "proto": IpProto.RAW,
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
                    proto=IpProto.RAW,
                    cksum=0,
                    src=Ip4Address("1.1.1.1"),
                    dst=Ip4Address("2.2.2.2"),
                ),
                "options": Ip4Options(*([Ip4OptionNop()] * 40)),
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
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the IPv4 assembler from the parametrized kwargs.
        """

        self._ip4__assembler = Ip4Assembler(**self._kwargs)

    def test__ip4__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total packet length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            len(self._ip4__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip4__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            str(self._ip4__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip4__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            repr(self._ip4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip4__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            bytes(self._ip4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip4__assembler__ver(self) -> None:
        """
        Ensure the 'ver' property returns IpVersion.IP4.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.ver,
            self._results["ver"],
            msg=f"Unexpected 'ver' for case: {self._description}",
        )

    def test__ip4__assembler__hlen(self) -> None:
        """
        Ensure the 'hlen' property returns the header byte length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.hlen,
            self._results["hlen"],
            msg=f"Unexpected 'hlen' for case: {self._description}",
        )

    def test__ip4__assembler__dscp(self) -> None:
        """
        Ensure the 'dscp' property returns the provided DSCP value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.dscp,
            self._results["dscp"],
            msg=f"Unexpected 'dscp' for case: {self._description}",
        )

    def test__ip4__assembler__ecn(self) -> None:
        """
        Ensure the 'ecn' property returns the provided ECN value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.ecn,
            self._results["ecn"],
            msg=f"Unexpected 'ecn' for case: {self._description}",
        )

    def test__ip4__assembler__plen(self) -> None:
        """
        Ensure the 'plen' property returns the total packet length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.plen,
            self._results["plen"],
            msg=f"Unexpected 'plen' for case: {self._description}",
        )

    def test__ip4__assembler__id(self) -> None:
        """
        Ensure the 'id' property returns the provided identification.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.id,
            self._results["id"],
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__ip4__assembler__flag_df(self) -> None:
        """
        Ensure the 'flag_df' property returns the provided DF flag.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.flag_df,
            self._results["flag_df"],
            msg=f"Unexpected 'flag_df' for case: {self._description}",
        )

    def test__ip4__assembler__flag_mf(self) -> None:
        """
        Ensure the 'flag_mf' property returns False (Ip4Assembler pins
        MF to False because fragmentation is handled by Ip4FragAssembler).

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.flag_mf,
            self._results["flag_mf"],
            msg=f"Unexpected 'flag_mf' for case: {self._description}",
        )

    def test__ip4__assembler__offset(self) -> None:
        """
        Ensure the 'offset' property returns 0 (Ip4Assembler pins
        offset to 0 because fragmentation is handled by Ip4FragAssembler).

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.offset,
            self._results["offset"],
            msg=f"Unexpected 'offset' for case: {self._description}",
        )

    def test__ip4__assembler__ttl(self) -> None:
        """
        Ensure the 'ttl' property returns the provided TTL value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.ttl,
            self._results["ttl"],
            msg=f"Unexpected 'ttl' for case: {self._description}",
        )

    def test__ip4__assembler__proto(self) -> None:
        """
        Ensure the 'proto' property returns the IpProto derived from
        the provided payload type.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.proto,
            self._results["proto"],
            msg=f"Unexpected 'proto' for case: {self._description}",
        )

    def test__ip4__assembler__cksum(self) -> None:
        """
        Ensure the 'cksum' property returns 0 before assemble() runs
        (the checksum is back-patched into buffers[0][10:12] by
        assemble(), not into the header dataclass).

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__ip4__assembler__src(self) -> None:
        """
        Ensure the 'src' property returns the provided source address.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ip4__assembler__dst(self) -> None:
        """
        Ensure the 'dst' property returns the provided destination address.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ip4__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed Ip4Header.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ip4__assembler__options(self) -> None:
        """
        Ensure the 'options' property returns the provided Ip4Options.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.options,
            self._results["options"],
            msg=f"Unexpected 'options' for case: {self._description}",
        )

    def test__ip4__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload
        assembler.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ip4__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header, options, and payload in
        order and the concatenation matches '__bytes__'.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        buffers: list[Buffer] = []

        self._ip4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__ip4__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly three buffers — fixed-size
        header, options, and payload — so downstream stack code (e.g.
        Ethernet / fragmenter) can locate and mutate them by index.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        buffers: list[Buffer] = []

        self._ip4__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            3,
            msg="Ip4Assembler.assemble must append header + options + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            20,
            msg="Ip4Assembler.assemble must append the 20-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["options"]),
            msg="Ip4Assembler.assemble must append the options block second.",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 (Frag) mid-stream fragment (no MF, non-zero offset).",
            "_kwargs": {
                "ip4_frag__src": Ip4Address("4.3.2.1"),
                "ip4_frag__dst": Ip4Address("8.7.6.5"),
                "ip4_frag__ttl": 128,
                "ip4_frag__dscp": 10,
                "ip4_frag__ecn": 1,
                "ip4_frag__id": 54321,
                "ip4_frag__flag_mf": False,
                "ip4_frag__offset": 32008,
                "ip4_frag__options": Ip4Options(),
                "ip4_frag__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 36,
                "__str__": ("IPv4 4.3.2.1 > 8.7.6.5, proto Raw, id 54321, offset 32008, " "ttl 128, len 36 (20+0+16)"),
                "__repr__": (
                    "Ip4FragAssembler("
                    "header=Ip4Header("
                    "hlen=20, dscp=10, ecn=1, plen=36, id=54321, "
                    "flag_df=False, flag_mf=False, offset=32008, ttl=128, "
                    "proto=<IpProto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('4.3.2.1'), dst=Ip4Address('8.7.6.5'))"
                    ", options=Ip4Options(options=[])"
                    ", payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                # IPv4 (Frag) wire format (36 bytes):
                #   Byte  0     : 0x45   -> ver=4, hlen=20
                #   Byte  1     : 0x29   -> dscp=10<<2 | ecn=1
                #   Bytes 2-3   : 0x0024 -> plen=36
                #   Bytes 4-5   : 0xd431 -> id=54321
                #   Bytes 6-7   : 0x0fa1 -> no flags, offset=32008 (wire 4001)
                #   Byte  8     : 0x80   -> ttl=128
                #   Byte  9     : 0xff   -> proto=RAW
                #   Bytes 10-11 : 0x41d0 -> inet checksum
                #   Bytes 12-15 : 0x04030201 -> src 4.3.2.1
                #   Bytes 16-19 : 0x08070605 -> dst 8.7.6.5
                #   Bytes 20-35 : b"0123456789ABCDEF" (raw payload)
                "__bytes__": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0"
                    b"\x04\x03\x02\x01\x08\x07\x06\x05"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "ver": IpVersion.IP4,
                "hlen": 20,
                "dscp": 10,
                "ecn": 1,
                "plen": 36,
                "id": 54321,
                "flag_df": False,
                "flag_mf": False,
                "offset": 32008,
                "ttl": 128,
                "proto": IpProto.RAW,
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
                    proto=IpProto.RAW,
                    cksum=0,
                    src=Ip4Address("4.3.2.1"),
                    dst=Ip4Address("8.7.6.5"),
                ),
                "options": Ip4Options(),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "IPv4 (Frag) leading fragment (MF set, offset=0, 1466-byte payload).",
            "_kwargs": {
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
            "_results": {
                "__len__": 1486,
                "__str__": (
                    "IPv4 1.2.3.4 > 5.6.7.8, proto Raw, id 12345, MF, offset 0, " "ttl 255, len 1486 (20+0+1466)"
                ),
                "__repr__": (
                    "Ip4FragAssembler("
                    "header=Ip4Header("
                    "hlen=20, dscp=17, ecn=2, plen=1486, id=12345, "
                    "flag_df=False, flag_mf=True, offset=0, ttl=255, "
                    "proto=<IpProto.RAW: 255>, cksum=0, "
                    "src=Ip4Address('1.2.3.4'), dst=Ip4Address('5.6.7.8'))"
                    ", options=Ip4Options(options=[])" + f", payload=RawAssembler(raw__payload=b'{'X' * 1466}'))"
                ),
                # IPv4 (Frag) wire format (1486 bytes):
                #   Byte  0     : 0x45   -> ver=4, hlen=20
                #   Byte  1     : 0x46   -> dscp=17<<2 | ecn=2
                #   Bytes 2-3   : 0x05ce -> plen=1486
                #   Bytes 4-5   : 0x3039 -> id=12345
                #   Bytes 6-7   : 0x2000 -> MF=1, offset=0
                #   Byte  8     : 0xff   -> ttl=255
                #   Byte  9     : 0xff   -> proto=RAW
                #   Bytes 10-11 : 0x549e -> inet checksum
                #   Bytes 12-15 : 0x01020304 -> src 1.2.3.4
                #   Bytes 16-19 : 0x05060708 -> dst 5.6.7.8
                #   Bytes 20+   : 1466 bytes of 'X' payload
                "__bytes__": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e"
                    b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"X" * 1466
                ),
                "ver": IpVersion.IP4,
                "hlen": 20,
                "dscp": 17,
                "ecn": 2,
                "plen": 1486,
                "id": 12345,
                "flag_df": False,
                "flag_mf": True,
                "offset": 0,
                "ttl": 255,
                "proto": IpProto.RAW,
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
                    proto=IpProto.RAW,
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
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the IPv4 (Frag) assembler from the parametrized kwargs.
        """

        self._ip4_frag__assembler = Ip4FragAssembler(**self._kwargs)

    def test__ip4_frag__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total packet length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            len(self._ip4_frag__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip4_frag__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            str(self._ip4_frag__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip4_frag__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            repr(self._ip4_frag__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip4_frag__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            bytes(self._ip4_frag__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip4_frag__assembler__ver(self) -> None:
        """
        Ensure the 'ver' property returns IpVersion.IP4.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.ver,
            self._results["ver"],
            msg=f"Unexpected 'ver' for case: {self._description}",
        )

    def test__ip4_frag__assembler__hlen(self) -> None:
        """
        Ensure the 'hlen' property returns the header byte length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.hlen,
            self._results["hlen"],
            msg=f"Unexpected 'hlen' for case: {self._description}",
        )

    def test__ip4_frag__assembler__dscp(self) -> None:
        """
        Ensure the 'dscp' property returns the provided DSCP value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.dscp,
            self._results["dscp"],
            msg=f"Unexpected 'dscp' for case: {self._description}",
        )

    def test__ip4_frag__assembler__ecn(self) -> None:
        """
        Ensure the 'ecn' property returns the provided ECN value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.ecn,
            self._results["ecn"],
            msg=f"Unexpected 'ecn' for case: {self._description}",
        )

    def test__ip4_frag__assembler__plen(self) -> None:
        """
        Ensure the 'plen' property returns the total packet length.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.plen,
            self._results["plen"],
            msg=f"Unexpected 'plen' for case: {self._description}",
        )

    def test__ip4_frag__assembler__id(self) -> None:
        """
        Ensure the 'id' property returns the provided identification.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.id,
            self._results["id"],
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__ip4_frag__assembler__flag_df(self) -> None:
        """
        Ensure the 'flag_df' property returns False (Ip4FragAssembler
        pins DF to False because fragments cannot carry DF).

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.flag_df,
            self._results["flag_df"],
            msg=f"Unexpected 'flag_df' for case: {self._description}",
        )

    def test__ip4_frag__assembler__flag_mf(self) -> None:
        """
        Ensure the 'flag_mf' property returns the provided MF flag.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.flag_mf,
            self._results["flag_mf"],
            msg=f"Unexpected 'flag_mf' for case: {self._description}",
        )

    def test__ip4_frag__assembler__offset(self) -> None:
        """
        Ensure the 'offset' property returns the provided offset value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.offset,
            self._results["offset"],
            msg=f"Unexpected 'offset' for case: {self._description}",
        )

    def test__ip4_frag__assembler__ttl(self) -> None:
        """
        Ensure the 'ttl' property returns the provided TTL value.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.ttl,
            self._results["ttl"],
            msg=f"Unexpected 'ttl' for case: {self._description}",
        )

    def test__ip4_frag__assembler__proto(self) -> None:
        """
        Ensure the 'proto' property returns the provided IpProto value
        (the Frag assembler takes proto as an explicit argument rather
        than inferring from payload type).

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.proto,
            self._results["proto"],
            msg=f"Unexpected 'proto' for case: {self._description}",
        )

    def test__ip4_frag__assembler__cksum(self) -> None:
        """
        Ensure the 'cksum' property returns 0 before assemble() runs.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__ip4_frag__assembler__src(self) -> None:
        """
        Ensure the 'src' property returns the provided source address.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ip4_frag__assembler__dst(self) -> None:
        """
        Ensure the 'dst' property returns the provided destination address.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ip4_frag__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed Ip4Header.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ip4_frag__assembler__options(self) -> None:
        """
        Ensure the 'options' property returns the provided Ip4Options.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.options,
            self._results["options"],
            msg=f"Unexpected 'options' for case: {self._description}",
        )

    def test__ip4_frag__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload buffer.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        self.assertEqual(
            self._ip4_frag__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ip4_frag__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header, options, and payload in
        order and the concatenation matches '__bytes__'.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        buffers: list[Buffer] = []

        self._ip4_frag__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__ip4_frag__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure Ip4FragAssembler.assemble appends exactly three buffers
        — fixed header, options, and payload — mirroring the Ip4Assembler
        layout so the fragmenter can splice them uniformly.

        Reference: RFC 791 §3.1 (IPv4 datagram wire format).
        """

        buffers: list[Buffer] = []

        self._ip4_frag__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            3,
            msg="Ip4FragAssembler.assemble must append header + options + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            20,
            msg="Ip4FragAssembler.assemble must append the 20-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["options"]),
            msg="Ip4FragAssembler.assemble must append the options block second.",
        )
