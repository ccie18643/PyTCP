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
This module contains tests for the IPv6 packet assembler operation.

net_proto/tests/unit/protocols/ip6/test__ip6__assembler__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, Ip6Address, IpVersion
from net_proto import IP6__DEFAULT_HOP_LIMIT, Ip6Assembler, Ip6Header, IpProto, RawAssembler
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IPv6 packet, header only (empty payload, hop=1).",
            "_kwargs": {
                "ip6__src": Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                "ip6__dst": Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                "ip6__hop": 1,
                "ip6__dscp": 0,
                "ip6__ecn": 0,
                "ip6__flow": 0,
                "ip6__payload": RawAssembler(),
            },
            "_results": {
                "__len__": 40,
                "__str__": (
                    "IPv6 1001:2002:3003:4004:5005:6006:7007:8008 > a00a:b00b:c00c:d00d:e00e:f00f:a0a:b0b, "
                    "next Raw, flow 0, hop 1, len 40 (40+0)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=0, ecn=0, flow=0, dlen=0, "
                    "next=<IpProto.RAW: 255>, hop=1, "
                    "src=Ip6Address('1001:2002:3003:4004:5005:6006:7007:8008'), "
                    "dst=Ip6Address('a00a:b00b:c00c:d00d:e00e:f00f:a0a:b0b')), "
                    "payload=RawAssembler(raw__payload=b''))"
                ),
                # IPv6 wire frame (40 bytes, header only):
                #   Bytes 0-3   : 0x60000000 ->
                #                 ver=6, dscp=0, ecn=0, flow=0
                #   Bytes 4-5   : 0x0000 -> dlen=0
                #   Byte  6     : 0xff   -> next=IpProto.RAW
                #   Byte  7     : 0x01   -> hop=1
                #   Bytes 8-23  : src=1001:2002:3003:4004:5005:6006:7007:8008
                #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
                "__bytes__": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
                "ver": IpVersion.IP6,
                "dscp": 0,
                "ecn": 0,
                "flow": 0,
                "dlen": 0,
                "next": IpProto.RAW,
                "hop": 1,
                "src": Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                "dst": Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                "header": Ip6Header(
                    dscp=0,
                    ecn=0,
                    flow=0,
                    dlen=0,
                    next=IpProto.RAW,
                    hop=1,
                    src=Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                    dst=Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                ),
                "payload": RawAssembler(),
                "payload_len": 0,
            },
        },
        {
            "_description": "IPv6 packet with 16-byte ASCII payload at maximum flow value.",
            "_kwargs": {
                "ip6__src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "ip6__dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "ip6__hop": 255,
                "ip6__dscp": 38,
                "ip6__ecn": 2,
                "ip6__flow": 1048575,
                "ip6__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 56,
                "__str__": (
                    "IPv6 1111:2222:3333:4444:5555:6666:7777:8888 > 8888:7777:6666:5555:4444:3333:2222:1111, "
                    "next Raw, flow 1048575, hop 255, len 56 (40+16)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=38, ecn=2, flow=1048575, dlen=16, "
                    "next=<IpProto.RAW: 255>, hop=255, "
                    "src=Ip6Address('1111:2222:3333:4444:5555:6666:7777:8888'), "
                    "dst=Ip6Address('8888:7777:6666:5555:4444:3333:2222:1111')), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                # IPv6 wire frame (56 bytes = 40-byte header + 16-byte payload):
                #   Bytes 0-3   : 0x69afffff ->
                #                 ver=6, dscp=38, ecn=2, flow=0xfffff (1048575)
                #   Bytes 4-5   : 0x0010 -> dlen=16
                #   Byte  6     : 0xff   -> next=IpProto.RAW
                #   Byte  7     : 0xff   -> hop=255
                #   Bytes 8-23  : src=1111:2222:3333:4444:5555:6666:7777:8888
                #   Bytes 24-39 : dst=8888:7777:6666:5555:4444:3333:2222:1111
                #   Bytes 40-55 : b"0123456789ABCDEF" (ASCII payload)
                "__bytes__": (
                    b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "ver": IpVersion.IP6,
                "dscp": 38,
                "ecn": 2,
                "flow": 1048575,
                "dlen": 16,
                "next": IpProto.RAW,
                "hop": 255,
                "src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "header": Ip6Header(
                    dscp=38,
                    ecn=2,
                    flow=1048575,
                    dlen=16,
                    next=IpProto.RAW,
                    hop=255,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
                "payload_len": 16,
            },
        },
        {
            "_description": "IPv6 packet at maximum dlen (65535) with 65495-byte payload.",
            "_kwargs": {
                "ip6__src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "ip6__dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "ip6__hop": 128,
                "ip6__dscp": 63,
                "ip6__ecn": 3,
                "ip6__flow": 0,
                "ip6__payload": RawAssembler(raw__payload=b"X" * 65495),
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "IPv6 1111:2222:3333:4444:5555:6666:7777:8888 > 8888:7777:6666:5555:4444:3333:2222:1111, "
                    "next Raw, flow 0, hop 128, len 65535 (40+65495)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=63, ecn=3, flow=0, dlen=65495, "
                    "next=<IpProto.RAW: 255>, hop=128, "
                    "src=Ip6Address('1111:2222:3333:4444:5555:6666:7777:8888'), "
                    "dst=Ip6Address('8888:7777:6666:5555:4444:3333:2222:1111')), "
                    f"payload=RawAssembler(raw__payload=b'{'X' * 65495}'))"
                ),
                # IPv6 wire frame (65535 bytes = 40-byte header + 65495-byte payload):
                #   Bytes 0-3   : 0x6ff00000 ->
                #                 ver=6, dscp=63, ecn=3, flow=0
                #   Bytes 4-5   : 0xffd7 -> dlen=65495
                #   Byte  6     : 0xff   -> next=IpProto.RAW
                #   Byte  7     : 0x80   -> hop=128
                #   Bytes 8-23  : src=1111:2222:3333:4444:5555:6666:7777:8888
                #   Bytes 24-39 : dst=8888:7777:6666:5555:4444:3333:2222:1111
                #   Bytes 40+   : 65495 bytes of 'X'
                "__bytes__": (
                    b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11" + b"X" * 65495
                ),
                "ver": IpVersion.IP6,
                "dscp": 63,
                "ecn": 3,
                "flow": 0,
                "dlen": 65495,
                "next": IpProto.RAW,
                "hop": 128,
                "src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "header": Ip6Header(
                    dscp=63,
                    ecn=3,
                    flow=0,
                    dlen=65495,
                    next=IpProto.RAW,
                    hop=128,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": RawAssembler(raw__payload=b"X" * 65495),
                "payload_len": 65495,
            },
        },
    ]
)
class TestIp6AssemblerOperation(TestCase):
    """
    The IPv6 packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the IPv6 assembler from the parametrized kwargs.
        """

        self._ip6__assembler = Ip6Assembler(**self._kwargs)

    def test__ip6__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total packet length.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            len(self._ip6__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip6__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            str(self._ip6__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip6__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            repr(self._ip6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip6__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            bytes(self._ip6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip6__assembler__ver(self) -> None:
        """
        Ensure the 'ver' property returns IpVersion.IP6.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.ver,
            self._results["ver"],
            msg=f"Unexpected 'ver' for case: {self._description}",
        )

    def test__ip6__assembler__dscp(self) -> None:
        """
        Ensure the 'dscp' property returns the provided DSCP value.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.dscp,
            self._results["dscp"],
            msg=f"Unexpected 'dscp' for case: {self._description}",
        )

    def test__ip6__assembler__ecn(self) -> None:
        """
        Ensure the 'ecn' property returns the provided ECN value.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.ecn,
            self._results["ecn"],
            msg=f"Unexpected 'ecn' for case: {self._description}",
        )

    def test__ip6__assembler__flow(self) -> None:
        """
        Ensure the 'flow' property returns the provided flow label.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.flow,
            self._results["flow"],
            msg=f"Unexpected 'flow' for case: {self._description}",
        )

    def test__ip6__assembler__dlen(self) -> None:
        """
        Ensure the 'dlen' property returns the payload length computed
        from the provided payload assembler.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.dlen,
            self._results["dlen"],
            msg=f"Unexpected 'dlen' for case: {self._description}",
        )

    def test__ip6__assembler__next(self) -> None:
        """
        Ensure the 'next' property returns the IpProto derived from the
        provided payload type.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.next,
            self._results["next"],
            msg=f"Unexpected 'next' for case: {self._description}",
        )

    def test__ip6__assembler__hop(self) -> None:
        """
        Ensure the 'hop' property returns the provided hop limit.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.hop,
            self._results["hop"],
            msg=f"Unexpected 'hop' for case: {self._description}",
        )

    def test__ip6__assembler__src(self) -> None:
        """
        Ensure the 'src' property returns the provided source address.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ip6__assembler__dst(self) -> None:
        """
        Ensure the 'dst' property returns the provided destination address.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ip6__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed Ip6Header.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ip6__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload
        assembler.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ip6__assembler__payload_len(self) -> None:
        """
        Ensure 'payload_len' matches len(payload) without invoking
        assemble(); downstream code reads it before the packet is
        serialized.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self.assertEqual(
            self._ip6__assembler.payload_len,
            self._results["payload_len"],
            msg=f"Unexpected 'payload_len' for case: {self._description}",
        )

    def test__ip6__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header and payload in order and the
        concatenation matches '__bytes__'.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        buffers: list[Buffer] = []

        self._ip6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__ip6__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers — the fixed
        40-byte header followed by the payload — so downstream code
        (e.g. Ethernet, fragmenter) can locate them by index.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        buffers: list[Buffer] = []

        self._ip6__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg="Ip6Assembler.assemble must append header + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            40,
            msg="Ip6Assembler.assemble must append the 40-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            self._results["payload_len"],
            msg="Ip6Assembler.assemble must append the payload buffer second.",
        )


class TestIp6AssemblerDefaults(TestCase):
    """
    The IPv6 assembler default-keyword tests.
    """

    def test__ip6__assembler__default_hop_dscp_ecn_flow(self) -> None:
        """
        Ensure a default-constructed Ip6Assembler uses hop limit 64
        (the RFC-recommended default) and dscp / ecn / flow of 0,
        pinning the default keyword values and the
        IP6__DEFAULT_HOP_LIMIT constant against their literals.

        Reference: RFC 8200 §3 (Hop Limit, Traffic Class, Flow Label defaults).
        """

        assembler = Ip6Assembler()

        # Literals, NOT IP6__DEFAULT_HOP_LIMIT — asserting against the
        # constant would move with a mutation of its definition.
        self.assertEqual(assembler.hop, 64, msg="Default Ip6Assembler hop limit must be 64.")
        self.assertEqual(assembler.dscp, 0, msg="Default Ip6Assembler dscp must be 0.")
        self.assertEqual(assembler.ecn, 0, msg="Default Ip6Assembler ecn must be 0.")
        self.assertEqual(assembler.flow, 0, msg="Default Ip6Assembler flow must be 0.")
        self.assertEqual(IP6__DEFAULT_HOP_LIMIT, 64, msg="IP6__DEFAULT_HOP_LIMIT must be 64.")
