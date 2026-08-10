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
Module contains tests for the DHCPv4 packet parser operation (header + options
round-trip, plus all exposed accessor properties).

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py

ver 3.0.10
"""

import struct
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, Ip4Mask, MacAddress
from net_proto import (
    DHCP4__HEADER__LEN,
    Dhcp4Header,
    Dhcp4MessageType,
    Dhcp4OptionClientId,
    Dhcp4OptionEnd,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionMessageType,
    Dhcp4OptionPad,
    Dhcp4OptionParamReqList,
    Dhcp4OptionReqIpAddr,
    Dhcp4OptionRouter,
    Dhcp4Options,
    Dhcp4OptionServerId,
    Dhcp4OptionSubnetMask,
    Dhcp4OptionType,
    Dhcp4Parser,
)
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4HardwareType, Dhcp4Operation
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__MAGIC_COOKIE
from net_proto.tests.lib.parameterized import parameterized_class


def _dhcp4_header(
    *,
    op: int = 0x01,  # BOOTREQUEST
    htype: int = 0x01,  # Ethernet
    hlen: int = 0x06,  # MAC length
    hops: int = 0x00,
    xid: int = 0x12345678,
    secs: int = 0x0000,
    flags: int = 0x0000,
    ciaddr: bytes = b"\x00\x00\x00\x00",
    yiaddr: bytes = b"\x00\x00\x00\x00",
    siaddr: bytes = b"\x00\x00\x00\x00",
    giaddr: bytes = b"\x00\x00\x00\x00",
    chaddr_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    sname: str = "",
    file: str = "",
) -> bytes:
    """
    Build a DHCPv4 header (236 BOOTP bytes + 4-byte DHCP magic cookie).
    """

    assert len(chaddr_mac) == 6, f"Ethernet MAC must be 6 bytes. Got: {len(chaddr_mac)}"
    chaddr = chaddr_mac + b"\x00" * (16 - 6)

    sname_bytes = sname.encode("ascii") + b"\x00" * (64 - len(sname))
    file_bytes = file.encode("ascii") + b"\x00" * (128 - len(file))

    header = bytes([op, htype, hlen, hops])
    header += xid.to_bytes(4, "big")
    header += secs.to_bytes(2, "big") + flags.to_bytes(2, "big")
    header += ciaddr + yiaddr + siaddr + giaddr
    header += chaddr + sname_bytes + file_bytes + DHCP4__HEADER__MAGIC_COOKIE

    assert len(header) == DHCP4__HEADER__LEN, f"Got header len {len(header)}, expected {DHCP4__HEADER__LEN}"

    return header


DHCP4_HEADER_DEFAULT = _dhcp4_header()


@parameterized_class(
    [
        {
            "_description": "DHCPv4 packet with only Message Type (DISCOVER) and End.",
            "_args": [
                DHCP4_HEADER_DEFAULT
                # Message Type [RFC 2132]: Code=53, Len=1, DISCOVER (1)
                + b"\x35\x01\x01"
                # End [RFC 2132]: terminator
                + b"\xff",
            ],
            "_results": {
                "header_bytes": DHCP4_HEADER_DEFAULT,
                "options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "DHCPv4 packet with a rich mix of options, pads, and trailing ignored bytes.",
            "_args": [
                DHCP4_HEADER_DEFAULT
                + (
                    # Subnet Mask [RFC 2132]: Code=1, Len=4, 255.255.255.0
                    b"\x01\x04\xff\xff\xff\x00"
                    # Router [RFC 2132]: Code=3, Len=8, 192.0.2.1, 198.51.100.5
                    b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05"
                    # Server Identifier [RFC 2132]: Code=54, Len=4, 192.0.2.1
                    b"\x36\x04\xc0\x00\x02\x01"
                    # IP Address Lease Time [RFC 2132]: Code=51, Len=4, 60 s
                    b"\x33\x04\x00\x00\x00\x3c"
                    # Client Identifier [RFC 2132]: Code=61, Len=7, 01:de:ad:be:ef:00:01
                    b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01"
                    # Pad + Pad [RFC 2132]: two 1-byte 0x00 fillers
                    b"\x00\x00"
                    # Requested IP Address [RFC 2132]: Code=50, Len=4, 1.2.3.4
                    b"\x32\x04\x01\x02\x03\x04"
                    # Parameter Request List [RFC 2132]:
                    #   Code=55, Len=2, [HOST_NAME=12, MESSAGE_TYPE=53]
                    b"\x37\x02\x0c\x35"
                    # Message Type [RFC 2132]: Code=53, Len=1, REQUEST (3)
                    b"\x35\x01\x03"
                    # End [RFC 2132]: terminator
                    b"\xff"
                    # Trailing garbage — must be ignored by the parser.
                    b"\x00\x00\x00"
                ),
            ],
            "_results": {
                "header_bytes": DHCP4_HEADER_DEFAULT,
                "options": Dhcp4Options(
                    Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
                    Dhcp4OptionRouter(
                        [
                            Ip4Address("192.0.2.1"),
                            Ip4Address("198.51.100.5"),
                        ]
                    ),
                    Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                    Dhcp4OptionLeaseTime(60),
                    Dhcp4OptionClientId(b"\x01\xde\xad\xbe\xef\x00\x01"),
                    Dhcp4OptionPad(),
                    Dhcp4OptionPad(),
                    Dhcp4OptionReqIpAddr(Ip4Address("1.2.3.4")),
                    Dhcp4OptionParamReqList(
                        [
                            Dhcp4OptionType.HOST_NAME,
                            Dhcp4OptionType.MESSAGE_TYPE,
                        ]
                    ),
                    Dhcp4OptionMessageType(Dhcp4MessageType.REQUEST),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "DHCPv4 packet with minimum-length ClientId and a Message Type.",
            "_args": [
                DHCP4_HEADER_DEFAULT
                + (
                    # Message Type [RFC 2132]: Code=53, Len=1, DISCOVER (1)
                    b"\x35\x01\x01"
                    # Client Identifier [RFC 2132 §9.14]: Code=61, Len=2 (RFC minimum),
                    # 1-byte htype + 1-byte ID.
                    b"\x3d\x02\x01\xff"
                    # End [RFC 2132]: terminator
                    b"\xff"
                ),
            ],
            "_results": {
                "header_bytes": DHCP4_HEADER_DEFAULT,
                "options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionClientId(b"\x01\xff"),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "DHCPv4 packet with only Message Type and End (minimum-valid options).",
            "_args": [
                DHCP4_HEADER_DEFAULT
                # Message Type [RFC 2132]: Code=53, Len=1, DISCOVER (1)
                + b"\x35\x01\x01"
                # End [RFC 2132]: terminator
                + b"\xff",
            ],
            "_results": {
                "header_bytes": DHCP4_HEADER_DEFAULT,
                "options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionEnd(),
                ),
            },
        },
    ]
)
class TestDhcp4ParserOperation(TestCase):
    """
    The DHCPv4 packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Parse the test frame once per testcase.
        """

        self._parser = Dhcp4Parser(*self._args)

    def test__dhcp4__parser__header(self) -> None:
        """
        Ensure the parser's 'header' matches the one re-parsed from the raw
        header bytes.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.header,
            Dhcp4Header.from_buffer(self._results["header_bytes"]),
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__dhcp4__parser__options(self) -> None:
        """
        Ensure the parser's 'options' match the expected Dhcp4Options object.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.options,
            self._results["options"],
            msg=f"Unexpected parsed options for case: {self._description}",
        )

    def test__dhcp4__parser__len(self) -> None:
        """
        Ensure '__len__()' returns header length + options length.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            len(self._parser),
            len(self._results["header_bytes"]) + len(self._results["options"]),
            msg=f"Unexpected parser __len__ for case: {self._description}",
        )

    def test__dhcp4__parser__buffer_protocol(self) -> None:
        """
        Ensure the buffer protocol yields header bytes concatenated with the
        options' wire image.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            bytes(memoryview(self._parser)),
            self._results["header_bytes"] + bytes(self._results["options"]),
            msg=f"Unexpected parser buffer output for case: {self._description}",
        )


class TestDhcp4ParserHeaderProperties(TestCase):
    """
    Exercise every Dhcp4HeaderProperties accessor exposed on the parser for
    a fully-populated DHCPv4 frame.
    """

    @override
    def setUp(self) -> None:
        """
        Parse a frame with every header field set to a distinct non-default
        value so the per-field accessors can be verified individually.
        """

        self._header_bytes = _dhcp4_header(
            op=int(Dhcp4Operation.REQUEST),
            hops=3,
            xid=0xDEADBEEF,
            secs=0x1234,
            # flag_b=True → top bit of the 'flags' word.
            flags=0x8000,
            ciaddr=bytes(Ip4Address("10.0.0.1")),
            yiaddr=bytes(Ip4Address("10.0.0.2")),
            siaddr=bytes(Ip4Address("10.0.0.3")),
            giaddr=bytes(Ip4Address("10.0.0.4")),
            chaddr_mac=b"\x00\x11\x22\x33\x44\x55",
            sname="server.example",
            file="boot.img",
        )

        # Minimum-valid options block: Message Type (REQUEST) + End.
        # RFC 2131 §3 requires every DHCP message to carry a Message
        # Type option; the parser's `_validate_sanity` rejects frames
        # without it.
        frame = self._header_bytes + b"\x35\x01\x03\xff"
        self._parser = Dhcp4Parser(memoryview(frame))

    def test__dhcp4__parser__operation(self) -> None:
        """
        Ensure 'operation' reflects the header operation field.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.operation,
            Dhcp4Operation.REQUEST,
            msg="Unexpected 'operation' value.",
        )

    def test__dhcp4__parser__hrtype(self) -> None:
        """
        Ensure 'hrtype' reports the Ethernet hardware type constant.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.hrtype,
            Dhcp4HardwareType.ETHERNET,
            msg="Unexpected 'hrtype' value.",
        )

    def test__dhcp4__parser__hrlen(self) -> None:
        """
        Ensure 'hrlen' reports the Ethernet hardware-address length (6).

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.hrlen,
            6,
            msg="Unexpected 'hrlen' value.",
        )

    def test__dhcp4__parser__hops(self) -> None:
        """
        Ensure 'hops' matches the byte at the 'hops' offset.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.hops,
            3,
            msg="Unexpected 'hops' value.",
        )

    def test__dhcp4__parser__xid(self) -> None:
        """
        Ensure 'xid' is the transaction identifier decoded as big-endian u32.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.xid,
            0xDEADBEEF,
            msg="Unexpected 'xid' value.",
        )

    def test__dhcp4__parser__secs(self) -> None:
        """
        Ensure 'secs' is the 16-bit seconds-elapsed field.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.secs,
            0x1234,
            msg="Unexpected 'secs' value.",
        )

    def test__dhcp4__parser__flag_b(self) -> None:
        """
        Ensure 'flag_b' decodes the top bit of the 'flags' word.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertTrue(
            self._parser.flag_b,
            msg="Broadcast flag (flag_b) must be True when flags=0x8000.",
        )

    def test__dhcp4__parser__ciaddr(self) -> None:
        """
        Ensure 'ciaddr' decodes the client IP address as Ip4Address.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.ciaddr,
            Ip4Address("10.0.0.1"),
            msg="Unexpected 'ciaddr' value.",
        )

    def test__dhcp4__parser__yiaddr(self) -> None:
        """
        Ensure 'yiaddr' decodes the "your" IP address as Ip4Address.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.yiaddr,
            Ip4Address("10.0.0.2"),
            msg="Unexpected 'yiaddr' value.",
        )

    def test__dhcp4__parser__siaddr(self) -> None:
        """
        Ensure 'siaddr' decodes the server IP address as Ip4Address.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.siaddr,
            Ip4Address("10.0.0.3"),
            msg="Unexpected 'siaddr' value.",
        )

    def test__dhcp4__parser__giaddr(self) -> None:
        """
        Ensure 'giaddr' decodes the gateway/relay IP address as Ip4Address.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.giaddr,
            Ip4Address("10.0.0.4"),
            msg="Unexpected 'giaddr' value.",
        )

    def test__dhcp4__parser__chaddr(self) -> None:
        """
        Ensure 'chaddr' decodes the first 6 bytes of the hardware-address
        field as a MacAddress.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.chaddr,
            MacAddress("00:11:22:33:44:55"),
            msg="Unexpected 'chaddr' value.",
        )

    def test__dhcp4__parser__sname(self) -> None:
        """
        Ensure 'sname' strips trailing NULs from the server-hostname field.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.sname,
            "server.example",
            msg="Unexpected 'sname' value.",
        )

    def test__dhcp4__parser__file(self) -> None:
        """
        Ensure 'file' strips trailing NULs from the bootfile-name field.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.file,
            "boot.img",
            msg="Unexpected 'file' value.",
        )

    def test__dhcp4__parser__magic_cookie(self) -> None:
        """
        Ensure 'magic_cookie' returns the DHCP magic cookie constant.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.magic_cookie,
            DHCP4__HEADER__MAGIC_COOKIE,
            msg="Unexpected 'magic_cookie' value.",
        )


class TestDhcp4ParserOptionsProperties(TestCase):
    """
    Exercise every Dhcp4OptionsProperties accessor exposed on the parser.
    """

    @override
    def setUp(self) -> None:
        """
        Parse a frame carrying one instance of each option whose value is
        surfaced through a Dhcp4OptionsProperties accessor.
        """

        self._parser = Dhcp4Parser(
            memoryview(
                DHCP4_HEADER_DEFAULT
                # Subnet Mask [RFC 2132]: Code=1, Len=4, 255.255.255.0
                + b"\x01\x04\xff\xff\xff\x00"
                # Router [RFC 2132]: Code=3, Len=4, 192.0.2.1
                + b"\x03\x04\xc0\x00\x02\x01"
                # Host Name [RFC 2132]: Code=12, Len=3, "srv"
                + b"\x0c\x03\x73\x72\x76"
                # Requested IP Address [RFC 2132]: Code=50, Len=4, 10.0.0.7
                + b"\x32\x04\x0a\x00\x00\x07"
                # Message Type [RFC 2132]: Code=53, Len=1, ACK (5)
                + b"\x35\x01\x05"
                # Server Identifier [RFC 2132]: Code=54, Len=4, 192.0.2.254
                + b"\x36\x04\xc0\x00\x02\xfe"
                # Parameter Request List [RFC 2132]: Code=55, Len=2, [1, 3]
                + b"\x37\x02\x01\x03"
                # End [RFC 2132]: terminator
                + b"\xff"
            )
        )

    def test__dhcp4__parser__host_name(self) -> None:
        """
        Ensure 'host_name' returns the Host Name option value.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.host_name,
            "srv",
            msg="Unexpected 'host_name' value.",
        )

    def test__dhcp4__parser__message_type(self) -> None:
        """
        Ensure 'message_type' returns the Message Type option value.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.message_type,
            Dhcp4MessageType.ACK,
            msg="Unexpected 'message_type' value.",
        )

    def test__dhcp4__parser__param_req_list(self) -> None:
        """
        Ensure 'param_req_list' returns the Parameter Request List values as
        Dhcp4OptionType members.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.param_req_list,
            [Dhcp4OptionType.SUBNET_MASK, Dhcp4OptionType.ROUTER],
            msg="Unexpected 'param_req_list' value.",
        )

    def test__dhcp4__parser__req_ip_addr(self) -> None:
        """
        Ensure 'req_ip_addr' returns the Requested IP Address option value.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.req_ip_addr,
            Ip4Address("10.0.0.7"),
            msg="Unexpected 'req_ip_addr' value.",
        )

    def test__dhcp4__parser__router(self) -> None:
        """
        Ensure 'router' returns the Router option list.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.router,
            [Ip4Address("192.0.2.1")],
            msg="Unexpected 'router' value.",
        )

    def test__dhcp4__parser__server_id(self) -> None:
        """
        Ensure 'server_id' returns the Server Identifier option value.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.server_id,
            Ip4Address("192.0.2.254"),
            msg="Unexpected 'server_id' value.",
        )

    def test__dhcp4__parser__subnet_mask(self) -> None:
        """
        Ensure 'subnet_mask' returns the Subnet Mask option value as Ip4Mask.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        self.assertEqual(
            self._parser.subnet_mask,
            Ip4Mask("255.255.255.0"),
            msg="Unexpected 'subnet_mask' value.",
        )

    def test__dhcp4__parser__options_accessors_absent(self) -> None:
        """
        Ensure every Dhcp4OptionsProperties accessor (except those
        the parser's sanity check requires to be present —
        message_type for every DHCP message, server_id /
        lease_time for server responses) returns None when the
        corresponding option is missing from the frame.

        Uses a DHCPDISCOVER (client request) frame so the parser
        does not require server_id or lease_time. param_req_list,
        host_name, router, subnet_mask, req_ip_addr — all genuinely
        absent and must report None.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        # Minimum-valid options block: Message Type = DISCOVER + End.
        # DISCOVER (client request) has no required-options sanity
        # constraints beyond Message Type itself.
        parser = Dhcp4Parser(memoryview(DHCP4_HEADER_DEFAULT + b"\x35\x01\x01\xff"))

        self.assertIsNone(parser.host_name, msg="host_name must be None.")
        self.assertIsNone(parser.param_req_list, msg="param_req_list must be None.")
        self.assertIsNone(parser.req_ip_addr, msg="req_ip_addr must be None.")
        self.assertIsNone(parser.router, msg="router must be None.")
        self.assertIsNone(parser.server_id, msg="server_id must be None.")
        self.assertIsNone(parser.subnet_mask, msg="subnet_mask must be None.")


class TestDhcp4ParserBufferRoundtrip(TestCase):
    """
    Ensure the parser's buffer output can be re-parsed into an equal object.
    """

    def test__dhcp4__parser__roundtrip(self) -> None:
        """
        Ensure that a parse-encode-parse round-trip is idempotent at
        the level of the exposed header and options — the second
        parser must be indistinguishable from the first.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        frame = (
            DHCP4_HEADER_DEFAULT
            # Message Type [RFC 2132]: Code=53, Len=1, OFFER (2)
            + b"\x35\x01\x02"
            # Server Identifier [RFC 2132]: Code=54, Len=4, 192.0.2.1
            + b"\x36\x04\xc0\x00\x02\x01"
            # IP Address Lease Time [RFC 2132]: Code=51, Len=4, 3600s
            + b"\x33\x04\x00\x00\x0e\x10"
            # End [RFC 2132]: terminator
            + b"\xff"
        )

        first = Dhcp4Parser(memoryview(frame))
        second = Dhcp4Parser(memoryview(bytes(memoryview(first))))

        self.assertEqual(
            first.header,
            second.header,
            msg="Header must survive a buffer-protocol roundtrip.",
        )
        self.assertEqual(
            first.options,
            second.options,
            msg="Options must survive a buffer-protocol roundtrip.",
        )


class TestDhcp4ParserPreservesMagicCookieStructurally(TestCase):
    """
    Sanity-check the helper and the parser: the helper-produced header bytes
    must contain the DHCP magic cookie at the documented offset and the
    parser must accept such a frame.
    """

    def test__dhcp4__parser__magic_cookie_offset(self) -> None:
        """
        Ensure the 4-byte magic cookie sits at bytes 236..239 of the header.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        header = _dhcp4_header()

        self.assertEqual(
            header[236:240],
            DHCP4__HEADER__MAGIC_COOKIE,
            msg="Magic cookie must occupy bytes 236..239 of the DHCPv4 header.",
        )

    def test__dhcp4__parser__flags_broadcast_bit_off(self) -> None:
        """
        Ensure that with flags=0x0000 the parser reports flag_b=False.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        header = _dhcp4_header(flags=0x0000)
        # Minimum-valid options block: Message Type = DISCOVER + End.
        # The default `_dhcp4_header()` builds a BOOTREQUEST so a
        # DISCOVER message type matches and the per-message-type
        # sanity checks do not fire.
        parser = Dhcp4Parser(memoryview(header + b"\x35\x01\x01\xff"))

        self.assertFalse(
            parser.flag_b,
            msg="flag_b must be False when the broadcast bit is clear.",
        )

    def test__dhcp4__parser__struct_layout_matches_header(self) -> None:
        """
        Ensure the helper lays out fields in the same order struct.unpack
        expects — parse the header with both approaches and compare.

        Reference: RFC 2131 §2 (DHCP message parse).
        """

        header = _dhcp4_header(xid=0xAABBCCDD)
        (
            op,
            _htype,
            _hlen,
            _hops,
            xid,
            *_rest,
        ) = struct.unpack("! BBBB L HH L L L L 16s 64s 128s 4s", header)

        self.assertEqual(op, int(Dhcp4Operation.REQUEST), msg="op mismatch.")
        self.assertEqual(xid, 0xAABBCCDD, msg="xid mismatch.")
