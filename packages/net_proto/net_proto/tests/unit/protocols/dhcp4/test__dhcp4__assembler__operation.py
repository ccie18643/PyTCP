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
Module contains tests for the DHCPv4 packet assembler operation.

The assembler composes a Dhcp4Header (236-byte BOOTP portion + 4-byte magic
cookie) followed by the Dhcp4Options blob, and exposes the combined wire image
through the buffer protocol. The 'assemble()' method is intentionally an L7
stub that raises NotImplementedError — sockets are the user-facing API.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address, Ip4Mask, MacAddress
from net_proto import (
    DHCP4__HEADER__LEN,
    Dhcp4Header,
    Dhcp4MessageType,
    Dhcp4OptionClientId,
    Dhcp4OptionEnd,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionMessageType,
    Dhcp4OptionParamReqList,
    Dhcp4OptionReqIpAddr,
    Dhcp4OptionRouter,
    Dhcp4Options,
    Dhcp4OptionServerId,
    Dhcp4OptionSubnetMask,
    Dhcp4OptionType,
    Dhcp4Parser,
)
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4Operation


def _bootp_header(
    *,
    op: int,
    hops: int = 0,
    xid: int,
    secs: int = 0,
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
    Build the 240-byte BOOTP+magic-cookie header blob used by the expected
    wire-image assertions.
    """

    assert len(chaddr_mac) == 6, f"Ethernet MAC must be 6 bytes. Got: {len(chaddr_mac)}"
    chaddr = chaddr_mac + b"\x00" * 10
    sname_bytes = sname.encode("ascii") + b"\x00" * (64 - len(sname))
    file_bytes = file.encode("ascii") + b"\x00" * (128 - len(file))

    blob = bytes([op, 0x01, 0x06, hops])
    blob += xid.to_bytes(4, "big")
    blob += secs.to_bytes(2, "big") + flags.to_bytes(2, "big")
    blob += ciaddr + yiaddr + siaddr + giaddr
    blob += chaddr + sname_bytes + file_bytes
    blob += b"\x63\x82\x53\x63"  # DHCP magic cookie [RFC 2131]

    assert len(blob) == DHCP4__HEADER__LEN, f"BOOTP header must be {DHCP4__HEADER__LEN} bytes. Got: {len(blob)}"
    return blob


@parameterized_class(
    [
        {
            "_description": "DHCPDISCOVER request with Message Type + End.",
            "_kwargs": {
                "dhcp4__operation": Dhcp4Operation.REQUEST,
                "dhcp4__xid": 0x12345678,
                "dhcp4__chaddr": MacAddress("00:11:22:33:44:55"),
                "dhcp4__options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionEnd(),
                ),
            },
            "_results": {
                "__len__": DHCP4__HEADER__LEN + 3 + 1,
                "__str__": (
                    "DHCPv4 Request, xid 305419896, ciaddr 0.0.0.0, yiaddr 0.0.0.0, "
                    "giaddr 0.0.0.0, chaddr 00:11:22:33:44:55, "
                    "opts [message_type Discover, end]"
                ),
                # Header (BOOTREQUEST/Ethernet/6, xid 0x12345678) + cookie
                # Options: Message Type Code=53 Len=1 DISCOVER (1) + End (0xff)
                "__bytes_tail__": b"\x35\x01\x01\xff",
            },
        },
        {
            "_description": (
                "DHCPOFFER reply — server supplies yiaddr, subnet mask, router, "
                "lease time, server-id, sname and file fields."
            ),
            "_kwargs": {
                "dhcp4__operation": Dhcp4Operation.REPLY,
                "dhcp4__hops": 1,
                "dhcp4__xid": 0xAABBCCDD,
                "dhcp4__secs": 4,
                "dhcp4__flag_b": True,
                "dhcp4__yiaddr": Ip4Address("192.0.2.50"),
                "dhcp4__siaddr": Ip4Address("192.0.2.1"),
                "dhcp4__giaddr": Ip4Address("192.0.2.254"),
                "dhcp4__chaddr": MacAddress("02:00:00:00:00:91"),
                "dhcp4__sname": "srv-1",
                "dhcp4__file": "pxe/boot.bin",
                "dhcp4__options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.OFFER),
                    Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
                    Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
                    Dhcp4OptionLeaseTime(86400),
                    Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                    Dhcp4OptionEnd(),
                ),
            },
            "_results": {
                "__len__": DHCP4__HEADER__LEN + 3 + 6 + 6 + 6 + 6 + 1,
                "__str__": (
                    "DHCPv4 Reply, xid 2864434397, ciaddr 0.0.0.0, yiaddr 192.0.2.50, "
                    "giaddr 192.0.2.254, chaddr 02:00:00:00:00:91, "
                    "opts [message_type Offer, subnet_mask /24, "
                    "router ['192.0.2.1'], lease_time 86400, "
                    "server_id 192.0.2.1, end]"
                ),
                # Options [RFC 2132]:
                #   Message Type  : 0x35 0x01 0x02              (OFFER)
                #   Subnet Mask   : 0x01 0x04 255.255.255.0
                #   Router        : 0x03 0x04 192.0.2.1
                #   Lease Time    : 0x33 0x04 0x00015180        (86400 s)
                #   Server Id     : 0x36 0x04 192.0.2.1
                #   End           : 0xff
                "__bytes_tail__": (
                    b"\x35\x01\x02"
                    b"\x01\x04\xff\xff\xff\x00"
                    b"\x03\x04\xc0\x00\x02\x01"
                    b"\x33\x04\x00\x01\x51\x80"
                    b"\x36\x04\xc0\x00\x02\x01"
                    b"\xff"
                ),
            },
        },
        {
            "_description": "DHCPREQUEST request with Client Identifier and Parameter Request List.",
            "_kwargs": {
                "dhcp4__operation": Dhcp4Operation.REQUEST,
                "dhcp4__xid": 0xDEADBEEF,
                "dhcp4__chaddr": MacAddress("aa:bb:cc:dd:ee:ff"),
                "dhcp4__options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.REQUEST),
                    Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.50")),
                    Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                    Dhcp4OptionClientId(b"\x01\xaa\xbb\xcc\xdd\xee\xff"),
                    Dhcp4OptionParamReqList(
                        [
                            Dhcp4OptionType.SUBNET_MASK,
                            Dhcp4OptionType.ROUTER,
                        ]
                    ),
                    Dhcp4OptionEnd(),
                ),
            },
            "_results": {
                "__len__": DHCP4__HEADER__LEN + 3 + 6 + 6 + 9 + 4 + 1,
                "__str__": (
                    "DHCPv4 Request, xid 3735928559, ciaddr 0.0.0.0, yiaddr 0.0.0.0, "
                    "giaddr 0.0.0.0, chaddr aa:bb:cc:dd:ee:ff, "
                    "opts [message_type Request, req_ip_addr 192.0.2.50, "
                    "server_id 192.0.2.1, client_id 01:aa:bb:cc:dd:ee:ff, "
                    "param_req_list ['SUBNET_MASK', 'ROUTER'], end]"
                ),
                # Options [RFC 2132]:
                #   Message Type      : 0x35 0x01 0x03                          (REQUEST)
                #   Requested IP Addr : 0x32 0x04 192.0.2.50
                #   Server Identifier : 0x36 0x04 192.0.2.1
                #   Client Identifier : 0x3d 0x07 01:aa:bb:cc:dd:ee:ff
                #   Param Req List    : 0x37 0x02 [SUBNET_MASK=1, ROUTER=3]
                #   End               : 0xff
                "__bytes_tail__": (
                    b"\x35\x01\x03"
                    b"\x32\x04\xc0\x00\x02\x32"
                    b"\x36\x04\xc0\x00\x02\x01"
                    b"\x3d\x07\x01\xaa\xbb\xcc\xdd\xee\xff"
                    b"\x37\x02\x01\x03"
                    b"\xff"
                ),
            },
        },
    ]
)
class TestDhcp4AssemblerOperation(TestCase):
    """
    The DHCPv4 packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Construct a Dhcp4Assembler for every parameterized testcase.
        """

        self._dhcp4__assembler = Dhcp4Assembler(**self._kwargs)

    def test__dhcp4__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals the 240-byte header plus
        the total options length.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        self.assertEqual(
            len(self._dhcp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__assembler__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical DHCPv4 log line.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        self.assertEqual(
            str(self._dhcp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__assembler__repr_is_round_trippable(self) -> None:
        """
        Ensure '__repr__()' wraps the Dhcp4Header and Dhcp4Options repr and
        mentions the class name plus the 'header=' and 'options=' anchors.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        rendered = repr(self._dhcp4__assembler)
        self.assertTrue(
            rendered.startswith("Dhcp4Assembler(header=Dhcp4Header("),
            msg=f"Unexpected __repr__ prefix for case: {self._description} — got: {rendered!r}",
        )
        self.assertIn(
            "options=Dhcp4Options(options=[",
            rendered,
            msg=f"__repr__ must include Dhcp4Options envelope for case: {self._description}",
        )
        self.assertTrue(
            rendered.endswith("]))"),
            msg=f"Unexpected __repr__ suffix for case: {self._description} — got: {rendered!r}",
        )

    def test__dhcp4__assembler__header_bytes_layout(self) -> None:
        """
        Ensure the first 240 bytes of the assembler output match the expected
        BOOTP+magic-cookie header layout built from the same fields.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        k = self._kwargs
        expected_header = _bootp_header(
            op=int(k["dhcp4__operation"]),
            hops=k.get("dhcp4__hops", 0),
            xid=k["dhcp4__xid"],
            secs=k.get("dhcp4__secs", 0),
            flags=0x8000 if k.get("dhcp4__flag_b", False) else 0x0000,
            ciaddr=bytes(k.get("dhcp4__ciaddr", Ip4Address("0.0.0.0"))),
            yiaddr=bytes(k.get("dhcp4__yiaddr", Ip4Address("0.0.0.0"))),
            siaddr=bytes(k.get("dhcp4__siaddr", Ip4Address("0.0.0.0"))),
            giaddr=bytes(k.get("dhcp4__giaddr", Ip4Address("0.0.0.0"))),
            chaddr_mac=bytes(k["dhcp4__chaddr"]),
            sname=k.get("dhcp4__sname") or "",
            file=k.get("dhcp4__file") or "",
        )

        self.assertEqual(
            bytes(self._dhcp4__assembler)[:DHCP4__HEADER__LEN],
            expected_header,
            msg=f"Unexpected header bytes for case: {self._description}",
        )

    def test__dhcp4__assembler__options_bytes_tail(self) -> None:
        """
        Ensure the options portion appears verbatim after the 240-byte header.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        self.assertEqual(
            bytes(self._dhcp4__assembler)[DHCP4__HEADER__LEN:],
            self._results["__bytes_tail__"],
            msg=f"Unexpected options tail for case: {self._description}",
        )

    def test__dhcp4__assembler__memoryview_matches_bytes(self) -> None:
        """
        Ensure the buffer protocol yields the same image as 'bytes(assembler)'.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        self.assertEqual(
            bytes(memoryview(self._dhcp4__assembler)),
            bytes(self._dhcp4__assembler),
            msg=f"memoryview must match bytes() for case: {self._description}",
        )

    def test__dhcp4__assembler__parser_roundtrip(self) -> None:
        """
        Ensure a parser applied to the assembler output reproduces the same
        header and options.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        frame = bytes(self._dhcp4__assembler)
        parser = Dhcp4Parser(memoryview(frame))

        self.assertEqual(
            parser.header,
            Dhcp4Header(
                operation=self._kwargs["dhcp4__operation"],
                hops=self._kwargs.get("dhcp4__hops", 0),
                xid=self._kwargs["dhcp4__xid"],
                secs=self._kwargs.get("dhcp4__secs", 0),
                flag_b=self._kwargs.get("dhcp4__flag_b", False),
                ciaddr=self._kwargs.get("dhcp4__ciaddr", Ip4Address("0.0.0.0")),
                yiaddr=self._kwargs.get("dhcp4__yiaddr", Ip4Address("0.0.0.0")),
                siaddr=self._kwargs.get("dhcp4__siaddr", Ip4Address("0.0.0.0")),
                giaddr=self._kwargs.get("dhcp4__giaddr", Ip4Address("0.0.0.0")),
                chaddr=self._kwargs["dhcp4__chaddr"],
                sname=self._kwargs.get("dhcp4__sname") or "",
                file=self._kwargs.get("dhcp4__file") or "",
            ),
            msg=f"Parsed header must match assembler header for case: {self._description}",
        )
        self.assertEqual(
            parser.options,
            self._kwargs["dhcp4__options"],
            msg=f"Parsed options must match assembler options for case: {self._description}",
        )


class TestDhcp4AssemblerAssembleRaises(TestCase):
    """
    The DHCPv4 assembler 'assemble()' method is a deliberate L7 stub.
    """

    def test__dhcp4__assembler__assemble_raises_not_implemented(self) -> None:
        """
        Ensure the 'assemble()' method raises NotImplementedError referencing
        the Socket API as the correct entry point.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        assembler = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x00000001,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__options=Dhcp4Options(Dhcp4OptionEnd()),
        )

        with self.assertRaises(NotImplementedError) as error:
            assembler.assemble([])

        self.assertIn(
            "not implemented for L7 protocols",
            str(error.exception),
            msg="NotImplementedError message must direct users to the Socket API.",
        )


class TestDhcp4AssemblerDefaults(TestCase):
    """
    The DHCPv4 assembler default-value and None-coalescing tests.
    """

    def test__dhcp4__assembler__defaults(self) -> None:
        """
        Ensure optional constructor parameters default to the documented zeroed
        values (0.0.0.0 addresses, empty sname/file, empty options).

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        assembler = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0xCAFEBABE,
            dhcp4__chaddr=MacAddress("00:11:22:33:44:55"),
        )

        self.assertEqual(assembler.ciaddr, Ip4Address("0.0.0.0"), msg="Default 'ciaddr' must be 0.0.0.0.")
        self.assertEqual(assembler.yiaddr, Ip4Address("0.0.0.0"), msg="Default 'yiaddr' must be 0.0.0.0.")
        self.assertEqual(assembler.siaddr, Ip4Address("0.0.0.0"), msg="Default 'siaddr' must be 0.0.0.0.")
        self.assertEqual(assembler.giaddr, Ip4Address("0.0.0.0"), msg="Default 'giaddr' must be 0.0.0.0.")
        self.assertEqual(assembler.hops, 0, msg="Default 'hops' must be 0.")
        self.assertEqual(assembler.secs, 0, msg="Default 'secs' must be 0.")
        self.assertFalse(assembler.flag_b, msg="Default 'flag_b' must be False.")
        self.assertEqual(assembler.sname, "", msg="Default 'sname' must be empty.")
        self.assertEqual(assembler.file, "", msg="Default 'file' must be empty.")
        self.assertEqual(len(assembler), DHCP4__HEADER__LEN, msg="Default assembler must be header-sized (no options).")

    def test__dhcp4__assembler__sname_and_file_none_coalesce_to_empty(self) -> None:
        """
        Ensure explicit None values for 'sname' and 'file' coalesce to empty
        strings before reaching the Dhcp4Header.

        Reference: RFC 2131 §2 (DHCP message + options assembly).
        """

        assembler = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REPLY,
            dhcp4__xid=0x00000002,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__sname=None,
            dhcp4__file=None,
        )

        self.assertEqual(assembler.sname, "", msg="'sname=None' must coalesce to empty string.")
        self.assertEqual(assembler.file, "", msg="'file=None' must coalesce to empty string.")


class TestDhcp4AssemblerOptionsTerminator(TestCase):
    """
    The DHCPv4 assembler RFC 2132 §3 trailing-End-option enforcement
    tests. When the assembler is given a non-empty 'dhcp4__options'
    block, the last option MUST be 'Dhcp4OptionEnd'. Empty options
    are deliberately permitted — the magic cookie alone marks the
    DHCP options field and an emitter sending zero options is
    constructing a degenerate (and operator-visible) DHCP message.
    """

    def test__dhcp4__assembler__options_missing_end_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with non-empty
        Dhcp4Options whose last entry is not Dhcp4OptionEnd raises
        AssertionError at construction time.

        Reference: RFC 2132 §3 ("The last option must always be
        the 'end' option.").
        """

        options_without_end = Dhcp4Options(
            Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
        )

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REQUEST,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
                dhcp4__options=options_without_end,
            )

        self.assertIn(
            "RFC 2132 §3",
            str(error.exception),
            msg="AssertionError must cite RFC 2132 §3 for the trailing-End requirement.",
        )

    def test__dhcp4__assembler__empty_options_accepted(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with empty Dhcp4Options
        is permitted — the magic cookie alone is the documented
        options-field marker, and an explicit Dhcp4OptionEnd is
        meaningful only when there is at least one preceding option.

        Reference: RFC 2131 §3 (magic cookie marks the options field;
        the End option terminates a non-empty option list).
        """

        # Should not raise.
        assembler = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x00000001,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__options=Dhcp4Options(),
        )
        self.assertEqual(
            len(assembler.options),
            0,
            msg="Empty Dhcp4Options must remain empty after construction.",
        )

    def test__dhcp4__assembler__options_with_end_last_accepted(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with a non-empty
        Dhcp4Options block whose last entry IS Dhcp4OptionEnd is
        accepted (the canonical well-formed case).

        Reference: RFC 2132 §3 (trailing End option).
        """

        # Should not raise.
        Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x00000001,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionEnd(),
            ),
        )


class TestDhcp4AssemblerAsciiSnameFile(TestCase):
    """
    The DHCPv4 assembler RFC 2131 §2 ASCII-only sname / file
    enforcement tests. The wire serialization path uses
    `bytes(value, encoding="ascii")` which raises
    UnicodeEncodeError on non-ASCII input; without an early
    construction-time check the failure would surface deep
    inside __buffer__ instead of at the assembler boundary.

    The Dhcp4Header dataclass itself permits non-ASCII because the
    parser uses `errors="replace"` to tolerantly absorb RFC 2132
    §9.3 Option Overload binary payloads on the RX path — that
    tolerance lives on RX, not TX.
    """

    def test__dhcp4__assembler__sname_non_ascii_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with a non-ASCII
        'dhcp4__sname' raises AssertionError at construction time
        rather than deferring the failure to __buffer__.

        Reference: RFC 2131 §2 (sname is a null-terminated ASCII string).
        """

        value = "café"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REQUEST,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
                dhcp4__sname=value,
            )

        self.assertEqual(
            str(error.exception),
            f"The 'dhcp4__sname' field must be ASCII. Got: {value!r}",
            msg="Unexpected non-ASCII 'sname' assert message.",
        )

    def test__dhcp4__assembler__file_non_ascii_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with a non-ASCII
        'dhcp4__file' raises AssertionError at construction time.

        Reference: RFC 2131 §2 (file is a null-terminated ASCII string).
        """

        value = "naïve.bin"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REQUEST,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
                dhcp4__file=value,
            )

        self.assertEqual(
            str(error.exception),
            f"The 'dhcp4__file' field must be ASCII. Got: {value!r}",
            msg="Unexpected non-ASCII 'file' assert message.",
        )

    def test__dhcp4__assembler__sname_file_none_accepted(self) -> None:
        """
        Ensure 'dhcp4__sname=None' / 'dhcp4__file=None' (the
        None-coalescing default path) passes the ASCII check —
        the None value coalesces to the empty string, which is
        trivially ASCII.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Should not raise.
        assembler = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x00000001,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__sname=None,
            dhcp4__file=None,
        )
        self.assertEqual(
            assembler.sname,
            "",
            msg="sname=None must coalesce to empty string and pass the ASCII check.",
        )
        self.assertEqual(
            assembler.file,
            "",
            msg="file=None must coalesce to empty string and pass the ASCII check.",
        )


class TestDhcp4AssemblerUnknownEnumReject(TestCase):
    """
    The DHCPv4 assembler TX-strict enum-domain enforcement tests.

    ProtoEnum '_missing_' materialises any unknown wire codepoint
    as a UNKNOWN_<value> pseudo-member so the parser can surface
    it via _validate_sanity. The assembler is the strict-TX
    boundary and MUST refuse to emit such pseudo-members.
    """

    def test__dhcp4__assembler__unknown_operation_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler with an unknown
        Dhcp4Operation member (e.g. value 99 synthesised via
        from_int) raises AssertionError at construction time.

        Reference: RFC 2131 §2 (op field BOOTREQUEST=1 / BOOTREPLY=2).
        """

        unknown_op = Dhcp4Operation.from_int(99)
        self.assertTrue(unknown_op.is_unknown, msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.")

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=unknown_op,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            )

        self.assertIn(
            "must be a known Dhcp4Operation",
            str(error.exception),
            msg="AssertionError must cite the Dhcp4Operation domain.",
        )

    def test__dhcp4__assembler__unknown_message_type_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler whose options block
        contains a Dhcp4OptionMessageType carrying an unknown
        Dhcp4MessageType member raises AssertionError at
        construction time.

        Reference: RFC 2132 §9.6 (Message Type option values 1..8).
        """

        unknown_msg = Dhcp4MessageType.from_int(99)
        self.assertTrue(
            unknown_msg.is_unknown,
            msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.",
        )

        options = Dhcp4Options(
            Dhcp4OptionMessageType(message_type=unknown_msg),
            Dhcp4OptionEnd(),
        )

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REQUEST,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
                dhcp4__options=options,
            )

        self.assertIn(
            "unknown Dhcp4MessageType",
            str(error.exception),
            msg="AssertionError must cite the Dhcp4MessageType domain.",
        )

    def test__dhcp4__assembler__unknown_param_req_list_element_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4Assembler whose options block
        contains a Dhcp4OptionParamReqList with an unknown
        Dhcp4OptionType element raises AssertionError at
        construction time.

        Reference: RFC 2132 §9.8 (Parameter Request List element codepoints).
        """

        options = Dhcp4Options(
            Dhcp4OptionParamReqList(
                [
                    Dhcp4OptionType.SUBNET_MASK,
                    Dhcp4OptionType.from_int(99),
                ]
            ),
            Dhcp4OptionEnd(),
        )

        with self.assertRaises(AssertionError) as error:
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REQUEST,
                dhcp4__xid=0x00000001,
                dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
                dhcp4__options=options,
            )

        self.assertIn(
            "unknown Dhcp4OptionType",
            str(error.exception),
            msg="AssertionError must cite the Dhcp4OptionType domain.",
        )

    def test__dhcp4__assembler__known_enums_accepted(self) -> None:
        """
        Ensure construction succeeds when every enum member used in
        the operation field, in the Message Type option, and in the
        Parameter Request List is a known codepoint — the
        canonical happy path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Should not raise.
        Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x00000001,
            dhcp4__chaddr=MacAddress("00:00:00:00:00:00"),
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionEnd(),
            ),
        )
