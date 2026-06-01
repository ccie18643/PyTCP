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
Module contains tests for the DHCPv4 options support code (parser, assembler,
properties, and integrity checks).

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__options.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address, Ip4Mask, Ip4Network
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4MessageType,
    Dhcp4OptionClasslessStaticRoute,
    Dhcp4OptionClientId,
    Dhcp4OptionEnd,
    Dhcp4OptionHostName,
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
    Dhcp4OptionUnknown,
)
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__LEN


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 options assembler (empty).",
            "_args": [],
            "_results": {
                "__len__": 0,
                "__str__": "",
                "__repr__": "Dhcp4Options(options=[])",
                "__bytes__": b"",
                "__bool__": False,
            },
        },
        {
            "_description": "The DHCPv4 options assembler (End only).",
            "_args": [Dhcp4OptionEnd()],
            "_results": {
                "__len__": 1,
                "__str__": "end",
                "__repr__": "Dhcp4Options(options=[Dhcp4OptionEnd()])",
                #   End : 0xff (terminator)
                "__bytes__": b"\xff",
                "__bool__": True,
            },
        },
        {
            "_description": "The DHCPv4 options assembler (message_type + End).",
            "_args": [
                Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                Dhcp4OptionEnd(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "message_type Discover, end",
                "__repr__": (
                    "Dhcp4Options(options=[Dhcp4OptionMessageType(message_type="
                    f"{Dhcp4MessageType.DISCOVER!r}), Dhcp4OptionEnd()])"
                ),
                "__bytes__": (
                    # Message Type option [RFC 2132]
                    #   Code : 0x35 (53, Message Type)
                    #   Len  : 0x01 (1 byte)
                    #   Data : 0x01 (DISCOVER)
                    b"\x35\x01\x01"
                    #   End  : 0xff
                    b"\xff"
                ),
                "__bool__": True,
            },
        },
        {
            "_description": "The DHCPv4 options assembler (rich mix with pads).",
            "_args": [
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
                Dhcp4OptionHostName("host"),
                Dhcp4OptionReqIpAddr(Ip4Address("1.2.3.4")),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.HOST_NAME,
                        Dhcp4OptionType.MESSAGE_TYPE,
                    ]
                ),
                Dhcp4OptionMessageType(Dhcp4MessageType.REQUEST),
                Dhcp4OptionEnd(),
            ],
            "_results": {
                "__len__": 6 + 10 + 6 + 6 + 9 + 1 + 1 + 6 + 6 + 4 + 3 + 1,
                "__bytes__": (
                    # Subnet Mask [RFC 2132]: Code=1, Len=4, 255.255.255.0
                    b"\x01\x04\xff\xff\xff\x00"
                    # Router [RFC 2132]: Code=3, Len=8, 192.0.2.1, 198.51.100.5
                    b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05"
                    # Server Identifier [RFC 2132]: Code=54, Len=4, 192.0.2.1
                    b"\x36\x04\xc0\x00\x02\x01"
                    # IP Address Lease Time [RFC 2132]: Code=51, Len=4, 60 s
                    b"\x33\x04\x00\x00\x00\x3c"
                    # Client Identifier [RFC 2132]: Code=61, Len=7, hw-type + MAC
                    b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01"
                    # Pad + Pad [RFC 2132]: two 1-byte 0x00 fillers
                    b"\x00\x00"
                    # Host Name [RFC 2132]: Code=12, Len=4, "host"
                    b"\x0c\x04\x68\x6f\x73\x74"
                    # Requested IP Address [RFC 2132]: Code=50, Len=4, 1.2.3.4
                    b"\x32\x04\x01\x02\x03\x04"
                    # Parameter Request List [RFC 2132]:
                    #   Code=55, Len=2, [HOST_NAME=12, MESSAGE_TYPE=53]
                    b"\x37\x02\x0c\x35"
                    # Message Type [RFC 2132]: Code=53, Len=1, REQUEST
                    b"\x35\x01\x03"
                    # End [RFC 2132]: terminator
                    b"\xff"
                ),
                "__bool__": True,
            },
        },
    ]
)
class TestDhcp4OptionsAssembler(TestCase):
    """
    The 'Dhcp4Options' class assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the 'Dhcp4Options' class object with testcase arguments.
        """

        self._options = Dhcp4Options(*self._args)

    def test__dhcp4__options__len(self) -> None:
        """
        Ensure '__len__()' returns the sum of all option lengths.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            len(self._options),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__options__str(self) -> None:
        """
        Ensure '__str__()' returns comma-separated option strings.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        if "__str__" in self._results:
            self.assertEqual(
                str(self._options),
                self._results["__str__"],
                msg=f"Unexpected __str__ for case: {self._description}",
            )

    def test__dhcp4__options__repr(self) -> None:
        """
        Ensure '__repr__()' renders the container and its options.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        if "__repr__" in self._results:
            self.assertEqual(
                repr(self._options),
                self._results["__repr__"],
                msg=f"Unexpected __repr__ for case: {self._description}",
            )

    def test__dhcp4__options__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the concatenated wire image.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            bytes(self._options),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__options__memoryview(self) -> None:
        """
        Ensure the container supports the buffer protocol.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            bytes(memoryview(self._options)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__options__bool(self) -> None:
        """
        Ensure '__bool__()' reflects whether any options are present.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            bool(self._options),
            self._results["__bool__"],
            msg=f"Unexpected __bool__ for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 options parser — single option + End.",
            "_args": [
                # Message Type [RFC 2132]: Code=53, Len=1, DISCOVER (1)
                b"\x35\x01\x01"
                # End [RFC 2132]: terminator
                b"\xff"
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options parser — rich mix, pads, trailing bytes.",
            "_args": [
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
                # Pad + Pad [RFC 2132]
                b"\x00\x00"
                # Host Name [RFC 2132]: Code=12, Len=4, "host"
                b"\x0c\x04\x68\x6f\x73\x74"
                # Requested IP Address [RFC 2132]: Code=50, Len=4, 1.2.3.4
                b"\x32\x04\x01\x02\x03\x04"
                # Parameter Request List [RFC 2132]:
                #   Code=55, Len=2, [HOST_NAME, MESSAGE_TYPE]
                b"\x37\x02\x0c\x35"
                # Message Type [RFC 2132]: Code=53, Len=1, REQUEST (3)
                b"\x35\x01\x03"
                # End [RFC 2132]: terminator
                b"\xff"
                # Trailing bytes after End — must be ignored by the parser.
                b"\x00\x00\x00"
            ],
            "_results": {
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
                    Dhcp4OptionHostName("host"),
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
            "_description": "The DHCPv4 options parser — only End marker.",
            "_args": [
                # End [RFC 2132]: terminator
                b"\xff",
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options parser — options behind End are ignored.",
            "_args": [
                # Server Identifier [RFC 2132]: Code=54, Len=4, 192.0.2.1
                b"\x36\x04\xc0\x00\x02\x01"
                # End [RFC 2132]: terminator
                b"\xff"
                # Subnet Mask after End — must be ignored
                b"\x01\x04\xff\xff\xff\x00",
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options parser — minimum-length Client Id with Host Name.",
            "_args": [
                # Client Identifier [RFC 2132 §9.14]: Code=61, Len=2 (RFC-minimum),
                # 1-byte htype + 1-byte ID.
                b"\x3d\x02\x01\xff"
                # Host Name [RFC 2132]: Code=12, Len=1 (RFC-minimum, single 'a')
                b"\x0c\x01\x61"
                # End [RFC 2132]: terminator
                b"\xff",
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionClientId(b"\x01\xff"),
                    Dhcp4OptionHostName("a"),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options parser — unknown option code falls back to Unknown.",
            "_args": [
                # Unknown DHCPv4 option: Code=254, Len=3, data='ABC'
                b"\xfe\x03\x41\x42\x43"
                # End [RFC 2132]: terminator
                b"\xff",
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionUnknown(
                        type=Dhcp4OptionType.from_int(254),
                        data=b"ABC",
                    ),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options parser — runs off the end of the buffer without End.",
            "_args": [
                # Subnet Mask [RFC 2132]: Code=1, Len=4, 255.255.255.0
                b"\x01\x04\xff\xff\xff\x00"
            ],
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
                ),
            },
        },
    ]
)
class TestDhcp4OptionsParser(TestCase):
    """
    The 'Dhcp4Options' class parser tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__options__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' builds the expected Dhcp4Options container.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        dhcp4_options = Dhcp4Options.from_buffer(*self._args)

        self.assertEqual(
            dhcp4_options,
            self._results["options"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionsValidateIntegrity(TestCase):
    """
    The 'Dhcp4Options.validate_integrity()' static method tests.

    The method scans the frame starting at offset DHCP4__HEADER__LEN (240) up
    to hlen, so test frames are constructed as 240 zero header bytes followed
    by the option stream under test.
    """

    def _frame(self, options: bytes) -> bytes:
        """
        Build a DHCPv4 frame (zero-filled header + provided option bytes).
        """

        return b"\x00" * DHCP4__HEADER__LEN + options

    def test__dhcp4__options__validate_integrity__all_pads_and_end(self) -> None:
        """
        Ensure Pad bytes are consumed 1-at-a-time and End terminates scanning.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        # Pad, Pad, Pad, End — all known, all valid.
        frame = self._frame(b"\x00\x00\x00\xff")

        Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

    def test__dhcp4__options__validate_integrity__well_formed_mix(self) -> None:
        """
        Ensure a well-formed mix of TLV options and an End marker passes.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        frame = self._frame(
            # Subnet Mask [RFC 2132]: Code=1, Len=4, 255.255.255.0
            b"\x01\x04\xff\xff\xff\x00"
            # Message Type [RFC 2132]: Code=53, Len=1, DISCOVER
            b"\x35\x01\x01"
            # End
            b"\xff"
        )

        Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

    def test__dhcp4__options__validate_integrity__missing_end_is_accepted(
        self,
    ) -> None:
        """
        Ensure a frame with no End marker passes integrity as long as the
        offset walk doesn't exceed hlen. The loop simply falls off the end.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        frame = self._frame(b"\x01\x04\xff\xff\xff\x00")

        Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

    def test__dhcp4__options__validate_integrity__length_byte_zero_accepted(
        self,
    ) -> None:
        """
        Ensure an option whose length byte is 0 passes integrity. The
        DHCPv4 wire format (RFC 2132) uses the length byte as data length
        only; 0 bytes of data is legal. End terminates the scan.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        # Server Identifier with Len=0 (no data), then End.
        frame = self._frame(b"\x36\x00\xff")

        Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

    def test__dhcp4__options__validate_integrity__length_byte_one_accepted(
        self,
    ) -> None:
        """
        Ensure an option with length byte = 1 passes integrity. The length
        byte encodes data length only, so 1 byte of data is legal.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        # Server Identifier with Len=1, 1 data byte, then End.
        frame = self._frame(b"\x36\x01\x00\xff")

        Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

    def test__dhcp4__options__validate_integrity__missing_length_byte(
        self,
    ) -> None:
        """
        Ensure a frame whose final option is truncated at its type byte
        (length byte missing) raises Dhcp4IntegrityError.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        # A single type byte at the end of the frame — length byte is absent.
        frame = self._frame(b"\x36")

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

        expected_offset = DHCP4__HEADER__LEN
        hlen = len(frame)
        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 option is missing its "
            f"length byte. Got: offset={expected_offset}, hlen={hlen}",
            msg="Unexpected integrity error for length-byte-truncated option.",
        )

    def test__dhcp4__options__validate_integrity__length_extends_past_hlen(
        self,
    ) -> None:
        """
        Ensure an option whose data length extends past hlen raises
        Dhcp4IntegrityError. Total option size on the wire is
        DHCP4__OPTION__LEN + data_len (2-byte header + data).

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        # Client Identifier claims Len=10 but only 2 data bytes are present.
        options = b"\x3d\x0a\xaa\xbb"
        frame = self._frame(options)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Options.validate_integrity(frame=frame, hlen=len(frame))

        expected_offset = DHCP4__HEADER__LEN + 2 + 0x0A
        hlen = len(frame)
        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 option length must not extend past "
            f"the header length. Got: offset={expected_offset}, hlen={hlen}",
            msg="Unexpected integrity error for over-long option.",
        )


class TestDhcp4OptionsProperties(TestCase):
    """
    The 'Dhcp4Options' per-option accessor property tests.
    """

    def test__dhcp4__options__properties__all_absent(self) -> None:
        """
        Ensure every accessor returns None when the corresponding option is
        absent.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        options = Dhcp4Options(Dhcp4OptionEnd())

        self.assertIsNone(options.classless_static_route, msg="classless_static_route must be None.")
        self.assertIsNone(options.host_name, msg="host_name must be None.")
        self.assertIsNone(options.message_type, msg="message_type must be None.")
        self.assertIsNone(options.param_req_list, msg="param_req_list must be None.")
        self.assertIsNone(options.req_ip_addr, msg="req_ip_addr must be None.")
        self.assertIsNone(options.router, msg="router must be None.")
        self.assertIsNone(options.server_id, msg="server_id must be None.")
        self.assertIsNone(options.subnet_mask, msg="subnet_mask must be None.")

    def test__dhcp4__options__properties__all_present(self) -> None:
        """
        Ensure every accessor returns the value carried by the corresponding
        option when present.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        options = Dhcp4Options(
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            Dhcp4OptionServerId(Ip4Address("192.0.2.254")),
            Dhcp4OptionHostName("example"),
            Dhcp4OptionReqIpAddr(Ip4Address("10.0.0.7")),
            Dhcp4OptionParamReqList(
                [
                    Dhcp4OptionType.SUBNET_MASK,
                    Dhcp4OptionType.ROUTER,
                ]
            ),
            Dhcp4OptionMessageType(Dhcp4MessageType.OFFER),
            Dhcp4OptionEnd(),
        )

        self.assertEqual(
            options.host_name,
            "example",
            msg="host_name must reflect the Host Name option.",
        )
        self.assertEqual(
            options.message_type,
            Dhcp4MessageType.OFFER,
            msg="message_type must reflect the Message Type option.",
        )
        self.assertEqual(
            options.param_req_list,
            [Dhcp4OptionType.SUBNET_MASK, Dhcp4OptionType.ROUTER],
            msg="param_req_list must reflect the Parameter Request List option.",
        )
        self.assertEqual(
            options.req_ip_addr,
            Ip4Address("10.0.0.7"),
            msg="req_ip_addr must reflect the Requested IP Address option.",
        )
        self.assertEqual(
            options.router,
            [Ip4Address("192.0.2.1")],
            msg="router must reflect the Router option.",
        )
        self.assertEqual(
            options.server_id,
            Ip4Address("192.0.2.254"),
            msg="server_id must reflect the Server Identifier option.",
        )
        self.assertEqual(
            options.subnet_mask,
            Ip4Mask("255.255.255.0"),
            msg="subnet_mask must reflect the Subnet Mask option.",
        )

    def test__dhcp4__options__classless_static_route_present(self) -> None:
        """
        Ensure the 'classless_static_route' accessor returns the route
        list carried by the Classless Static Route option when present.

        Reference: RFC 3442 (Classless Static Route option).
        """

        options = Dhcp4Options(
            Dhcp4OptionClasslessStaticRoute(
                [
                    (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                    (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
                ]
            ),
            Dhcp4OptionEnd(),
        )

        self.assertEqual(
            options.classless_static_route,
            [
                (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
            ],
            msg="classless_static_route must reflect the Classless Static Route option.",
        )

    def test__dhcp4__options__properties__first_occurrence_wins(self) -> None:
        """
        Ensure each accessor returns the first matching option when duplicates
        are present (the loop returns on first match).

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        options = Dhcp4Options(
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.0.0")),
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            Dhcp4OptionServerId(Ip4Address("10.0.0.1")),
            Dhcp4OptionServerId(Ip4Address("10.0.0.2")),
            Dhcp4OptionEnd(),
        )

        self.assertEqual(
            options.subnet_mask,
            Ip4Mask("255.255.0.0"),
            msg="subnet_mask must return the first Subnet Mask option.",
        )
        self.assertEqual(
            options.server_id,
            Ip4Address("10.0.0.1"),
            msg="server_id must return the first Server Identifier option.",
        )


class TestDhcp4OptionsClasslessStaticRouteConcatenation(TestCase):
    """
    The 'Dhcp4Options' RFC 3396 concatenation tests for the
    Classless Static Route option.
    """

    def test__dhcp4__options__concatenates_split_classless_static_route(self) -> None:
        """
        Ensure two option-121 instances split mid-descriptor are
        concatenated by their data and decoded as one route list
        (per-instance decoding would fail on the split chunk).

        Reference: RFC 3442 (Classless Static Route is concatenation-requiring).
        Reference: RFC 3396 (DHCP option concatenation).
        """

        # Logical data = route(0.0.0.0/0 via 192.0.2.1) [5 bytes]
        #              + route(10.0.0.0/8 via 10.0.0.1)  [6 bytes].
        # Split after 4 bytes — mid the first route — across two
        # option-121 instances; the first instance's 4-byte data is
        # below the 5-octet single-option minimum on its own.
        buffer = (
            # 121, len 4, first 4 data bytes (00 c0 00 02)
            b"\x79\x04\x00\xc0\x00\x02"
            # 121, len 7, remaining data (01 08 0a 0a 00 00 01)
            b"\x79\x07\x01\x08\x0a\x0a\x00\x00\x01"
            # End
            b"\xff"
        )

        self.assertEqual(
            Dhcp4Options.from_buffer(buffer).classless_static_route,
            [
                (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
            ],
            msg="Split option-121 instances must be joined by data and decoded as one route list.",
        )

    def test__dhcp4__options__single_classless_static_route_emitted(self) -> None:
        """
        Ensure several option-121 instances collapse to exactly one
        Classless Static Route option in the parsed container.

        Reference: RFC 3396 (DHCP option concatenation).
        """

        buffer = b"\x79\x04\x00\xc0\x00\x02" b"\x79\x07\x01\x08\x0a\x0a\x00\x00\x01" b"\xff"

        options = Dhcp4Options.from_buffer(buffer)
        count = sum(1 for option in options._options if isinstance(option, Dhcp4OptionClasslessStaticRoute))
        self.assertEqual(
            count,
            1,
            msg="Concatenated option-121 instances must yield exactly one option object.",
        )

    def test__dhcp4__options__rejects_empty_classless_static_route(self) -> None:
        """
        Ensure an option-121 instance carrying no route data is
        rejected with a typed integrity error rather than leaking an
        AssertionError from the empty-route constructor.

        Reference: RFC 3442 (minimum length 5 bytes).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Options.from_buffer(b"\x79\x00\xff")

        self.assertIn(
            "must carry at least one route",
            str(error.exception),
            msg="An empty Classless Static Route option must raise a typed integrity error.",
        )


class TestDhcp4OptionsBehavior(TestCase):
    """
    The 'Dhcp4Options' collection and equality behavior tests.
    """

    def setUp(self) -> None:
        """
        Initialize a representative Dhcp4Options object for the behavior tests.
        """

        self._server_id = Dhcp4OptionServerId(Ip4Address("192.0.2.1"))
        self._message_type = Dhcp4OptionMessageType(Dhcp4MessageType.ACK)
        self._end = Dhcp4OptionEnd()
        self._options = Dhcp4Options(
            self._server_id,
            self._message_type,
            self._end,
        )

    def test__dhcp4__options__equality(self) -> None:
        """
        Ensure two Dhcp4Options built from equal inputs compare equal.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            self._options,
            Dhcp4Options(
                Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                Dhcp4OptionMessageType(Dhcp4MessageType.ACK),
                Dhcp4OptionEnd(),
            ),
            msg="Dhcp4Options with identical options must compare equal.",
        )

    def test__dhcp4__options__inequality_different_options(self) -> None:
        """
        Ensure Dhcp4Options with different option lists compare unequal.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertNotEqual(
            self._options,
            Dhcp4Options(
                Dhcp4OptionServerId(Ip4Address("192.0.2.2")),
                Dhcp4OptionMessageType(Dhcp4MessageType.ACK),
                Dhcp4OptionEnd(),
            ),
            msg="Dhcp4Options with different options must compare unequal.",
        )

    def test__dhcp4__options__inequality_different_order(self) -> None:
        """
        Ensure Dhcp4Options with options in different order compare unequal —
        the underlying list is order-sensitive.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertNotEqual(
            self._options,
            Dhcp4Options(
                self._message_type,
                self._server_id,
                self._end,
            ),
            msg="Dhcp4Options with reordered options must compare unequal.",
        )

    def test__dhcp4__options__inequality_other_type(self) -> None:
        """
        Ensure Dhcp4Options compare unequal to a non-Dhcp4Options value.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertNotEqual(
            self._options,
            [self._server_id, self._message_type, self._end],
            msg="Dhcp4Options must not compare equal to a plain list.",
        )

    def test__dhcp4__options__contains(self) -> None:
        """
        Ensure '__contains__' reports membership of a specific option value.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertIn(
            self._server_id,
            self._options,
            msg="Server Identifier option must be reported as present.",
        )
        self.assertNotIn(
            Dhcp4OptionServerId(Ip4Address("203.0.113.1")),
            self._options,
            msg="A different Server Identifier option must not be reported as present.",
        )

    def test__dhcp4__options__iter(self) -> None:
        """
        Ensure iteration yields the options in insertion order.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            list(self._options),
            [self._server_id, self._message_type, self._end],
            msg="Iteration must yield options in insertion order.",
        )

    def test__dhcp4__options__getitem(self) -> None:
        """
        Ensure '__getitem__' returns the option at the given index.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            self._options[0],
            self._server_id,
            msg="Index 0 must return the first inserted option.",
        )
        self.assertEqual(
            self._options[-1],
            self._end,
            msg="Index -1 must return the last inserted option.",
        )

    def test__dhcp4__options__index(self) -> None:
        """
        Ensure 'index()' returns the position of a given option.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertEqual(
            self._options.index(self._message_type),
            1,
            msg="Message Type option must be at position 1.",
        )

    def test__dhcp4__options__bool_empty(self) -> None:
        """
        Ensure empty Dhcp4Options is falsy.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertFalse(
            bool(Dhcp4Options()),
            msg="Empty Dhcp4Options must be falsy.",
        )

    def test__dhcp4__options__bool_non_empty(self) -> None:
        """
        Ensure a non-empty Dhcp4Options is truthy.

        Reference: RFC 2132 §2 (DHCP options encoding).
        """

        self.assertTrue(
            bool(self._options),
            msg="Non-empty Dhcp4Options must be truthy.",
        )
