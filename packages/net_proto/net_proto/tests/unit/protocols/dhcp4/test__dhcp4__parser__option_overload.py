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
Module contains parser-side tests for the RFC 2132 §9.3 DHCPv4
Option Overload feature — when option 52 is present in the
main option block, the BOOTP 'file' and/or 'sname' fields carry
additional DHCP options that the parser must merge into the
unified view exposed by 'Dhcp4Parser.options'.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__option_overload.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip4Mask, MacAddress
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4MessageType,
    Dhcp4Operation,
    Dhcp4OptionEnd,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionMessageType,
    Dhcp4OptionOverload,
    Dhcp4OptionOverloadValue,
    Dhcp4OptionRouter,
    Dhcp4OptionServerId,
    Dhcp4OptionSubnetMask,
    Dhcp4Parser,
)
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options


def _build_overload_frame(
    *,
    overload_value: int,
    sname_options: bytes = b"",
    file_options: bytes = b"",
) -> memoryview:
    """
    Build a DHCPv4 reply frame whose BOOTP 'sname' and/or 'file'
    fields contain the supplied option bytes (raw, including
    type+length headers). The main option block carries the
    Option Overload option pointing the parser at the supplied
    extras.

    The assembler refuses non-ASCII sname/file inputs at
    construction time, so we assemble a minimal valid frame
    first and then patch the raw bytes at the canonical header
    offsets (44 for sname, 108 for file).
    """

    # ACK message-type requires a Server Identifier per
    # RFC 2131 §3 Table 3 / §4.3.6; include it in the main option
    # block (even when the test's payload of interest lives in
    # the overloaded sname/file) so the parser's sanity check
    # accepts the wrapping frame.
    frame = bytearray(
        bytes(
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REPLY,
                dhcp4__xid=0x11223344,
                dhcp4__yiaddr=Ip4Address("10.0.0.100"),
                dhcp4__chaddr=MacAddress("02:00:00:00:00:01"),
                dhcp4__options=Dhcp4Options(
                    Dhcp4OptionMessageType(message_type=Dhcp4MessageType.ACK),
                    Dhcp4OptionServerId(server_id=Ip4Address("10.0.0.200")),
                    Dhcp4OptionOverload(Dhcp4OptionOverloadValue(overload_value)),
                    Dhcp4OptionEnd(),
                ),
            )
        )
    )

    # Direct overlay of the BOOTP fields. 'sname' is 64 bytes at
    # offset 44; 'file' is 128 bytes at offset 108. Pad both to
    # their full length so the surrounding bytes stay zero.
    sname_buf = sname_options + b"\x00" * (64 - len(sname_options))
    file_buf = file_options + b"\x00" * (128 - len(file_options))
    frame[44 : 44 + 64] = sname_buf
    frame[108 : 108 + 128] = file_buf

    return memoryview(bytes(frame))


class TestDhcp4ParserOptionOverload(TestCase):
    """
    The DHCPv4 parser Option Overload integration tests.
    """

    def test__parser__no_overload__sname_file_stay_inert(self) -> None:
        """
        Ensure that without Option Overload, the parser does NOT
        attempt to interpret the 'file' or 'sname' BOOTP fields as
        DHCP options. Pins the negative-case invariant so the
        overload code path is genuinely gated on option 52.

        Reference: RFC 2132 §9.3 (overload feature is opt-in).
        """

        # Main options carry server_id 10.0.0.200 (the RFC-required
        # server identifier for an ACK message); 'sname' is patched
        # with a DIFFERENT server_id 10.0.0.254. Without overload
        # signalling, the parser must surface the main-block value
        # and ignore the 'sname'-resident option entirely.
        frame = bytes(
            Dhcp4Assembler(
                dhcp4__operation=Dhcp4Operation.REPLY,
                dhcp4__xid=0x11223344,
                dhcp4__yiaddr=Ip4Address("10.0.0.100"),
                dhcp4__chaddr=MacAddress("02:00:00:00:00:01"),
                dhcp4__options=Dhcp4Options(
                    Dhcp4OptionMessageType(message_type=Dhcp4MessageType.ACK),
                    Dhcp4OptionServerId(server_id=Ip4Address("10.0.0.200")),
                    Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask("255.255.255.0")),
                    Dhcp4OptionEnd(),
                ),
            )
        )
        # Force-overwrite the full 64-byte 'sname' field with an
        # option block padded out to its exact length. In the
        # absence of option 52 these bytes MUST be ignored.
        sname_replacement = bytes(Dhcp4OptionServerId(server_id=Ip4Address("10.0.0.254"))) + bytes(Dhcp4OptionEnd())
        patched = bytearray(frame)
        patched[44 : 44 + 64] = sname_replacement + b"\x00" * (64 - len(sname_replacement))

        packet = Dhcp4Parser(memoryview(bytes(patched)))

        self.assertEqual(
            packet.subnet_mask,
            Ip4Mask("255.255.255.0"),
            msg="The main-block Subnet Mask must still parse correctly.",
        )
        self.assertEqual(
            packet.server_id,
            Ip4Address("10.0.0.200"),
            msg=(
                "Without Option Overload, the main-block server_id must be returned; "
                "the 'sname'-resident server_id (10.0.0.254) must be ignored entirely."
            ),
        )

    def test__parser__overload_file_only__file_options_visible(self) -> None:
        """
        Ensure that with overload=1, options embedded in the BOOTP
        'file' field are parsed and merged into the unified options
        view. 'sname' is left inert.

        Reference: RFC 2132 §9.3 (overload value 1 = file only).
        """

        # 'file' carries Router; 'sname' carries Subnet Mask. With
        # overload=1, only 'file's extras are merged — the sname
        # Subnet Mask must remain invisible. The main option block
        # (built by `_build_overload_frame`) carries the
        # RFC-required Server Identifier so the parser's sanity
        # check accepts the ACK wrapping frame.
        file_options = bytes(Dhcp4OptionRouter(routers=[Ip4Address("10.0.0.1")])) + bytes(Dhcp4OptionEnd())
        sname_options = bytes(Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask("255.255.0.0"))) + bytes(Dhcp4OptionEnd())

        frame = _build_overload_frame(
            overload_value=1,
            file_options=file_options,
            sname_options=sname_options,
        )

        packet = Dhcp4Parser(frame)

        self.assertEqual(
            packet.router,
            [Ip4Address("10.0.0.1")],
            msg="Router embedded in 'file' must be merged into the unified options view.",
        )
        # The sname Subnet Mask must NOT be visible because overload=1
        # excludes 'sname'.
        self.assertIsNone(
            packet.subnet_mask,
            msg=("With overload=1, the 'sname'-resident Subnet Mask must be ignored " "(file-only overlay)."),
        )

    def test__parser__overload_sname_only__sname_options_visible(self) -> None:
        """
        Ensure that with overload=2, options embedded in the BOOTP
        'sname' field are parsed and merged into the unified options
        view. 'file' is left inert.

        Reference: RFC 2132 §9.3 (overload value 2 = sname only).
        """

        # 'sname' carries Lease Time; 'file' carries Subnet Mask.
        # With overload=2, only 'sname's extras are merged — the
        # file Subnet Mask must remain invisible. The main option
        # block carries the RFC-required Server Identifier so the
        # parser accepts the ACK frame.
        sname_options = bytes(Dhcp4OptionLeaseTime(7200)) + bytes(Dhcp4OptionEnd())
        file_options = bytes(Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask("255.255.0.0"))) + bytes(Dhcp4OptionEnd())

        frame = _build_overload_frame(
            overload_value=2,
            sname_options=sname_options,
            file_options=file_options,
        )

        packet = Dhcp4Parser(frame)

        self.assertEqual(
            packet.lease_time,
            7200,
            msg="Lease-time embedded in 'sname' must be merged into the unified options view.",
        )
        self.assertIsNone(
            packet.subnet_mask,
            msg=("With overload=2, the 'file'-resident Subnet Mask must be ignored " "(sname-only overlay)."),
        )

    def test__parser__overload_both__both_fields_merged(self) -> None:
        """
        Ensure that with overload=3, options from BOTH 'file' and
        'sname' are merged into the unified options view. This is
        the maximum-capacity overload mode (~190 bytes of extras).

        Reference: RFC 2132 §9.3 (overload value 3 = both fields).
        """

        # 'file' carries Lease Time; 'sname' carries Router. With
        # overload=3, both extras must be merged into the unified
        # options view alongside the main-block options (which
        # already carry the RFC-required Server Identifier).
        file_options = bytes(Dhcp4OptionLeaseTime(7200)) + bytes(Dhcp4OptionEnd())
        sname_options = bytes(
            Dhcp4OptionRouter(routers=[Ip4Address("10.0.0.1")]),
        ) + bytes(Dhcp4OptionEnd())

        frame = _build_overload_frame(
            overload_value=3,
            file_options=file_options,
            sname_options=sname_options,
        )

        packet = Dhcp4Parser(frame)

        self.assertEqual(
            packet.lease_time,
            7200,
            msg="With overload=3, the 'file'-resident Lease Time must be merged.",
        )
        self.assertEqual(
            packet.router,
            [Ip4Address("10.0.0.1")],
            msg="With overload=3, the 'sname'-resident router must be merged.",
        )


class TestDhcp4ParserOptionOverloadHostileBlob(TestCase):
    """
    The DHCPv4 parser Option Overload hostile-blob safety tests.
    A server signalling Option Overload reuses the BOOTP
    'sname' / 'file' fields for additional DHCP options; the
    parser's overload pass must run the same TLV integrity
    walker against the re-extracted slice that protects the
    main option block, so a malformed sub-option raises a
    typed Dhcp4IntegrityError rather than walking past the
    slice end.
    """

    def test__parser__overload_sname_with_length_past_slice_end_rejected(self) -> None:
        """
        Ensure a Dhcp4Parser invocation against a frame whose
        overloaded 'sname' field carries an option whose Length
        byte extends past the 64-byte slice end raises
        Dhcp4IntegrityError. Without the pre-walk safety check
        the dispatch loop would over-read the slice and silently
        truncate the option payload.

        Reference: RFC 2132 §9.3 (overloaded BOOTP fields carry a full options sub-block).
        """

        # Hostile sname: Message Type (53) with Length=0xFF, which
        # asserts 257 trailing bytes but the sname slice is only
        # 64 bytes.
        hostile_sname = b"\x35\xff"

        frame = _build_overload_frame(
            overload_value=2,  # sname carries options
            sname_options=hostile_sname,
        )

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "option length must not extend past the header length",
            str(error.exception),
            msg="Hostile sname must be rejected with typed Dhcp4IntegrityError.",
        )

    def test__parser__overload_file_with_missing_length_byte_rejected(self) -> None:
        """
        Ensure a Dhcp4Parser invocation against a frame whose
        overloaded 'file' field carries a non-Pad, non-End option
        whose length byte does not exist within the 128-byte
        slice (option type appears as the slice's last byte)
        raises Dhcp4IntegrityError.

        Reference: RFC 2132 §9.3 (overloaded BOOTP fields carry a full options sub-block).
        """

        # Hostile file: 127 PAD bytes then a single Message Type
        # type byte at offset 127 — the length byte would live at
        # offset 128, past the 128-byte file slice end.
        hostile_file = b"\x00" * 127 + b"\x35"

        frame = _build_overload_frame(
            overload_value=1,  # file carries options
            file_options=hostile_file,
        )

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "missing its length byte",
            str(error.exception),
            msg="Hostile file with missing length byte must be rejected with typed Dhcp4IntegrityError.",
        )
