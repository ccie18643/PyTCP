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
This module contains integrity / sanity tests for the IGMP packet
parser dispatch.

net_proto/tests/unit/protocols/igmp/test__igmp__parser__integrity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from unittest import TestCase

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__errors import (
    IgmpIntegrityError,
    IgmpSanityError,
)
from net_proto.protocols.igmp.igmp__parser import IgmpParser


def _packet_rx(frame: bytes, *, payload_len: int | None = None) -> PacketRx:
    """Build a PacketRx with a stubbed IPv4 layer for IGMP parsing."""

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = SimpleNamespace(  # type: ignore[assignment]
        payload_len=len(frame) if payload_len is None else payload_len,
    )

    return packet_rx


class TestIgmpParserIntegrity(TestCase):
    """
    The IGMP packet parser integrity / sanity dispatch tests.
    """

    def test__igmp__parser__rejects_short_frame(self) -> None:
        """
        Ensure a frame whose IPv4 payload is shorter than the 8-octet
        IGMP minimum is rejected.

        Reference: RFC 3376 §4 (IGMP minimum message length).
        """

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpParser(_packet_rx(b"\x16\x00\x00\x00\xef\x01\x01", payload_len=7))

        self.assertIn("IGMP__MESSAGE__MIN_LEN <= self._ip4__payload_len", str(error.exception))

    def test__igmp__parser__rejects_bad_checksum(self) -> None:
        """
        Ensure a frame whose IGMP checksum does not verify is rejected.

        Reference: RFC 3376 §4.1.2 (checksum MUST be verified on receipt).
        """

        # A V2 Report with a deliberately wrong checksum (0xffff).
        frame = b"\x16\x00\xff\xff\xef\x01\x01\x01"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpParser(_packet_rx(frame))

        self.assertIn("checksum must be valid", str(error.exception))

    def test__igmp__parser__unknown_type_rejected_at_sanity(self) -> None:
        """
        Ensure an unrecognised IGMP type (valid checksum, valid length)
        is routed to the unknown carrier and rejected at sanity so the
        RX handler silently drops it.

        Reference: RFC 3376 §4 (unrecognized message types silently ignored).
        """

        # Unknown type 0x99 with a valid checksum over the 8-octet frame.
        body = b"\x99\x00\x00\x00\x00\x00\x00\x00"
        cksum = inet_cksum(body)
        frame = body[:2] + cksum.to_bytes(2, "big") + body[4:]

        with self.assertRaises(IgmpSanityError) as error:
            IgmpParser(_packet_rx(frame))

        self.assertIn("must be one of", str(error.exception))
