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
Tests for the IPC datagram data-channel frame codec.

pytcp/tests/unit/ipc/test__ipc__dgram_frame.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram
from pytcp.ipc.ipc__errors import IpcFrameError


class TestIpcDgramFrame(TestCase):
    """
    The IPC datagram-frame codec tests.
    """

    def test__ipc__dgram_frame__ipv4_round_trip(self) -> None:
        """
        Ensure an IPv4 (address, cmsg, payload) datagram round-trips
        through the frame codec with the address, empty cmsg list, and
        payload recovered intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            decode_dgram(encode_dgram(("10.0.1.91", 50000), b"hello")),
            (("10.0.1.91", 50000), [], b"hello"),
            msg="An IPv4 datagram frame must round-trip its address and payload.",
        )

    def test__ipc__dgram_frame__ipv6_round_trip(self) -> None:
        """
        Ensure an IPv6 (address, cmsg, payload) datagram round-trips
        through the frame codec with the address normalised and payload
        intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address, cmsg, payload = decode_dgram(encode_dgram(("2001:db8::91", 50000), b"hi6"))

        self.assertEqual(
            (address, cmsg, payload),
            (("2001:db8::91", 50000), [], b"hi6"),
            msg="An IPv6 datagram frame must round-trip its address and payload.",
        )

    def test__ipc__dgram_frame__no_address_round_trip(self) -> None:
        """
        Ensure a frame with no address (a connected-socket send) round-
        trips to a None address with its payload intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            decode_dgram(encode_dgram(None, b"connected")),
            (None, [], b"connected"),
            msg="An address-less datagram frame must round-trip to a None address.",
        )

    def test__ipc__dgram_frame__cmsg_round_trip(self) -> None:
        """
        Ensure ancillary control messages round-trip alongside the
        address and payload, so recvmsg cmsgs (IP_TOS / IP_OPTIONS /
        IPV6_TCLASS) survive the boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        cmsg = [(0, 1, b"\x10"), (41, 67, b"\x00\x00\x00\x20")]

        self.assertEqual(
            decode_dgram(encode_dgram(("10.0.1.91", 50000), b"with-cmsg", cmsg)),
            (("10.0.1.91", 50000), cmsg, b"with-cmsg"),
            msg="Ancillary cmsgs must round-trip alongside the address and payload.",
        )

    def test__ipc__dgram_frame__empty_payload(self) -> None:
        """
        Ensure a zero-length payload (a legal empty UDP datagram) round-
        trips intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            decode_dgram(encode_dgram(("10.0.1.91", 7), b"")),
            (("10.0.1.91", 7), [], b""),
            msg="An empty-payload datagram frame must round-trip.",
        )

    def test__ipc__dgram_frame__unknown_tag_rejected(self) -> None:
        """
        Ensure a frame whose address-family tag is neither absent / IPv4 /
        IPv6 is rejected rather than mis-decoded.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            decode_dgram(b"\x09rest")

    def test__ipc__dgram_frame__empty_blob_rejected(self) -> None:
        """
        Ensure an empty blob (no tag byte) is rejected rather than
        indexing past the end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            decode_dgram(b"")
