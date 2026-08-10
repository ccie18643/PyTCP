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

ver 3.0.10
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


class TestIpcDgramFrame__WireGoldens(TestCase):
    """
    Exact wire-byte goldens and boundary cases that byte-pin the
    datagram frame format. Round-trip tests alone leave the format
    free: a tag value or field-length constant used symmetrically in
    encode + decode survives a round trip, and the framing-offset
    arithmetic and truncation bounds are only exercised at lengths
    where '+' is indistinguishable from a bitwise op.
    """

    def test__dgram__encode_exact_wire_bytes(self) -> None:
        """
        Ensure each address family and the no-address form encode to
        the exact wire bytes — pinning the tag values (0 / 4 / 6), the
        2-byte big-endian port, the packed address, and the cmsg-count
        byte.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            encode_dgram(None, b"hello"),
            bytes.fromhex("000068656c6c6f"),
            msg="None-address frame must be tag 0x00 + ncmsg 0x00 + payload.",
        )
        self.assertEqual(
            encode_dgram(("10.0.0.1", 80), b"hi"),
            bytes.fromhex("0400500a000001006869"),
            msg="IPv4 frame must be tag 0x04 + port 0x0050 + 0x0a000001 + ncmsg 0x00 + payload.",
        )
        self.assertEqual(
            encode_dgram(("::1", 53), b""),
            bytes.fromhex("0600350000000000000000000000000000000100"),
            msg="IPv6 frame must be tag 0x06 + port 0x0035 + 16-byte ::1 + ncmsg 0x00.",
        )

    def test__dgram__encode_cmsg_exact_wire_bytes(self) -> None:
        """
        Ensure a control-message entry encodes as 2-byte level, 2-byte
        type, 2-byte data length, then the data — and that the cmsg
        count byte reflects the entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            encode_dgram(("10.0.0.1", 80), b"x", [(1, 2, b"abc")]),
            bytes.fromhex("0400500a0000010100010002000361626378"),
            msg="cmsg frame must carry ncmsg 0x01 + level/type/len 0x0001/0x0002/0x0003 + 'abc' + payload.",
        )

    def test__dgram__roundtrip_multiple_cmsg(self) -> None:
        """
        Ensure a frame with multiple control messages round-trips with
        the exact (level, type, data) tuples and the trailing payload,
        exercising the cmsg-metadata-length offset arithmetic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        blob = encode_dgram(("10.0.0.1", 80), b"payload", [(41, 12, b"\x05\x00"), (0, 8, b"\x01")])
        self.assertEqual(
            decode_dgram(blob),
            (("10.0.0.1", 80), [(41, 12, b"\x05\x00"), (0, 8, b"\x01")], b"payload"),
            msg="multi-cmsg frame must round-trip address, cmsg tuples, and payload exactly.",
        )

    def test__dgram__unknown_address_tag_rejected(self) -> None:
        """
        Ensure a tag that is neither 0 / 4 / 6 is rejected, pinning the
        exact tag-equality dispatch against a relational edit that would
        misroute an out-of-set tag into the IPv4 or IPv6 branch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad in (b"\x03\x00\x50\x0a\x00\x00\x01", b"\x07" + b"\x00" * 20):
            with self.subTest(tag=bad[0]):
                with self.assertRaises(IpcFrameError):
                    decode_dgram(bad)

    def test__dgram__truncated_frames_rejected(self) -> None:
        """
        Ensure frames truncated before the end of the address or before
        the cmsg count are rejected, pinning the length-bound checks.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            decode_dgram(b"\x04\x00\x50\x0a\x00")  # IPv4, address cut short
        with self.assertRaises(IpcFrameError):
            decode_dgram(encode_dgram(("10.0.0.1", 80), b"")[:7])  # tag+port+ip, no ncmsg byte
