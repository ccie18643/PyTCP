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
Tests for the IPC AF_PACKET data-channel frame codec.

pytcp/tests/unit/ipc/test__ipc__packet_frame.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class TestIpcPacketFrame(TestCase):
    """
    The IPC AF_PACKET-frame codec tests.
    """

    def test__ipc__packet_frame__round_trip(self) -> None:
        """
        Ensure a (sockaddr_ll, frame) pair round-trips through the codec
        with the address fields and the verbatim frame recovered intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(
            ifindex=2,
            ethertype=EtherType.ARP,
            pkttype=PacketType.PACKET_BROADCAST,
            mac=MacAddress("02:00:00:00:00:91"),
        )

        self.assertEqual(
            decode_packet(encode_packet(sockaddr_ll, b"\xaa\xbb\xcc frame")),
            (sockaddr_ll, b"\xaa\xbb\xcc frame"),
            msg="An AF_PACKET frame must round-trip its sockaddr_ll and verbatim frame.",
        )

    def test__ipc__packet_frame__empty_frame(self) -> None:
        """
        Ensure a header-only blob (zero-length frame) decodes to an empty
        frame rather than indexing past the end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(ethertype=EtherType.IP4, mac=MacAddress("02:00:00:00:00:07"))

        self.assertEqual(
            decode_packet(encode_packet(sockaddr_ll, b"")),
            (sockaddr_ll, b""),
            msg="An AF_PACKET frame with an empty frame body must round-trip.",
        )

    def test__ipc__packet_frame__truncated_header_rejected(self) -> None:
        """
        Ensure a blob shorter than the fixed sockaddr_ll header is
        rejected rather than mis-decoded.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            decode_packet(b"\x00\x00\x00")
