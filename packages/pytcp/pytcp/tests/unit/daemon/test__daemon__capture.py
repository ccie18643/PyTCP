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
This module contains unit tests for the daemon capture writer
('DaemonCapture'): the boot-time background drain that reads every frame
off an in-daemon AF_PACKET socket, decodes it, and writes a rebased,
direction-tagged tcpdump-style line to a text sink. The capture socket is
injected so the drain / format / rebase logic is tested with crafted
frames and no running daemon.

pytcp/tests/unit/daemon/test__daemon__capture.py

ver 3.0.10
"""

import io
import threading
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto import EthernetAssembler, Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp.cli.cli__tcpdump import pcap_global_header, pcap_record
from pytcp.daemon.daemon__capture import DaemonCapture
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

_SRC_MAC = MacAddress("02:00:00:00:00:07")
_DST_MAC = MacAddress("02:00:00:00:00:91")
_SRC4 = Ip4Address("10.0.1.7")
_DST4 = Ip4Address("10.0.1.91")


def _udp_frame() -> bytes:
    """
    Build an IPv4/UDP frame from 10.0.1.7:7 to 10.0.1.91:12345, payload
    'hello'.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_SRC4,
                ip4__dst=_DST4,
                ip4__payload=UdpAssembler(udp__sport=7, udp__dport=12345, udp__payload=b"hello"),
            ),
        )
    )


class _FakeCaptureSocket:
    """
    A fake AF_PACKET capture socket: 'recvfrom' returns a fixed queue of
    '(frame, sockaddr_ll)' pairs, then signals exhaustion and idles by
    raising 'TimeoutError' each subsequent poll, so the drain loop keeps
    spinning until stopped.
    """

    def __init__(self, packets: list[tuple[bytes, SockAddrLl]], drained: threading.Event, /) -> None:
        self._packets = list(packets)
        self._drained = drained

    def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        if self._packets:
            return self._packets.pop(0)
        self._drained.set()
        raise TimeoutError("idle")


class TestDaemonCapture(TestCase):
    """
    The daemon capture-writer tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build an outbound then an inbound UDP capture pair and a binary sink.
        """

        self._drained = threading.Event()
        self._packets = [
            (_udp_frame(), SockAddrLl(pkttype=PacketType.PACKET_OUTGOING)),
            (_udp_frame(), SockAddrLl(pkttype=PacketType.PACKET_HOST)),
        ]
        self._sink = io.BytesIO()

    def test__daemon__capture__drains_and_writes_rebased_lines(self) -> None:
        """
        Ensure the writer drains every captured frame and writes one
        direction-tagged, rebased-timestamp line per frame to the sink.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        clock = iter([50.0, 50.1]).__next__
        capture = DaemonCapture(
            capture_socket=_FakeCaptureSocket(self._packets, self._drained),
            sink=self._sink,
            clock=clock,
        )
        self.addCleanup(capture.stop)

        capture.start()
        self.assertTrue(self._drained.wait(timeout=5.0), msg="The writer must drain both queued frames.")
        capture.stop()

        self.assertEqual(
            self._sink.getvalue(),
            b" 0.000000 Out IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5\n"
            b" 0.100000 In IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5\n",
            msg="The writer must emit one rebased, direction-tagged line per captured frame.",
        )

    def test__daemon__capture__pcap_mode_writes_libpcap_stream(self) -> None:
        """
        Ensure pcap mode writes a libpcap global header followed by one
        record per captured frame, so 'tshark -r' can decode the stream.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        capture = DaemonCapture(
            capture_socket=_FakeCaptureSocket(self._packets, self._drained),
            sink=self._sink,
            pcap=True,
            clock=iter([50.0, 50.1]).__next__,
        )
        self.addCleanup(capture.stop)

        capture.start()
        self.assertTrue(self._drained.wait(timeout=5.0), msg="The writer must drain both queued frames.")
        capture.stop()

        stream = self._sink.getvalue()
        self.assertEqual(
            stream[:24],
            pcap_global_header(),
            msg="A pcap-mode stream must begin with the libpcap global header.",
        )
        frame = _udp_frame()
        self.assertEqual(
            stream[24:],
            pcap_record(frame, seconds=50, micros=0) + pcap_record(frame, seconds=50, micros=100000),
            msg="A pcap-mode stream must carry one libpcap record per captured frame.",
        )

    def test__daemon__capture__stop_is_idempotent_and_joins(self) -> None:
        """
        Ensure 'stop' terminates the drain thread and is safe to call more
        than once, so daemon teardown never wedges on the capture writer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        capture = DaemonCapture(
            capture_socket=_FakeCaptureSocket([], self._drained),
            sink=self._sink,
            clock=iter([0.0]).__next__,
        )

        capture.start()
        capture.stop()
        capture.stop()

        self.assertFalse(capture.is_alive(), msg="The drain thread must be joined after 'stop'.")
