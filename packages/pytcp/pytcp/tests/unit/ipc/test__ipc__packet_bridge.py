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
Tests for the daemon-side per-socket AF_PACKET bridge.

The stack AF_PACKET socket the bridge drives is stood in for by
'_LinkSocketStub', a queue-backed adapter exposing the 'recvfrom(bufsize,
timeout)' / 'sendto' surface the bridge calls. A test injects an inbound
frame to exercise the RX direction and inspects the stub's outbound list
to exercise the TX direction.

pytcp/tests/unit/ipc/test__ipc__packet_bridge.py

ver 3.0.9
"""

import queue
import socket
import time
from typing import override
from unittest import TestCase

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from pytcp.ipc.ipc__packet_bridge import PacketBridge
from pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

_DEADLINE__SEC: float = 5.0


class _LinkSocketStub:
    """
    A queue-backed stand-in for a stack AF_PACKET socket.
    """

    def __init__(self) -> None:
        self._inbound: queue.Queue[tuple[bytes, SockAddrLl]] = queue.Queue()
        self.outbound: list[tuple[bytes, SockAddrLl]] = []

    def inject(self, frame: bytes, sockaddr_ll: SockAddrLl, /) -> None:
        self._inbound.put((frame, sockaddr_ll))

    def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        try:
            return self._inbound.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError from None

    def sendto(self, data: bytes, address: SockAddrLl) -> int:
        self.outbound.append((data, address))
        return len(data)


class TestIpcPacketBridge(TestCase):
    """
    The daemon-side per-socket AF_PACKET-bridge tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a packet bridge between a stack-socket stub and a SOCK_DGRAM
        data socketpair (daemon end driven by the bridge, client end the
        simulated client fd).
        """

        self._stack = _LinkSocketStub()
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._client_end.settimeout(_DEADLINE__SEC)
        self.addCleanup(self._client_end.close)

        self._bridge = PacketBridge(self._stack, self._data_end)
        self._bridge.start()
        self.addCleanup(self._bridge.stop)

    def _wait_for_outbound(self) -> tuple[bytes, SockAddrLl]:
        """
        Block until the stub has received a frame from the TX pump.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            if self._stack.outbound:
                return self._stack.outbound[0]
            time.sleep(0.01)
        raise AssertionError("The TX pump did not deliver a frame to the stack.")

    def test__ipc__packet_bridge__rx_frames_sockaddr_ll(self) -> None:
        """
        Ensure a frame the stack captures is framed with its sockaddr_ll
        and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(
            ifindex=2,
            ethertype=EtherType.ARP,
            pkttype=PacketType.PACKET_HOST,
            mac=MacAddress("02:00:00:00:00:91"),
        )
        self._stack.inject(b"a-frame", sockaddr_ll)

        self.assertEqual(
            decode_packet(self._client_end.recv(65600)),
            (sockaddr_ll, b"a-frame"),
            msg="The RX pump must frame a captured frame with its sockaddr_ll.",
        )

    def test__ipc__packet_bridge__tx_replays_sockaddr_ll(self) -> None:
        """
        Ensure a frame the client writes is replayed into the stack as a
        'sendto' carrying the framed sockaddr_ll.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(ifindex=3, ethertype=EtherType.IP4, mac=MacAddress("02:00:00:00:00:07"))
        self._client_end.send(encode_packet(sockaddr_ll, b"out-frame"))

        self.assertEqual(
            self._wait_for_outbound(),
            (b"out-frame", sockaddr_ll),
            msg="The TX pump must replay a client frame as a sendto with its sockaddr_ll.",
        )


class _ScriptedLinkSocket:
    """
    An AF_PACKET stack-socket stub whose recvfrom plays a scripted
    sequence: a 'TimeoutError' / 'OSError' sentinel raises (a poll
    timeout / transient capture error) and a tuple is delivered as a
    captured frame. After the script it idles by raising 'TimeoutError'.
    """

    def __init__(self, script: list[object], /) -> None:
        self._script = script
        self._index = 0

    def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        """Play the next scripted recvfrom result (or idle-then-timeout)."""

        if self._index < len(self._script):
            item = self._script[self._index]
            self._index += 1
            if item is TimeoutError:
                raise TimeoutError
            if item is OSError:
                raise OSError
            assert isinstance(item, tuple)
            frame, sockaddr_ll = item
            return frame, sockaddr_ll
        time.sleep(0.02)
        raise TimeoutError

    def sendto(self, data: bytes, address: SockAddrLl) -> int:
        """Discard sent bytes (TX is not under test here)."""

        return len(data)


class TestIpcPacketBridge__FaultInjection(TestCase):
    """
    Fault-injected RX-pump behaviour: the pump must treat a poll
    TimeoutError AND a transient OSError as retries (continue), not a
    teardown, and still deliver the frame that follows them.
    """

    def test__packet_bridge__rx_pump_survives_timeout_and_oserror(self) -> None:
        """
        Ensure the RX pump continues past both a poll TimeoutError and a
        transient OSError, then frames and delivers the following
        captured frame — pinning both 'except ...: continue' branches.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(data_end.close)
        self.addCleanup(client_end.close)
        client_end.settimeout(_DEADLINE__SEC)

        sockaddr_ll = SockAddrLl(
            ifindex=2,
            ethertype=EtherType.ARP,
            pkttype=PacketType.PACKET_HOST,
            mac=MacAddress("02:00:00:00:00:91"),
        )
        stub = _ScriptedLinkSocket([TimeoutError, OSError, (b"a-frame", sockaddr_ll)])
        bridge = PacketBridge(stub, data_end)
        bridge.start()
        self.addCleanup(bridge.stop)

        self.assertEqual(
            decode_packet(client_end.recv(65600)),
            (sockaddr_ll, b"a-frame"),
            msg="a frame after a timeout + OSError must still be framed and delivered (the pump must continue).",
        )
