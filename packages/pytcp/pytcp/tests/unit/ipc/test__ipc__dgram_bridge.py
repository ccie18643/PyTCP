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
Tests for the daemon-side per-socket datagram bridge.

The stack datagram socket the bridge drives is stood in for by
'_DatagramSocketStub', a queue-backed adapter exposing the
'recvfrom(bufsize, timeout)' / 'sendto' / 'send' surface the bridge
calls. A test injects an inbound datagram to exercise the RX direction
and inspects the stub's outbound list to exercise the TX direction.

pytcp/tests/unit/ipc/test__ipc__dgram_bridge.py

ver 3.0.9
"""

import queue
import socket
import time
from collections.abc import Iterable
from typing import override
from unittest import TestCase

from net_addr import Buffer
from pytcp.ipc.ipc__dgram_bridge import DatagramBridge
from pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram

_DEADLINE__SEC: float = 5.0


class _DatagramSocketStub:
    """
    A queue-backed stand-in for a stack datagram socket.
    """

    def __init__(self) -> None:
        self._inbound: queue.Queue[tuple[bytes, list[tuple[int, int, bytes]], tuple[str, int]]] = queue.Queue()
        self.outbound: list[tuple[bytes, tuple[str, int] | None]] = []
        self.sendmsg_calls: list[tuple[bytes, list[tuple[int, int, bytes]], tuple[str, int] | None]] = []

    def inject(
        self,
        data: bytes,
        address: tuple[str, int],
        ancdata: list[tuple[int, int, bytes]] | None = None,
        /,
    ) -> None:
        self._inbound.put((data, ancdata or [], address))

    def recvmsg(
        self,
        bufsize: int | None,
        ancbufsize: int,
        flags: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int]]:
        try:
            data, ancdata, address = self._inbound.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError from None
        return data, ancdata, 0, address

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        self.outbound.append((data, address))
        return len(data)

    def send(self, data: bytes) -> int:
        self.outbound.append((data, None))
        return len(data)

    def sendmsg(
        self,
        buffers: Iterable[Buffer],
        ancdata: Iterable[tuple[int, int, Buffer]],
        flags: int,
        address: tuple[str, int] | None,
    ) -> int:
        payload = b"".join(bytes(buffer) for buffer in buffers)
        self.sendmsg_calls.append((payload, [(level, ctype, bytes(cdata)) for level, ctype, cdata in ancdata], address))
        return len(payload)


class TestIpcDatagramBridge(TestCase):
    """
    The daemon-side per-socket datagram-bridge tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a datagram bridge between a stack-socket stub and a
        SOCK_DGRAM data socketpair (daemon end driven by the bridge,
        client end the simulated client fd).
        """

        self._stack = _DatagramSocketStub()
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._client_end.settimeout(_DEADLINE__SEC)
        self.addCleanup(self._client_end.close)

        self._bridge = DatagramBridge(self._stack, self._data_end)
        self._bridge.start()
        self.addCleanup(self._bridge.stop)

    def _wait_for_outbound(self) -> tuple[bytes, tuple[str, int] | None]:
        """
        Block until the stub has received a datagram from the TX pump.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            if self._stack.outbound:
                return self._stack.outbound[0]
            time.sleep(0.01)
        raise AssertionError("The TX pump did not deliver a datagram to the stack.")

    def test__ipc__dgram_bridge__rx_frames_sender_address(self) -> None:
        """
        Ensure a datagram the stack receives is framed with its sender
        address and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack.inject(b"down", ("10.0.1.91", 5000))

        self.assertEqual(
            decode_dgram(self._client_end.recv(65600)),
            (("10.0.1.91", 5000), [], b"down"),
            msg="The RX pump must frame a received datagram with its sender address.",
        )

    def test__ipc__dgram_bridge__rx_frames_ancillary_cmsgs(self) -> None:
        """
        Ensure ancillary control messages a 'recvmsg' yields are framed
        alongside the datagram and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack.inject(b"tos", ("10.0.1.91", 5000), [(0, 1, b"\x10")])

        self.assertEqual(
            decode_dgram(self._client_end.recv(65600)),
            (("10.0.1.91", 5000), [(0, 1, b"\x10")], b"tos"),
            msg="The RX pump must carry recvmsg cmsgs alongside the datagram.",
        )

    def test__ipc__dgram_bridge__tx_replays_address_as_sendto(self) -> None:
        """
        Ensure an addressed datagram the client writes is replayed into
        the stack as a 'sendto' to that address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client_end.send(encode_dgram(("10.0.1.7", 80), b"up"))

        self.assertEqual(
            self._wait_for_outbound(),
            (b"up", ("10.0.1.7", 80)),
            msg="The TX pump must replay an addressed datagram as a sendto.",
        )

    def test__ipc__dgram_bridge__tx_no_address_is_connected_send(self) -> None:
        """
        Ensure an address-less datagram the client writes is replayed
        into the stack as a connected 'send'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client_end.send(encode_dgram(None, b"conn"))

        self.assertEqual(
            self._wait_for_outbound(),
            (b"conn", None),
            msg="The TX pump must replay an address-less datagram as a connected send.",
        )

    def test__ipc__dgram_bridge__tx_with_cmsg_routes_to_sendmsg(self) -> None:
        """
        Ensure a datagram the client writes WITH ancillary control
        messages is replayed into the stack as a 'sendmsg' carrying the
        cmsg (so the stack can honour an IP_TOS / IPV6_TCLASS byte),
        rather than the cmsg-less sendto path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        cmsg = [(0, 1, b"\x28")]  # IPPROTO_IP / IP_TOS -> TOS 0x28.
        self._client_end.send(encode_dgram(("10.0.1.7", 80), b"marked", cmsg))

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline and not self._stack.sendmsg_calls:
            time.sleep(0.01)

        self.assertEqual(
            self._stack.sendmsg_calls[0] if self._stack.sendmsg_calls else None,
            (b"marked", cmsg, ("10.0.1.7", 80)),
            msg="The TX pump must route a datagram with cmsg through sendmsg with the cmsg intact.",
        )
        self.assertEqual(
            self._stack.outbound,
            [],
            msg="A datagram with cmsg must not also take the cmsg-less sendto path.",
        )


class _ScriptedDatagramSocket:
    """
    A datagram stack-socket stub whose recvmsg plays a scripted
    sequence: a 'TimeoutError' / 'OSError' sentinel raises (a poll
    timeout / transient receive error) and a tuple is delivered as a
    datagram. After the script it idles by raising 'TimeoutError'.
    """

    def __init__(self, script: list[object], /) -> None:
        self._script = script
        self._index = 0

    def recvmsg(
        self,
        bufsize: int | None,
        ancbufsize: int,
        flags: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int]]:
        """Play the next scripted recvmsg result (or idle-then-timeout)."""

        if self._index < len(self._script):
            item = self._script[self._index]
            self._index += 1
            if item is TimeoutError:
                raise TimeoutError
            if item is OSError:
                raise OSError
            assert isinstance(item, tuple)
            data, ancdata, address = item
            return data, ancdata, 0, address
        time.sleep(0.02)
        raise TimeoutError

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """Discard sent bytes (TX is not under test here)."""

        return len(data)

    def send(self, data: bytes) -> int:
        """Discard sent bytes (TX is not under test here)."""

        return len(data)

    def sendmsg(
        self,
        buffers: Iterable[Buffer],
        ancdata: Iterable[tuple[int, int, Buffer]],
        flags: int,
        address: tuple[str, int] | None,
    ) -> int:
        """Discard sent bytes (TX is not under test here)."""

        return sum(len(bytes(buffer)) for buffer in buffers)


class TestIpcDatagramBridge__FaultInjection(TestCase):
    """
    Fault-injected RX-pump behaviour: the pump must treat a poll
    TimeoutError AND a transient OSError as retries (continue), not a
    teardown, and still deliver the datagram that follows them.
    """

    def test__dgram_bridge__rx_pump_survives_timeout_and_oserror(self) -> None:
        """
        Ensure the RX pump continues past both a poll TimeoutError and a
        transient OSError, then frames and delivers the following
        datagram — pinning both 'except ...: continue' branches against
        a teardown edit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(data_end.close)
        self.addCleanup(client_end.close)
        client_end.settimeout(_DEADLINE__SEC)

        stub = _ScriptedDatagramSocket([TimeoutError, OSError, (b"payload", [], ("10.0.0.1", 80))])
        bridge = DatagramBridge(stub, data_end)
        bridge.start()
        self.addCleanup(bridge.stop)

        self.assertEqual(
            decode_dgram(client_end.recv(4096)),
            (("10.0.0.1", 80), [], b"payload"),
            msg="a datagram after a timeout + OSError must still be framed and delivered (the pump must continue).",
        )
