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
This module contains the BSD-like AF_PACKET raw link-layer socket
interface for the stack — the PyTCP equivalent of Linux
'socket(AF_PACKET, SOCK_RAW, htons(ethertype))'. Unlike the raw IP
socket ('RawSocket'), it sends and receives complete Ethernet frames
(including ARP, which is below the IP layer), keyed by an ethertype
capture / delivery filter rather than an IANA next-header value.

This is the Phase-0 skeleton: it constructs and reports its
family / type / ethertype / ifindex; RX (a per-interface tap) and TX
(verbatim frame onto the egress TxRing) arrive in later phases.

pytcp/socket/packet__socket.py

ver 3.0.8
"""

import errno
import os
import threading
from typing import TYPE_CHECKING, cast, override

from net_proto.lib.enums import EtherType
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.socket import ETH_P_ALL, AddressFamily, SocketType, socket
from pytcp.socket.packet__metadata import PacketMetadata
from pytcp.socket.sockaddr_ll import SockAddrLl

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class PacketSocket(socket):
    """
    The AF_PACKET raw link-layer socket.
    """

    _address_family = AddressFamily.PACKET
    _socket_type = SocketType.RAW

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily = AddressFamily.PACKET,
        type: SocketType = SocketType.RAW,
        protocol: EtherType | int | None = None,
    ) -> None:
        """
        Initialize the AF_PACKET raw link-layer socket.
        """

        # Phase 0 supports the SOCK_RAW (full-frame) flavour only; the
        # cooked SOCK_DGRAM variant lands in a later phase.
        assert type is SocketType.RAW

        super().__init__()

        # A 'None' protocol (or the coerced BSD 0 sentinel) means no
        # explicit ethertype was requested; default to the ETH_P_ALL
        # capture-all filter. An 'EtherType' member is preserved as-is
        # so the later RX tap can match against the parser-layer enum.
        self._ethertype: EtherType | int = ETH_P_ALL if protocol is None else protocol

        # ifindex 0 = unbound (every interface); set by 'bind()' later.
        self._ifindex = 0

        # RX queue: the Ethernet tap appends a 'PacketMetadata' per
        # matching frame; 'recv' / 'recvfrom' drain it. The semaphore
        # mirrors 'RawSocket' — one release per queued frame.
        self._packet_rx_md: list[PacketMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)

        # Register the capture filter immediately: Linux starts
        # delivering matching frames the moment 'socket(AF_PACKET, ...)'
        # returns, before any 'bind' (Phase 3 narrows the ifindex).
        stack.packet_sockets.register(self)

        __debug__ and log("socket", f"<g>[{self}]</> - Created packet socket")

    @override
    def __str__(self) -> str:
        """
        Get the packet-socket log string.
        """

        return f"PACKET/RAW/0x{int(self._ethertype):04x}/if{self._ifindex}"

    @property
    def ethertype(self) -> EtherType | int:
        """
        Get the socket's ethertype capture / delivery filter.
        """

        return self._ethertype

    @property
    def ifindex(self) -> int:
        """
        Get the interface index the socket is bound to (0 = unbound).
        """

        return self._ifindex

    def process_packet(self, packet_rx_md: PacketMetadata, /) -> None:
        """
        Queue a captured frame's metadata for delivery to 'recv' /
        'recvfrom'. Called by the Ethernet RX tap for each matching
        frame. Dropped under the close-during-delivery drain when the
        socket has already been closed.
        """

        with self._lock__io:
            if self._closed:
                return
            self._packet_rx_md.append(packet_rx_md)
            self._packet_rx_md_ready.release()
        self._signal_readable()

    def _recv_md(self, timeout: float | None, /) -> PacketMetadata:
        """
        Block until a captured frame is available (honoring the
        blocking flag and SO_RCVTIMEO) and return its metadata. Raises
        'BlockingIOError(EAGAIN)' on a non-blocking empty queue and
        'TimeoutError' when a timeout elapses.
        """

        # SO_RCVTIMEO supplies the default if no per-call timeout.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if not acquired:
            if effective_timeout is None and not self._blocking:
                raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
            raise TimeoutError("PACKET Socket - Receive operation timed out.")

        packet_rx_md = self._packet_rx_md.pop(0)
        if not self._packet_rx_md:
            self._drain_readable()
            if self._packet_rx_md:
                self._signal_readable()
        return packet_rx_md

    @override
    def recv(self, bufsize: int | None = None, timeout: float | None = None) -> bytes:
        """
        Read one captured frame from the socket. 'bufsize' truncates the
        returned frame (POSIX recv(2) on SOCK_RAW discards the
        remainder).
        """

        packet_rx_md = self._recv_md(timeout)
        data = packet_rx_md.frame if bufsize is None else packet_rx_md.frame[:bufsize]
        __debug__ and log("socket", f"<B><g>[{self}]</> - Received {len(data)} bytes")
        return data

    @override
    def recvfrom(self, bufsize: int | None = None, timeout: float | None = None) -> tuple[bytes, SockAddrLl]:
        """
        Read one captured frame and the 'sockaddr_ll' describing how it
        arrived (interface, ethertype, packet type, source MAC).
        """

        packet_rx_md = self._recv_md(timeout)
        data = packet_rx_md.frame if bufsize is None else packet_rx_md.frame[:bufsize]
        __debug__ and log("socket", f"<B><g>[{self}]</> - Received {len(data)} bytes")
        return data, packet_rx_md.sockaddr_ll

    @override
    def close(self) -> None:
        """
        Close the socket: deregister its capture filter and release its
        OS-level runtime.
        """

        stack.packet_sockets.unregister(self)
        self._mark_closed()
        __debug__ and log("socket", f"<g>[{self}]</> - Closed packet socket")

    @override
    def bind(self, address: SockAddrLl) -> None:
        """
        Scope the socket to '(address.ifindex, address.ethertype)'. The
        SockAddrLl fully describes the binding (Linux sll_protocol takes
        effect on bind): ifindex 0 captures on every interface, a
        specific ifindex scopes to that one; the ethertype is set as the
        capture filter (so binding with the default ETH_P_ALL widens an
        ethertype-filtered socket back to capture-all). The registry's
        'matching()' reads these attributes live, so no re-registration
        is needed. Raises 'OSError(ENODEV)' when a non-zero ifindex names
        no registered interface.
        """

        if address.ifindex != 0 and address.ifindex not in stack.interfaces:
            raise OSError(errno.ENODEV, f"No interface registered under ifindex {address.ifindex}")

        self._ifindex = address.ifindex
        self._ethertype = address.ethertype
        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    def _egress_handler(self, ifindex: int, /) -> "PacketHandlerL2":
        """
        Resolve the L2 interface a frame egresses: the interface
        registered under 'ifindex', or — when 'ifindex' is 0 (an
        unbound socket / address) — the sole registered interface (the
        transitional N=1 crutch, as in the other stack control tools).
        Raises 'OSError(ENODEV)' when no matching interface exists and
        'OSError(ENXIO)' when the bare resolution is ambiguous (N>1 with
        no ifindex given). Packet sockets are L2-only; the cast encodes
        that precondition (Phase 3's 'bind' rejects an L3 ifindex).
        """

        if ifindex == 0:
            interfaces = stack.interfaces.values()
            if len(interfaces) == 1:
                handler = interfaces[0]
            elif not interfaces:
                raise OSError(errno.ENODEV, "No interface available for AF_PACKET send")
            else:
                raise OSError(errno.ENXIO, "Ambiguous egress interface; bind the packet socket to an ifindex")
        else:
            if ifindex not in stack.interfaces:
                raise OSError(errno.ENODEV, f"No interface registered under ifindex {ifindex}")
            handler = stack.interfaces[ifindex]

        return cast("PacketHandlerL2", handler)

    @override
    def send(self, data: bytes) -> int:
        """
        Send a complete link-layer frame verbatim out the interface the
        socket is bound to ('bind' sets the ifindex; an unbound socket
        egresses the sole interface). Returns the byte count accepted
        into the stack.
        """

        self._egress_handler(self._ifindex).send_link_frame(data)
        __debug__ and log("socket", f"<B><lr>[{self}]</> - Sent {len(data)} bytes")
        return len(data)

    @override
    def sendto(self, data: bytes, address: SockAddrLl) -> int:
        """
        Send a complete link-layer frame verbatim out the interface
        named by 'address.ifindex' (0 = the sole interface). Returns the
        byte count accepted into the stack.
        """

        self._egress_handler(address.ifindex).send_link_frame(data)
        __debug__ and log("socket", f"<B><lr>[{self}]</> - Sent {len(data)} bytes")
        return len(data)
