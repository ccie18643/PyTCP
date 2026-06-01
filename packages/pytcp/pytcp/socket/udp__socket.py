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
This module contains the BSD-like UDP socket interface for the stack.

pytcp/socket/udp__socket.py

ver 3.0.8
"""

from __future__ import annotations

import errno
import os
import threading
import time
from collections import deque
from collections.abc import Iterable
from typing import TYPE_CHECKING, override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from net_proto.lib.enums import IpProto
from net_proto.lib.proto_enum import ProtoEnum
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.udp.udp__plpmtud_adapter import UdpPlpmtudAdapter
from pytcp.socket import (
    IP_OPTIONS,
    IP_RECVERR,
    IP_TOS,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_RECVERR,
    IPV6_TCLASS,
    MSG_ERRQUEUE,
    SO_BINDTODEVICE,
    SO_LINGER,
    SOL_SOCKET,
    SOL_UDP,
    UDP_NO_CHECK6_RX,
    UDP_NO_CHECK6_TX,
    AddressFamily,
    SocketType,
    gaierror,
    socket,
)
from pytcp.socket.error_queue import (
    ERROR_QUEUE__MAX_LEN,
    ErrorQueueEntry,
    SoEeOrigin,
    build_icmp_error_entry,
    pack_sock_extended_err,
)
from pytcp.socket.socket__bind_helpers import (
    is_address_in_use,
    pick_local_ip_address,
    pick_local_port,
)

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
    from pytcp.socket.udp__metadata import UdpMetadata


class UdpSocket(socket):
    """
    The IPv6/IPv4 UDP socket.
    """

    _socket_type = SocketType.DGRAM
    _ip_proto = IpProto.UDP

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.DGRAM,
        protocol: IpProto | int | None = IpProto.UDP,
    ) -> None:
        """
        Initialize the IPv6/IPv4 UDP socket.
        """

        assert type is SocketType.DGRAM
        # Accept the BSD 'IPPROTO_IP' (= 0) default-protocol sentinel
        # as equivalent to 'IpProto.UDP' for DGRAM sockets.
        if protocol is None or (protocol.__class__ is int and protocol == 0):
            protocol = IpProto.UDP
        assert protocol is IpProto.UDP

        super().__init__()

        self._address_family = family
        self._local_port = 0
        self._remote_port = 0
        self._packet_rx_md: list[UdpMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)
        self._unreachable = False
        # Per-socket ICMP error queue (RFC 1122 §4.1.3.3 surface
        # via Linux IP_RECVERR / IPV6_RECVERR). FIFO-drop on
        # overflow at 'ERROR_QUEUE__MAX_LEN'.
        self._error_queue: deque[ErrorQueueEntry] = deque(maxlen=ERROR_QUEUE__MAX_LEN)
        self._error_queue_ready = threading.Semaphore(0)
        # RFC 6935 §5 per-port zero-checksum opt-in for the
        # IPv6 alternative mode (tunnel encapsulations: LISP,
        # MPLS-in-UDP, Geneve, GTP-U, GRE-in-UDP, NSH-in-UDP).
        # Both flags default to False; the IPv6 receiver gate
        # defaults to "drop cksum=0" per RFC 8200 §8.1 and the
        # TX path computes a checksum normally. Applications
        # implementing a tunnel encapsulation opt the listening
        # / sending socket in via setsockopt(SOL_UDP,
        # UDP_NO_CHECK6_RX, 1) and / or
        # setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1).
        self._udp_no_check6_tx: bool = False
        self._udp_no_check6_rx: bool = False
        # RFC 4821 / RFC 8899 per-socket PLPMTUD adapter, lazily
        # allocated on first 'probe_pmtu' / 'notify_pmtu' for a
        # connected destination. UDP has no native ACK channel,
        # so PLPMTUD is driven by the application via
        # 'probe_pmtu' / 'ack_probe' / 'timeout_probe'; unconnected
        # sockets have no fixed destination and therefore no
        # adapter.
        self._plpmtud_adapter: UdpPlpmtudAdapter | None = None

        match self._address_family:
            case AddressFamily.INET6:
                self._local_ip_address = Ip6Address()
                self._remote_ip_address = Ip6Address()
            case AddressFamily.INET4:
                self._local_ip_address = Ip4Address()
                self._remote_ip_address = Ip4Address()

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    @override
    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option per the BSD 'setsockopt' API. UDP
        sockets honor SOL_SOCKET / IPPROTO_IP / IPPROTO_IPV6 /
        SOL_UDP options. 'value' is 'int' for scalar options
        (SO_*, IP_TTL, IP_TOS, IPV6_*, UDP_NO_CHECK6_*) and
        'bytes' for IP_OPTIONS (RFC 1122 §4.1.3.2 raw options block).
        """

        if level == SOL_SOCKET and optname == SO_BINDTODEVICE:
            self._so_bindtodevice(value)
            return
        if level == SOL_SOCKET and optname == SO_LINGER:
            # Stored on the base; no close-path effect for
            # connectionless UDP (matches Linux's no-op).
            self._so_linger_set(value)
            return
        if isinstance(value, int) and level == SOL_SOCKET and self._sol_socket_setsockopt(optname, value):
            return
        if level == IPPROTO_IP and self._ipproto_ip_setsockopt(optname, value):
            return
        if level == IPPROTO_IPV6 and self._ipproto_ipv6_setsockopt(optname, value):
            return
        if isinstance(value, int) and level == SOL_UDP and self._sol_udp_setsockopt(optname, value):
            return
        raise OSError(
            errno.ENOPROTOOPT,
            f"setsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    @override
    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option per the BSD 'getsockopt' API.
        Symmetric to 'setsockopt': 'int' for scalar options,
        'bytes' for IP_OPTIONS.
        """

        value: int | bytes | None
        if level == SOL_SOCKET and optname == SO_BINDTODEVICE:
            return self._bound_interface_name.encode() if self._bound_interface_name else bytes()
        if level == SOL_SOCKET and (value := self._sol_socket_getsockopt(optname)) is not None:
            return value
        if level == IPPROTO_IP and (value := self._ipproto_ip_getsockopt(optname)) is not None:
            return value
        if level == IPPROTO_IPV6 and (value := self._ipproto_ipv6_getsockopt(optname)) is not None:
            return value
        if level == SOL_UDP and (value := self._sol_udp_getsockopt(optname)) is not None:
            return value
        raise OSError(
            errno.ENOPROTOOPT,
            f"getsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    def _sol_udp_setsockopt(self, optname: int, value: int, /) -> bool:
        """
        Apply a SOL_UDP-level setsockopt option; return True if
        handled. Currently supports the RFC 6935 §5 zero-cksum
        opt-in pair: UDP_NO_CHECK6_TX (sender emits cksum=0)
        and UDP_NO_CHECK6_RX (receiver accepts inbound cksum=0
        on the bound port).
        """

        if optname == UDP_NO_CHECK6_TX:
            self._udp_no_check6_tx = bool(value)
            return True
        if optname == UDP_NO_CHECK6_RX:
            self._udp_no_check6_rx = bool(value)
            return True
        return False

    def _sol_udp_getsockopt(self, optname: int, /) -> int | None:
        """
        Read a SOL_UDP-level option's stored value, or 'None' if
        the optname is not a SOL_UDP option (the caller then
        raises 'ENOPROTOOPT'). Booleans return 0 or 1.
        """

        if optname == UDP_NO_CHECK6_TX:
            return int(self._udp_no_check6_tx)
        if optname == UDP_NO_CHECK6_RX:
            return int(self._udp_no_check6_rx)
        return None

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address, Ip6Address] | tuple[Ip4Address, Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._address_family is AddressFamily.INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]") from error

        if remote_ip_address.is_unspecified:
            self._unreachable = True

        local_ip_address = self._local_ip_address

        if local_ip_address.is_unspecified:
            # DHCPv4 / DHCPv6 client sockets keep their local address
            # unspecified for the whole FSM lifetime so the RX-side
            # 'UdpMetadata.socket_ids' special-case can find them via a
            # single '(0.0.0.0, 68, ...)' / '(::, 546, ...)' bucket
            # regardless of whether the client is in INIT / RENEWING /
            # REBINDING. Calling 'pick_local_ip_address' here would
            # latch the owned IP into the stored 'socket_id' once a
            # lease is in place, moving the socket out of that bucket
            # and silently dropping every RENEW / REBIND reply.
            is_dhcp4_client = (
                self._address_family == AddressFamily.INET4 and self._local_port == 68 and remote_address[1] == 67
            )
            is_dhcp6_client = (
                self._address_family == AddressFamily.INET6 and self._local_port == 546 and remote_address[1] == 547
            )

            if not (is_dhcp4_client or is_dhcp6_client):
                local_ip_address = pick_local_ip_address(remote_ip_address=remote_ip_address)

                if local_ip_address.is_unspecified:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]")

        return (local_ip_address, remote_ip_address)  # type: ignore[return-value]

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

    @override
    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address and specific local port in case provided port equals zero
        # port value will be picked automatically.

        # Check if "bound" already.
        if self._local_port in range(1, 65536):
            raise OSError(
                errno.EINVAL,
                "Invalid argument - [Socket bound to specific port already]",
            )

        local_ip_address: Ip4Address | Ip6Address

        match self._address_family:
            case AddressFamily.INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(stack.local_ip6_unicast()) | {
                        Ip6Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

            case AddressFamily.INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(stack.local_ip4_unicast()) | {
                        Ip4Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip4AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

        # Sanity check on local port number.
        if address[1] not in range(0, 65536):
            raise OverflowError("bind(): port must be 0-65535. - [Port out of range]")

        # Confirm or pick local port number.
        if (local_port := address[1]) > 0:
            # SO_REUSEADDR bypasses the in-use check, mirroring
            # Linux's setsockopt(SOL_SOCKET, SO_REUSEADDR) which
            # allows rebinding to an in-use port (mostly used
            # post-restart so a server can rebind through TIME_WAIT).
            # dual_stack=True flags an AF_INET6 V6ONLY=0 bind to '::'
            # so the in-use check picks up cross-family conflicts
            # with existing AF_INET listeners on the same port — the
            # H3 dual-stack reservation rule.
            if not self._so_reuseaddr and is_address_in_use(
                local_ip_address=local_ip_address,
                local_port=local_port,
                address_family=self._address_family,
                socket_type=self._socket_type,
                dual_stack=(self._address_family is AddressFamily.INET6 and not self._ipv6_v6only),
                reuseport=self._so_reuseport,
            ):
                raise OSError(
                    errno.EADDRINUSE,
                    "Address already in use - [Local address already in use]",
                )
        else:
            local_port = pick_local_port()

        # Assigning local port makes socket "bound".
        stack.sockets.unregister(self)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets.register(self)

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    @override
    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local IP address (will
        # rebind if necessary), specific local port, specific remote IP address
        # and specific remote port.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("connect(): port must be 0-65535. - [Port out of range]")

        # Assigning local port makes socket "bound" if not "bound" already.
        if (local_port := self._local_port) not in range(1, 65536):
            local_port = pick_local_port()

        # Set local and remote ip addresses appropriately.
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id.
        stack.sockets.unregister(self)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets.register(self)

        __debug__ and log("socket", f"<g>[{self}]</> - Connected socket")

    def _egress_handler(self, remote_ip_address: "Ip4Address | Ip6Address", /) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Resolve the egress packet handler for an outbound datagram. When
        the socket is pinned to an interface via SO_BINDTODEVICE, egress
        that interface directly (bypassing FIB route selection — the
        Linux SO_BINDTODEVICE semantics a pre-lease DHCP client relies
        on); otherwise use the FIB-resolved egress.
        """

        if self._egress_ifindex is not None:
            handler = stack.interfaces.get(self._egress_ifindex)
            if handler is None:
                raise OSError(
                    errno.ENODEV,
                    "SO_BINDTODEVICE: bound interface is no longer registered",
                )
            return handler
        return stack.egress_packet_handler(remote_ip_address)

    @override
    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.
        if self._remote_ip_address.is_unspecified or self._remote_port == 0:
            raise OSError(
                errno.EDESTADDRREQ,
                "Destination address required - [Socket has no destination address set]",
            )

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError(
                errno.ECONNREFUSED,
                "Connection refused - [Remote host sent ICMP Unreachable]",
            )

        # RFC 1122 §3.3.1 / Linux parity: the route lookup happens at
        # send time. No route to the destination -> synchronous
        # EHOSTUNREACH, before the datagram is queued on the TX worker.
        if not stack.has_route_to(self._remote_ip_address):
            raise OSError(errno.EHOSTUNREACH, "No route to host - [No route to destination]")

        # H5 SO_BROADCAST gate (Linux 'udp_sendmsg'): sending to the
        # IPv4 limited broadcast '255.255.255.255' on a connected
        # socket requires 'SO_BROADCAST = 1'.
        if (
            isinstance(self._remote_ip_address, Ip4Address)
            and self._remote_ip_address.is_limited_broadcast
            and not self._so_broadcast
        ):
            raise OSError(
                errno.EACCES,
                "Permission denied - [SO_BROADCAST must be enabled for broadcast send]",
            )

        self._egress_handler(self._remote_ip_address).send_udp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=self._remote_port,
            udp__payload=data,
            udp__no_cksum=self._udp_no_check6_tx,
            ip__ttl=self._effective_ip_ttl(),
            ip__ecn=self._effective_ip_ecn(),
            ip__dscp=self._effective_ip_dscp(),
            ip4__options=self._effective_ip4_options(),
        )

        # Phase 4b fire-and-forget: the datagram is accepted into the
        # stack the moment 'send_udp_packet' queues it on the TX
        # worker; report the full byte count without waiting for the
        # wire-level result, matching Linux's queued-on-send UDP
        # semantics. Delivery failures surface asynchronously
        # (ICMP -> error queue / IP_RECVERR), not via the return value.
        sent_data_len = len(data)

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    @override
    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send the data to remote host.
        """

        # The 'sendto' call will bind socket to specific local port,
        # will leave local ip address intact.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("sendto(): port must be 0-65535. - [Port out of range]")

        # Assigning local port makes socket "bound" if not "bound" already.
        if self._local_port not in range(1, 65536):
            stack.sockets.unregister(self)
            self._local_port = pick_local_port()
            stack.sockets.register(self)

        # Set local and remote ip addresses appropriately.
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # RFC 1122 §3.3.1 / Linux parity: no route to the destination ->
        # synchronous EHOSTUNREACH at send time.
        if not stack.has_route_to(remote_ip_address):
            raise OSError(errno.EHOSTUNREACH, "No route to host - [No route to destination]")

        # H5 SO_BROADCAST gate (Linux 'udp_sendmsg'): sending to the
        # IPv4 limited broadcast '255.255.255.255' requires the socket
        # to have 'SO_BROADCAST = 1'. Without the flag we surface
        # EACCES synchronously so apps see actionable feedback at the
        # send call.
        if (
            isinstance(remote_ip_address, Ip4Address)
            and remote_ip_address.is_limited_broadcast
            and not self._so_broadcast
        ):
            raise OSError(
                errno.EACCES,
                "Permission denied - [SO_BROADCAST must be enabled for broadcast send]",
            )

        self._egress_handler(remote_ip_address).send_udp_packet(
            ip__local_address=local_ip_address,
            ip__remote_address=remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=remote_port,
            udp__payload=data,
            udp__no_cksum=self._udp_no_check6_tx,
            ip__ttl=self._effective_ip_ttl(),
            ip__ecn=self._effective_ip_ecn(),
            ip__dscp=self._effective_ip_dscp(),
            ip4__options=self._effective_ip4_options(),
        )

        # Phase 4b fire-and-forget — see 'send' above.
        sent_data_len = len(data)

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    @override
    def sendmsg(
        self,
        buffers: Iterable[bytes | bytearray | memoryview],
        ancdata: Iterable[tuple[int, int, bytes | bytearray | memoryview]] = (),
        flags: int = 0,
        address: tuple[str, int] | None = None,
    ) -> int:
        """
        Send a datagram from the scatter-gather 'buffers' iterable,
        mirroring stdlib 'socket.sendmsg(buffers, ancdata=[], flags=0,
        address=None)'. The buffers are concatenated into a single
        UDP payload; when 'address' is given the call behaves like
        sendto(), otherwise like send() on a connected socket.

        Phase-1 PyTCP honours no send-side cmsg type, so 'ancdata' is
        validated for shape then ignored (Linux silently ignores
        unhandled cmsgs).
        """

        # Phase 2: honour per-send IP_TOS / IP_TTL / IP_PKTINFO cmsg.
        self._validate_sendmsg_ancdata(ancdata)

        payload = b"".join(bytes(buffer) for buffer in buffers)

        if address is not None:
            return self.sendto(payload, address)
        return self.send(payload)

    @override
    def recv(self, bufsize: int | None = None, timeout: float | None = None) -> bytes:
        """
        Read data from socket.
        """

        return bytes(self.recv__mv(bufsize=bufsize, timeout=timeout))

    @override
    def recv__mv(self, bufsize: int | None = None, timeout: float | None = None) -> memoryview:
        """
        Read data from socket as a memoryview.
        """

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError(
                errno.ECONNREFUSED,
                "Connection refused - [Remote host sent ICMP Unreachable]",
            )

        # Per-call 'timeout' wins; otherwise SO_RCVTIMEO (if set)
        # supplies the default; otherwise the blocking flag picks
        # blocking-forever vs non-blocking-EAGAIN.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if acquired:
            data_rx = self._packet_rx_md.pop(0).udp__data
            # POSIX recv(2) on SOCK_DGRAM truncates the datagram to
            # 'bufsize' bytes and silently discards the remainder;
            # the entire datagram is consumed regardless.
            if bufsize is not None:
                data_rx = data_rx[:bufsize]
            if not self._packet_rx_md:
                self._drain_readable()
                # Producer race: a packet handler may have appended
                # between the empty-check and the drain; re-check
                # under the GIL and re-signal so the selector wakes.
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - Received {len(data_rx)} bytes of data",
            )
            return data_rx

        if effective_timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("UDP Socket - Receive operation timed out.")

    @override
    def recvfrom(self, bufsize: int | None = None, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        """
        Read data from socket.
        """

        _bytes, (remote_ip, remote_port) = self.recvfrom__mv(bufsize=bufsize, timeout=timeout)

        return bytes(_bytes), (remote_ip, remote_port)

    @override
    def recvfrom__mv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> tuple[memoryview, tuple[str, int]]:
        """
        Read data from socket as a memoryview.
        """

        # Per-call 'timeout' wins; otherwise SO_RCVTIMEO (if set)
        # supplies the default; otherwise the blocking flag picks
        # blocking-forever vs non-blocking-EAGAIN.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if acquired:
            packet_rx_md = self._packet_rx_md.pop(0)
            data_rx = packet_rx_md.udp__data
            if bufsize is not None:
                data_rx = data_rx[:bufsize]
            if not self._packet_rx_md:
                self._drain_readable()
                if self._packet_rx_md:
                    self._signal_readable()
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - <lg>Received</> {len(data_rx)} bytes of data",
            )
            return (
                data_rx,
                (
                    str(packet_rx_md.ip__remote_address),
                    packet_rx_md.udp__remote_port,
                ),
            )

        if effective_timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("UDP Socket - Receive operation timed out.")

    @override
    def recvmsg(
        self,
        bufsize: int | None = None,
        ancbufsize: int = 0,
        flags: int = 0,
        timeout: float | None = None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive a UDP datagram along with ancillary data (control
        messages) and the sender's address. Mirrors the Python
        stdlib 'socket.recvmsg(bufsize, ancbufsize=0, flags=0)'
        signature.

        Returns '(data, ancdata, msg_flags, address)'. 'ancdata'
        is a list of '(cmsg_level, cmsg_type, cmsg_data)' tuples;
        IP_OPTIONS cmsgs are emitted when 'IP_RECVOPTS' is set on
        the socket and the inbound datagram carried IPv4 options
        (RFC 1122 §4.1.3.2). 'address' is a 2-tuple
        '(host, port)' for IPv4 and a 4-tuple
        '(host, port, flowinfo, scope_id)' for IPv6, matching
        Python stdlib 'socket.recvmsg'.

        'ancbufsize' is currently advisory only — PyTCP returns
        every cmsg the socket has enabled regardless of buffer
        size; truncation handling is a follow-up commit. When
        'flags & MSG_ERRQUEUE' is set the call dequeues an
        ICMP error from the per-socket error queue instead of
        reading the data queue (Linux 'ip(7)' /
        'ipv6(7)' semantics, RFC 1122 §4.1.3.3 surface).
        """

        if flags & MSG_ERRQUEUE:
            return self._recvmsg_errqueue(ancbufsize=ancbufsize, timeout=timeout)

        # Per-call 'timeout' wins; otherwise SO_RCVTIMEO (if set)
        # supplies the default; otherwise the blocking flag picks
        # blocking-forever vs non-blocking-EAGAIN.
        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=effective_timeout)

        if acquired:
            packet_rx_md = self._packet_rx_md.pop(0)
            data_rx = packet_rx_md.udp__data
            if bufsize is not None:
                data_rx = data_rx[:bufsize]
            if not self._packet_rx_md:
                self._drain_readable()
                if self._packet_rx_md:
                    self._signal_readable()

            ancdata: list[tuple[int, int, bytes]] = []
            if self._ip_recvopts and packet_rx_md.ip4__options is not None and ancbufsize > 0:
                ancdata.append(
                    (
                        int(IPPROTO_IP),
                        int(IP_OPTIONS),
                        bytes(packet_rx_md.ip4__options),
                    )
                )
            # IP_TOS / IPV6_TCLASS ancillary data (RFC 1122 §4.1.4
            # / RFC 3542 §6.5). Linux's wire shape diverges across
            # the families: IP_TOS cmsg is one byte ('uint8_t' in
            # ip(7)); IPV6_TCLASS cmsg is a 4-byte integer
            # ('int' in ipv6(7)). Mirror both exactly.
            if ancbufsize > 0:
                if self._address_family is AddressFamily.INET4 and self._ip_recvtos:
                    ancdata.append(
                        (
                            int(IPPROTO_IP),
                            int(IP_TOS),
                            bytes([packet_rx_md.ip__tos & 0xFF]),
                        )
                    )
                elif self._address_family is AddressFamily.INET6 and self._ipv6_recvtclass:
                    ancdata.append(
                        (
                            int(IPPROTO_IPV6),
                            int(IPV6_TCLASS),
                            (packet_rx_md.ip__tos & 0xFF).to_bytes(4, "big"),
                        )
                    )

            address: tuple[str, int] | tuple[str, int, int, int]
            if self._address_family is AddressFamily.INET6:
                # Linux IPv6 sockaddr_in6: '(host, port, flowinfo,
                # scope_id)'. PyTCP doesn't track per-datagram flow
                # label / scope id today; return 0 for both. A future
                # commit can plumb them through 'UdpMetadata'.
                address = (
                    str(packet_rx_md.ip__remote_address),
                    packet_rx_md.udp__remote_port,
                    0,
                    0,
                )
            else:
                address = (
                    str(packet_rx_md.ip__remote_address),
                    packet_rx_md.udp__remote_port,
                )

            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - <lg>Received</> {len(data_rx)} bytes of data, " f"{len(ancdata)} cmsg(s)",
            )

            return bytes(data_rx), ancdata, 0, address

        if effective_timeout is None and not self._blocking:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        raise TimeoutError("UDP Socket - Receive operation timed out.")

    def _recvmsg_errqueue(
        self,
        *,
        ancbufsize: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Dequeue one entry from the per-socket ICMP error queue
        and return it in the Linux 'recvmsg(MSG_ERRQUEUE)'
        4-tuple shape. The data portion is the original
        outbound datagram that triggered the ICMP error (as
        quoted in the ICMP error 'data' field); the ancillary
        data carries an 'IP_RECVERR' / 'IPV6_RECVERR' cmsg
        whose payload is the packed 'struct sock_extended_err'
        + offender sockaddr. The address tuple is the ICMP
        source.

        Reference: RFC 1122 §4.1.3.3 (pass ICMP errors up to
        the application).
        Reference: Linux 'ip(7)' / 'ipv6(7)' (IP_RECVERR /
        IPV6_RECVERR API shape).
        """

        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._error_queue_ready.acquire(blocking=False)
        else:
            acquired = self._error_queue_ready.acquire(timeout=effective_timeout)

        if not acquired:
            if effective_timeout is None and not self._blocking:
                raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
            raise TimeoutError("UDP Socket - Receive operation timed out.")

        entry = self._error_queue.popleft()
        cmsg_payload = pack_sock_extended_err(entry)
        ancdata: list[tuple[int, int, bytes]] = []
        if ancbufsize > 0:
            if isinstance(entry.offender_ip, Ip4Address):
                ancdata.append((int(IPPROTO_IP), int(IP_RECVERR), cmsg_payload))
            else:
                ancdata.append((int(IPPROTO_IPV6), int(IPV6_RECVERR), cmsg_payload))

        # Address tuple shape matches the data-path 'recvmsg'
        # convention: 2-tuple for AF_INET, 4-tuple for AF_INET6.
        # The offender is the ICMP source; port is 0 because
        # ICMP carries no port.
        address: tuple[str, int] | tuple[str, int, int, int]
        if isinstance(entry.offender_ip, Ip4Address):
            address = (str(entry.offender_ip), 0)
        else:
            address = (str(entry.offender_ip), 0, 0, 0)

        return entry.embedded_datagram, ancdata, int(MSG_ERRQUEUE), address

    @override
    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.unregister(self)
        self._mark_closed()

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_udp_packet(self, packet_rx_md: UdpMetadata) -> None:
        """
        Process incoming packet's metadata. Dropped under the
        close-during-delivery drain (Phase 5) when the socket has
        already been closed.
        """

        with self._lock__io:
            if self._closed:
                return
            self._packet_rx_md.append(packet_rx_md)
            self._packet_rx_md_ready.release()
        self._signal_readable()

    def _is_recverr_enabled(self) -> bool:
        """
        Return True when the per-family RECVERR flag is set so the
        notify_* paths should enqueue the error for later
        'recvmsg(MSG_ERRQUEUE)' dequeue.
        """

        if self._address_family is AddressFamily.INET6:
            return self._ipv6_recverr
        return self._ip_recverr

    def _enqueue_error(self, entry: ErrorQueueEntry, /) -> None:
        """
        Append an 'ErrorQueueEntry' to the per-socket error
        queue and release the readability semaphore so a
        blocking 'recvmsg(MSG_ERRQUEUE)' wakes up. No-op when
        the per-family RECVERR flag is unset.
        """

        if not self._is_recverr_enabled():
            return
        # deque(maxlen=...) silently drops the oldest entry on
        # overflow — matches the FIFO-drop semantics documented
        # on 'ErrorQueueEntry'.
        self._error_queue.append(entry)
        self._error_queue_ready.release()

    def notify_unreachable(
        self,
        *,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        icmp_type: ProtoEnum | int = 0,
        icmp_code: ProtoEnum | int = 0,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Destination Unreachable matched against this
        socket. Sets the 'unreachable' flag so the next data-path
        'recv()' raises 'ConnectionRefusedError' (legacy BSD
        single-error surface) and, when 'IP_RECVERR' /
        'IPV6_RECVERR' is set on the socket, also appends an
        'ErrorQueueEntry' so the application can dequeue the
        full ICMP context via 'recvmsg(MSG_ERRQUEUE)'.
        """

        self._unreachable = True

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_icmp_error(
            icmp_origin=icmp_origin,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            offender_ip=offender_ip,
            embedded_datagram=embedded_datagram,
        )

    def notify_time_exceeded(
        self,
        *,
        icmp_type: ProtoEnum | int,
        icmp_code: ProtoEnum | int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Time Exceeded matched against this socket.
        Surfaces via 'recvmsg(MSG_ERRQUEUE)' when the per-family
        RECVERR flag is set; no data-path side effect otherwise
        (legacy 'ConnectionRefusedError' path is Port-Unreachable
        only). RFC 1122 §3.2.2.4 mandates pass-to-transport.
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_icmp_error(
            icmp_origin=icmp_origin,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            offender_ip=offender_ip,
            embedded_datagram=embedded_datagram,
        )

    def notify_parameter_problem(
        self,
        *,
        icmp_type: ProtoEnum | int,
        icmp_code: ProtoEnum | int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Parameter Problem matched against this
        socket. Surfaces via 'recvmsg(MSG_ERRQUEUE)' when the
        per-family RECVERR flag is set. RFC 1122 §3.2.2.5
        mandates pass-to-transport.
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_icmp_error(
            icmp_origin=icmp_origin,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            offender_ip=offender_ip,
            embedded_datagram=embedded_datagram,
        )

    def _ensure_plpmtud_adapter(self) -> UdpPlpmtudAdapter | None:
        """
        Lazy-allocate the per-socket PLPMTUD adapter on first
        ICMP / probe event. Returns None when the socket has no
        connected remote (probing requires a fixed destination)
        or no egress interface MTU can be resolved for the peer
        (a reduced context — e.g. unit-test fixtures with no
        interface registered).
        """

        if self._plpmtud_adapter is not None:
            return self._plpmtud_adapter
        if self._remote_ip_address.is_unspecified:
            return None
        iface_mtu = stack.egress_interface_mtu(self._remote_ip_address)
        if iface_mtu is None:
            return None
        self._plpmtud_adapter = UdpPlpmtudAdapter(
            remote_ip_address=self._remote_ip_address,
            interface_mtu=iface_mtu,
        )
        return self._plpmtud_adapter

    def probe_pmtu(self, *, size: int | None = None) -> int | None:
        """
        Emit a PLPMTUD probe datagram to the socket's connected
        peer. Returns the probe size (in bytes, including IP +
        UDP headers) if a probe was emitted, or None when:

        - The socket has no connected destination
        - A probe is already in flight (single-outstanding invariant)
        - The engine has no probe to recommend (when size is None)

        If 'size' is provided, that exact size is used (the
        application chose its own probe size). If 'size' is
        None, the engine's recommendation is used.

        The probe payload is zero-padded so the UDP datagram's
        IP packet size matches the requested probe size. The
        application is responsible for calling 'ack_probe()'
        when its app-layer ACK confirms the probe arrived,
        or 'timeout_probe()' when its app-layer timer expires.

        Reference: RFC 4821 §5 / RFC 8899 §6.
        """

        adapter = self._ensure_plpmtud_adapter()
        if adapter is None:
            return None
        now = time.monotonic()
        chosen_size = adapter.probe_pmtu(size=size, now=now)
        if chosen_size is None:
            return None
        # IP packet size - IP header - UDP header = UDP payload size.
        ip_overhead = 40 if isinstance(self._remote_ip_address, Ip6Address) else 20
        udp_payload_size = max(chosen_size - ip_overhead - 8, 0)
        payload = b"\x00" * udp_payload_size
        try:
            self.sendto(payload, (str(self._remote_ip_address), self._remote_port))
        except OSError:
            # Sendto failed (e.g. routing); clear the in-flight
            # slot so the application can retry.
            adapter.timeout_probe(now=now)
            return None
        return chosen_size

    def ack_probe(self) -> None:
        """
        Notify the PLPMTUD adapter that the application's
        app-layer ACK confirmed the in-flight probe.

        Reference: RFC 4821 §7.6.1 / RFC 8899 §6.
        """

        adapter = self._ensure_plpmtud_adapter()
        if adapter is None:
            return
        adapter.ack_probe(now=time.monotonic())

    def timeout_probe(self) -> None:
        """
        Notify the PLPMTUD adapter that the application's
        app-layer timer expired without an ACK; the in-flight
        probe is declared lost.

        Reference: RFC 4821 §7.5 / RFC 8899 §6.
        """

        adapter = self._ensure_plpmtud_adapter()
        if adapter is None:
            return
        adapter.timeout_probe(now=time.monotonic())

    def notify_pmtu(
        self,
        *,
        next_hop_mtu: int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        icmp_type: ProtoEnum | int = 0,
        icmp_code: ProtoEnum | int = 0,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMPv4 Fragmentation Needed or ICMPv6 Packet Too
        Big matched against this socket. Records the per-
        destination Path-MTU in 'stack.pmtu_cache' so the next
        'sendto()' fragment-or-fail-or-shrink decision uses the
        updated value, and (when RECVERR is set) appends an
        'ErrorQueueEntry' carrying 'errno=EMSGSIZE' and
        'ee_info=next_hop_mtu' per Linux semantics so
        'recvmsg(MSG_ERRQUEUE)' applications can read the
        new MTU.
        """

        stack.record_classical_pmtu(self._remote_ip_address, next_hop_mtu)

        # Route the classical PMTU signal through the per-socket
        # PLPMTUD adapter; lazy-allocate if the socket is connected
        # and the stack interface_mtu is available. Mirror the
        # adapter's engine into 'stack.pmtu_state' so sibling
        # sockets to the same destination share the same engine.
        adapter = self._ensure_plpmtud_adapter()
        if adapter is not None:
            adapter.on_classical_pmtu(next_hop_mtu, now=time.monotonic())
            stack.record_pmtu_engine(self._remote_ip_address, adapter.engine)

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_error(
            ErrorQueueEntry(
                errno=errno.EMSGSIZE,
                origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                ee_info=next_hop_mtu,
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )

    def _enqueue_icmp_error(
        self,
        *,
        icmp_origin: SoEeOrigin,
        icmp_type: ProtoEnum | int,
        icmp_code: ProtoEnum | int,
        offender_ip: Ip4Address | Ip6Address,
        embedded_datagram: bytes,
    ) -> None:
        """
        Shared body for notify_unreachable / time_exceeded /
        parameter_problem: build an 'ErrorQueueEntry' via the
        shared 'build_icmp_error_entry' helper and append it.
        Internal helper.
        """

        self._enqueue_error(
            build_icmp_error_entry(
                icmp_origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )
