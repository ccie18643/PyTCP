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
This module contains the ICMP Echo ('ping') datagram socket.

A 'PingSocket' is the PyTCP equivalent of a Linux unprivileged ICMP
datagram socket ('socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)' /
'socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)'). It owns a unique ICMP
'id' (assigned at creation, settable via 'bind'); 'sendto' rewrites the
echo request's id field to its own and re-emits it through the stack's
ICMP TX path; the ICMP Echo Reply RX handler demuxes replies back to the
owning socket by id. 'recvfrom' / 'recvmsg' hand the application the ICMP
message bytes only (no IP header), and 'recvmsg' surfaces the reply's
TTL / Hop Limit as an 'IP_TTL' / 'IPV6_HOPLIMIT' cmsg when 'IP_RECVTTL' /
'IPV6_RECVHOPLIMIT' is enabled. Only Echo Request may be sent.

pytcp/runtime/socket/ping__socket.py

ver 3.0.8
"""

import errno
import threading
from typing import override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from net_proto import Icmp4MessageEchoRequest, Icmp4Type, Icmp6MessageEchoRequest, Icmp6Type, IpProto
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.runtime.socket import (
    IP_RECVTTL,
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_HOPLIMIT,
    IPV6_RECVHOPLIMIT,
    AddressFamily,
    SocketType,
    gaierror,
)
from pytcp.runtime.socket.ping__metadata import PingMetadata
from pytcp.runtime.socket.socket__bind_helpers import pick_local_ip_address

# The 8-byte ICMP Echo header: type, code, checksum, id, seq. The id and
# seq sit at byte offsets 4 and 6; the payload follows the header.
ICMP__ECHO__HEADER__LEN: int = 8
ICMP__ECHO__SEQ__OFFSET: int = 6


class PingSocket:
    """
    The ICMP Echo ('ping') datagram socket.
    """

    def __init__(
        self,
        family: AddressFamily,
        type: SocketType = SocketType.DGRAM,
        protocol: IpProto | None = None,
    ) -> None:
        """
        Initialize the ICMP Echo datagram socket, assigning it a unique
        per-family ICMP id and registering it for reply demultiplexing.
        """

        assert type is SocketType.DGRAM
        assert protocol in (IpProto.ICMP4, IpProto.ICMP6)

        self._address_family = family
        self._ip_proto = protocol
        self._recv_ttl = False

        self._local_ip_address: Ip6Address | Ip4Address = (
            Ip6Address() if family is AddressFamily.INET6 else Ip4Address()
        )
        self._remote_ip_address: Ip6Address | Ip4Address = (
            Ip6Address() if family is AddressFamily.INET6 else Ip4Address()
        )

        self._packet_rx_md: list[PingMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)

        self._id = self._allocate_echo_id(family)
        stack.icmp_echo_sockets[(family, self._id)] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    @override
    def __str__(self) -> str:
        """
        Get the human-readable socket description.
        """

        proto = "ICMP6" if self._address_family is AddressFamily.INET6 else "ICMP4"
        return f"{proto}/PING/{self._local_ip_address}/{self._id}"

    @staticmethod
    def _allocate_echo_id(family: AddressFamily) -> int:
        """
        Pick an ICMP id not currently used by another ping socket of this
        family (the id is the per-socket demux key, like an ephemeral
        port).
        """

        used = {echo_id for (fam, echo_id) in stack.icmp_echo_sockets if fam is family}
        for candidate in range(1, 0x10000):
            if candidate not in used:
                return candidate
        raise OSError(errno.EADDRNOTAVAIL, "No free ICMP id available for a ping socket.")

    @property
    def echo_id(self) -> int:
        """
        Get the socket's owned ICMP id.
        """

        return self._id

    def accepts_reply_to(self, local_address: Ip6Address | Ip4Address, /) -> bool:
        """
        Whether an Echo Reply destined to 'local_address' belongs to this
        socket — true for an unbound socket (any local address) or one
        bound to that address.
        """

        return self._local_ip_address.is_unspecified or self._local_ip_address == local_address

    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to a local address and, when a non-zero id is
        given, to that ICMP id (mirroring Linux ping-socket bind, where
        the port field selects the id).
        """

        try:
            local_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(address[0]) if self._address_family is AddressFamily.INET6 else Ip4Address(address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

        requested_id = address[1]
        if requested_id and (self._address_family, requested_id) in stack.icmp_echo_sockets:
            raise OSError(errno.EADDRINUSE, "Address already in use - [ICMP id already in use]")

        del stack.icmp_echo_sockets[(self._address_family, self._id)]
        self._local_ip_address = local_ip_address
        if requested_id:
            self._id = requested_id
        stack.icmp_echo_sockets[(self._address_family, self._id)] = self

    def connect(self, address: tuple[str, int]) -> None:
        """
        Set the socket's default peer address for 'send'.
        """

        try:
            self._remote_ip_address = (
                Ip6Address(address[0]) if self._address_family is AddressFamily.INET6 else Ip4Address(address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]") from error

    def getsockname(self) -> tuple[str, int]:
        """
        Get the local address the socket is bound to, with its owned ICMP
        id in the port field (mirroring Linux ping-socket 'getsockname').
        """

        return str(self._local_ip_address), self._id

    def getpeername(self) -> tuple[str, int]:
        """
        Get the connected peer address (raises if no peer is set).
        """

        if self._remote_ip_address.is_unspecified:
            raise OSError(errno.ENOTCONN, "Transport endpoint is not connected")
        return str(self._remote_ip_address), 0

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option. Supports 'IP_RECVTTL' / 'IPV6_RECVHOPLIMIT',
        which make 'recvmsg' surface the reply's TTL / Hop Limit cmsg.
        """

        if optname in (IP_RECVTTL, IPV6_RECVHOPLIMIT):
            self._recv_ttl = bool(value)
            return

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option.
        """

        if optname in (IP_RECVTTL, IPV6_RECVHOPLIMIT):
            return int(self._recv_ttl)
        return 0

    def send(self, data: bytes) -> int:
        """
        Send an Echo Request to the connected peer.
        """

        if self._remote_ip_address.is_unspecified:
            raise OSError(errno.EDESTADDRREQ, "Destination address required - [Socket has no destination address set]")
        return self._send_echo(data, remote_ip_address=self._remote_ip_address)

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send an Echo Request to 'address'.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(address[0]) if self._address_family is AddressFamily.INET6 else Ip4Address(address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]") from error
        return self._send_echo(data, remote_ip_address=remote_ip_address)

    def sendmsg(
        self,
        buffers: list[bytes],
        ancdata: list[tuple[int, int, bytes]] = [],
        flags: int = 0,
        address: tuple[str, int] | None = None,
    ) -> int:
        """
        Gather 'buffers' into one Echo Request and send it (the cmsg send
        path is not honoured), mirroring stdlib 'socket.sendmsg'.
        """

        payload = b"".join(bytes(buffer) for buffer in buffers)
        if address is not None:
            return self.sendto(payload, address)
        return self.send(payload)

    def _send_echo(self, data: bytes, *, remote_ip_address: Ip6Address | Ip4Address) -> int:
        """
        Rewrite the application's Echo Request id to this socket's owned
        id and emit it through the stack's ICMP TX path. Only an Echo
        Request may be sent (Linux ping-socket restriction).
        """

        echo_type = Icmp6Type.ECHO_REQUEST if self._address_family is AddressFamily.INET6 else Icmp4Type.ECHO_REQUEST
        if len(data) < ICMP__ECHO__HEADER__LEN or data[0] != int(echo_type):
            raise OSError(errno.EACCES, "Permission denied - [A ping socket may send only an Echo Request]")

        if not stack.has_route_to(remote_ip_address):
            raise OSError(errno.EHOSTUNREACH, "No route to host - [No route to destination]")

        sequence = int.from_bytes(data[ICMP__ECHO__SEQ__OFFSET : ICMP__ECHO__SEQ__OFFSET + 2], "big")
        payload = bytes(data[ICMP__ECHO__HEADER__LEN:])

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address=remote_ip_address)
        else:
            local_ip_address = self._local_ip_address

        if self._address_family is AddressFamily.INET6:
            assert isinstance(local_ip_address, Ip6Address) and isinstance(remote_ip_address, Ip6Address)
            stack.egress_packet_handler(remote_ip_address).send_icmp6_packet(
                ip6__local_address=local_ip_address,
                ip6__remote_address=remote_ip_address,
                icmp6__message=Icmp6MessageEchoRequest(id=self._id, seq=sequence, data=payload),
            )
        else:
            assert isinstance(local_ip_address, Ip4Address) and isinstance(remote_ip_address, Ip4Address)
            stack.egress_packet_handler(remote_ip_address).send_icmp4_packet(
                ip4__local_address=local_ip_address,
                ip4__remote_address=remote_ip_address,
                icmp4__message=Icmp4MessageEchoRequest(id=self._id, seq=sequence, data=payload),
            )

        __debug__ and log("socket", f"<B><lr>[{self}]</> - Sent {len(data)} bytes of data")
        return len(data)

    def _next_metadata(self, *, timeout: float | None) -> PingMetadata:
        """
        Block until the next inbound Echo Reply is available (or the
        timeout elapses) and pop it from the RX queue.
        """

        if timeout == 0.0:
            acquired = self._packet_rx_md_ready.acquire(blocking=False)
        else:
            acquired = self._packet_rx_md_ready.acquire(timeout=timeout)
        if not acquired:
            raise TimeoutError("timed out")
        return self._packet_rx_md.pop(0)

    def recv(self, bufsize: int | None = None, timeout: float | None = None) -> bytes:
        """
        Receive the next Echo Reply's ICMP message bytes (no IP header).
        """

        return self._next_metadata(timeout=timeout).icmp__data

    def recvfrom(self, bufsize: int | None = None, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        """
        Receive the next Echo Reply, returning its ICMP message bytes and
        the sender's address.
        """

        metadata = self._next_metadata(timeout=timeout)
        return metadata.icmp__data, (str(metadata.ip__remote_address), 0)

    def recvmsg(
        self,
        bufsize: int | None = None,
        ancbufsize: int = 0,
        flags: int = 0,
        timeout: float | None = None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive the next Echo Reply with ancillary data, mirroring stdlib
        'socket.recvmsg'. When 'IP_RECVTTL' / 'IPV6_RECVHOPLIMIT' is
        enabled the reply's TTL / Hop Limit rides as an 'IP_TTL' /
        'IPV6_HOPLIMIT' cmsg.
        """

        metadata = self._next_metadata(timeout=timeout)
        ancdata: list[tuple[int, int, bytes]] = []
        if self._recv_ttl:
            if self._address_family is AddressFamily.INET6:
                ancdata.append((int(IPPROTO_IPV6), int(IPV6_HOPLIMIT), metadata.ip__ttl.to_bytes(4, "little")))
            else:
                ancdata.append((int(IPPROTO_IP), int(IP_TTL), metadata.ip__ttl.to_bytes(4, "little")))
        return metadata.icmp__data, ancdata, 0, (str(metadata.ip__remote_address), 0)

    def process_echo_reply(self, packet_rx_md: PingMetadata) -> None:
        """
        Enqueue an inbound Echo Reply for the application to receive.
        """

        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()

    def close(self) -> None:
        """
        Close the socket and stop receiving replies.
        """

        stack.icmp_echo_sockets.pop((self._address_family, self._id), None)
        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")
