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
This module contains the interface class for the TCP Parser -> TCP Socket communication.

pytcp/socket/tcp__metadata.py

ver 3.0.8
"""

from dataclasses import dataclass

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto import Tracker
from pytcp.protocols.tcp.tcp__seq import Seq32
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpMetadata:
    """
    The TCP socket metadata taken from the received packet.
    """

    ip__ver: IpVersion
    ip__local_address: Ip6Address | Ip4Address
    ip__remote_address: Ip6Address | Ip4Address
    ip__ecn: int = 0

    tcp__local_port: int
    tcp__remote_port: int
    tcp__flag_syn: bool
    tcp__flag_ack: bool
    tcp__flag_fin: bool
    tcp__flag_rst: bool
    tcp__flag_ece: bool
    tcp__flag_cwr: bool
    tcp__flag_ns: bool = False
    tcp__seq: Seq32
    tcp__ack: Seq32
    tcp__win: int
    tcp__wscale: int
    tcp__mss: int
    tcp__sackperm: bool
    tcp__sack_blocks: tuple[tuple[Seq32, Seq32], ...]
    tcp__tsval: int | None = None
    tcp__tsecr: int | None = None
    tcp__fastopen_cookie: bytes | None = None
    # RFC 9768 §3.2.3 AccECN option counters: tuple of
    # three 24-bit byte counters (ee0b, eceb, ee1b) when
    # the option is on the wire, None when absent. The
    # ordering is the AccECN0 convention regardless of
    # which kind appeared on the wire. Each tuple slot
    # is independently Optional so abbreviated forms
    # (Length 2/5/8) can carry None for trailing counters
    # the peer omitted - the consumer treats None as
    # 'unchanged from the prior emission' per §3.2.3.
    tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None
    tcp__data: memoryview

    tracker: Tracker | None = None

    @property
    def socket_id(self) -> SocketId:
        """
        Get the exact match socket ID.
        """

        return SocketId(
            address_family=AddressFamily.from_ver(self.ip__ver),
            socket_type=SocketType.STREAM,
            local_address=self.ip__local_address,
            local_port=self.tcp__local_port,
            remote_address=self.ip__remote_address,
            remote_port=self.tcp__remote_port,
        )

    @property
    def listening_socket_ids(self) -> list[SocketId]:
        """
        Get list of the listening socket IDs that match the metadata.

        Two same-family candidates first (specific-local then
        unspecified-local), so a family-specific listener wins over a
        dual-stack one when both are bound on the same port. For an
        IPv4 envelope a THIRD candidate is appended — the AF_INET6
        wildcard ('::') pattern — so an IPv6 listener with
        'IPV6_V6ONLY = 0' (the Linux dual-stack mode) can also accept
        the inbound IPv4 connection. The RX-side dispatcher in
        'packet_handler__tcp__rx.py' filters cross-family matches
        against the listener's '_ipv6_v6only' flag before delivering
        — a V6ONLY=1 listener that happened to bind '::' is skipped.

        The symmetric "IPv6 inbound accepted by AF_INET listener" path
        is not added — Linux has no such mode (IPv4 sockets are always
        single-family).
        """

        candidates: list[SocketId] = [
            SocketId(
                address_family=AddressFamily.from_ver(self.ip__ver),
                socket_type=SocketType.STREAM,
                local_address=self.ip__local_address,
                local_port=self.tcp__local_port,
                remote_address=self.ip__remote_address.unspecified,
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.from_ver(self.ip__ver),
                socket_type=SocketType.STREAM,
                local_address=self.ip__local_address.unspecified,
                local_port=self.tcp__local_port,
                remote_address=self.ip__remote_address.unspecified,
                remote_port=0,
            ),
        ]
        if self.ip__ver is IpVersion.IP4:
            candidates.append(
                SocketId(
                    address_family=AddressFamily.INET6,
                    socket_type=SocketType.STREAM,
                    local_address=Ip6Address(),
                    local_port=self.tcp__local_port,
                    remote_address=Ip6Address(),
                    remote_port=0,
                )
            )
        return candidates
