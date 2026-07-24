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

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains protocol support for the outbound UDP packets.

pytcp/runtime/packet_handler/packet_handler__udp__tx.py

ver 3.0.9
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from net_addr import Buffer, Ip4Address, Ip6Address
from net_proto import Tracker, UdpAssembler
from net_proto.protocols.ip4.options.ip4__options import Ip4Options
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class UdpTxHandler:
    """
    The outbound UDP packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phtx_udp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        udp__sport: int,
        udp__dport: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound UDP packets. 'udp__no_cksum' threads
        through to 'UdpAssembler' to emit the RFC 6935 §5
        alternative-mode zero checksum (literal 0x0000) when
        the originating socket has 'UDP_NO_CHECK6_TX' set.
        """

        self._if._packet_stats_tx.udp__pre_assemble += 1

        udp_packet_tx = UdpAssembler(
            udp__sport=udp__sport,
            udp__dport=udp__dport,
            udp__payload=udp__payload,
            udp__no_cksum=udp__no_cksum,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

        match ip__src.is_ip6, ip__dst.is_ip6, ip__src.is_ip4, ip__dst.is_ip4:
            case True, True, False, False:
                self._if._packet_stats_tx.udp__send += 1
                ip6_kwargs: dict[str, Any] = {
                    "ip6__src": cast(Ip6Address, ip__src),
                    "ip6__dst": cast(Ip6Address, ip__dst),
                    "ip6__payload": udp_packet_tx,
                    "ip6__ecn": ip__ecn,
                    "ip6__dscp": ip__dscp,
                }
                if ip__ttl is not None:
                    ip6_kwargs["ip6__hop"] = ip__ttl
                return self._if._phtx_ip6(**ip6_kwargs)
            case False, False, True, True:
                self._if._packet_stats_tx.udp__send += 1
                # RFC 791 §2.3 / RFC 1122 §3.3.3: an outbound UDP
                # datagram larger than the link MTU is fragmented,
                # not dropped, so DF=0 by default. This matches
                # Linux, whose default UDP socket (no IP_MTU_DISCOVER
                # set) fragments rather than path-MTU-discovers.
                # Phase 3: per-socket DF / PMTUD opt-in lands when
                # setsockopt(IP_MTU_DISCOVER) is wired through.
                ip4_kwargs: dict[str, Any] = {
                    "ip4__src": cast(Ip4Address, ip__src),
                    "ip4__dst": cast(Ip4Address, ip__dst),
                    "ip4__flag_df": False,
                    "ip4__payload": udp_packet_tx,
                    "ip4__ecn": ip__ecn,
                    "ip4__dscp": ip__dscp,
                }
                if ip__ttl is not None:
                    ip4_kwargs["ip4__ttl"] = ip__ttl
                # Per-socket IPv4 options block (RFC 1122 §4.1.3.2)
                # threads through from setsockopt(IP_OPTIONS) on
                # the originating UDP socket.
                if ip4__options is not None and len(ip4__options) > 0:
                    ip4_kwargs["ip4__options"] = ip4__options
                return self._if._phtx_ip4(**ip4_kwargs)
            case _:
                raise ValueError(f"Invalid IP address version combination: {ip__src} -> {ip__dst}")

    def send_udp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """
        Interface method for UDP Socket -> Packet Assembler
        communication. 'udp__no_cksum' threads through the
        UdpSocket.send / sendto path to enable the RFC 6935 §5
        zero-checksum opt-in.

        The '_phtx_udp' pipeline is handed to this interface's TX
        worker fire-and-forget via '_marshal_tx_async' (Phase 4b):
        the calling app thread does not block for the 'TxStatus'; the
        datagram is accepted into the stack the moment it is queued,
        matching Linux's queued-on-send UDP semantics. Delivery
        failures surface asynchronously, not via the caller.

        'on_complete' (if given) fires once after the datagram leaves
        the send queue — the SO_SNDBUF release hook for the calling
        socket.
        """

        self._if._marshal_tx_async(
            lambda: self._phtx_udp(
                ip__src=ip__local_address,
                ip__dst=ip__remote_address,
                udp__sport=udp__local_port,
                udp__dport=udp__remote_port,
                udp__payload=udp__payload,
                udp__no_cksum=udp__no_cksum,
                ip__ttl=ip__ttl,
                ip__ecn=ip__ecn,
                ip__dscp=ip__dscp,
                ip4__options=ip4__options,
            ),
            on_complete=on_complete,
        )
