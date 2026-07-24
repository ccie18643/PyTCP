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
This module contains packet handler for the outbound TCP packets.

pytcp/runtime/packet_handler/packet_handler__tcp__tx.py

ver 3.0.9
"""

from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, Ip6Address
from net_proto import (
    TcpAssembler,
    TcpOptionMss,
    TcpOptionNop,
    TcpOptions,
    TcpOptionWscale,
    Tracker,
)
from net_proto.protocols.tcp.options.tcp__option import TcpOption
from net_proto.protocols.tcp.options.tcp__option__accecn0 import TcpOptionAccecn0
from net_proto.protocols.tcp.options.tcp__option__accecn1 import TcpOptionAccecn1
from net_proto.protocols.tcp.options.tcp__option__fastopen import TcpOptionFastOpen
from net_proto.protocols.tcp.options.tcp__option__sack import (
    TcpOptionSack,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp__option__sackperm import TcpOptionSackperm
from net_proto.protocols.tcp.options.tcp__option__timestamps import TcpOptionTimestamps
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class TcpTxHandler:
    """
    The outbound TCP packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phtx_tcp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        tcp__sport: int,
        tcp__dport: int,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__flag_ns: bool = False,
        tcp__flag_cwr: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_urg: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_syn: bool = False,
        tcp__flag_fin: bool = False,
        tcp__mss: int | None = None,
        tcp__wscale: int | None = None,
        tcp__sackperm: bool = False,
        tcp__sack_blocks: list[tuple[int, int]] | None = None,
        tcp__tsval: int | None = None,
        tcp__tsecr: int | None = None,
        tcp__fastopen_cookie: bytes | None = None,
        tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__accecn1_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__win: int = 0,
        tcp__urg: int = 0,
        tcp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound TCP packets.
        """

        self._if._packet_stats_tx.tcp__pre_assemble += 1

        # Build the option list cumulatively so multiple options
        # can co-exist on the wire (an MSS-only SYN, a WSCALE-only
        # SYN, a SYN carrying MSS + SACK-Permitted + WSCALE, or a
        # post-handshake ACK carrying a SACK option). The previous
        # write-then-overwrite pattern broke the dual-option case
        # by losing the MSS when WSCALE was also requested. Pad
        # with NOPs at the end so the total option block length
        # is a multiple of 4 bytes (TCP requires 4-byte alignment
        # of the data offset).
        opts: list[TcpOption] = []

        if tcp__mss:
            self._if._packet_stats_tx.tcp__opt_mss += 1
            opts.append(TcpOptionMss(mss=tcp__mss))

        if tcp__sackperm:
            self._if._packet_stats_tx.tcp__opt_sackperm += 1
            opts.append(TcpOptionSackperm())

        if tcp__wscale:
            self._if._packet_stats_tx.tcp__opt_nop += 1
            self._if._packet_stats_tx.tcp__opt_wscale += 1
            opts.append(TcpOptionNop())
            opts.append(TcpOptionWscale(wscale=tcp__wscale))

        if tcp__sack_blocks:
            self._if._packet_stats_tx.tcp__opt_sack += 1
            opts.append(TcpOptionSack(blocks=[TcpSackBlock(left, right) for left, right in tcp__sack_blocks]))

        if tcp__tsval is not None and tcp__tsecr is not None:
            self._if._packet_stats_tx.tcp__opt_timestamps += 1
            opts.append(TcpOptionTimestamps(tsval=tcp__tsval, tsecr=tcp__tsecr))

        if tcp__fastopen_cookie is not None:
            opts.append(TcpOptionFastOpen(cookie=tcp__fastopen_cookie))

        if tcp__accecn0_counters is not None:
            opts.append(
                TcpOptionAccecn0(
                    ee0b=tcp__accecn0_counters[0],
                    eceb=tcp__accecn0_counters[1],
                    ee1b=tcp__accecn0_counters[2],
                )
            )

        if tcp__accecn1_counters is not None:
            opts.append(
                TcpOptionAccecn1(
                    ee0b=tcp__accecn1_counters[0],
                    eceb=tcp__accecn1_counters[1],
                    ee1b=tcp__accecn1_counters[2],
                )
            )

        pad_count = (-sum(len(opt) for opt in opts)) % 4
        opts.extend(TcpOptionNop() for _ in range(pad_count))

        options = TcpOptions(*opts)

        tcp_packet_tx = TcpAssembler(
            tcp__sport=tcp__sport,
            tcp__dport=tcp__dport,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__flag_ns=tcp__flag_ns,
            tcp__flag_cwr=tcp__flag_cwr,
            tcp__flag_ece=tcp__flag_ece,
            tcp__flag_urg=tcp__flag_urg,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_psh=tcp__flag_psh,
            tcp__flag_rst=tcp__flag_rst,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_fin=tcp__flag_fin,
            tcp__win=tcp__win,
            tcp__urg=tcp__urg,
            tcp__options=options,
            tcp__payload=tcp__payload,
            echo_tracker=echo_tracker,
        )

        if tcp__flag_ns:
            self._if._packet_stats_tx.tcp__flag_ns += 1

        if tcp__flag_cwr:
            self._if._packet_stats_tx.tcp__flag_cwr += 1

        if tcp__flag_ece:
            self._if._packet_stats_tx.tcp__flag_ece += 1

        if tcp__flag_urg:
            self._if._packet_stats_tx.tcp__flag_urg += 1

        if tcp__flag_ack:
            self._if._packet_stats_tx.tcp__flag_ack += 1

        if tcp__flag_psh:
            self._if._packet_stats_tx.tcp__flag_psh += 1

        if tcp__flag_rst:
            self._if._packet_stats_tx.tcp__flag_rst += 1

        if tcp__flag_syn:
            self._if._packet_stats_tx.tcp__flag_syn += 1

        if tcp__flag_fin:
            self._if._packet_stats_tx.tcp__flag_fin += 1

        __debug__ and log("tcp", f"{tcp_packet_tx.tracker} - {tcp_packet_tx}")

        match ip__src.is_ip6, ip__dst.is_ip6, ip__src.is_ip4, ip__dst.is_ip4:
            case True, True, False, False:
                self._if._packet_stats_tx.tcp__send += 1
                return self._if._phtx_ip6(
                    ip6__src=cast(Ip6Address, ip__src),
                    ip6__dst=cast(Ip6Address, ip__dst),
                    ip6__hop=ip__ttl,
                    ip6__ecn=ip__ecn,
                    ip6__dscp=ip__dscp,
                    ip6__payload=tcp_packet_tx,
                )
            case False, False, True, True:
                self._if._packet_stats_tx.tcp__send += 1
                # RFC 1191 §3 / RFC 9293 §3.7.5: outbound TCP segments
                # set DF=1 to elicit ICMP Frag-Needed for path-MTU
                # discovery rather than allowing in-network
                # fragmentation.
                return self._if._phtx_ip4(
                    ip4__src=cast(Ip4Address, ip__src),
                    ip4__dst=cast(Ip4Address, ip__dst),
                    ip4__ttl=ip__ttl,
                    ip4__ecn=ip__ecn,
                    ip4__dscp=ip__dscp,
                    ip4__flag_df=True,
                    ip4__payload=tcp_packet_tx,
                )
            case _:
                raise ValueError(f"Invalid IP address version combination: {ip__src} -> {ip__dst}")

    def send_tcp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        tcp__local_port: int,
        tcp__remote_port: int,
        tcp__flag_syn: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_fin: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_cwr: bool = False,
        tcp__flag_ns: bool = False,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__win: int = 0,
        tcp__wscale: int | None = None,
        tcp__mss: int | None = None,
        tcp__sackperm: bool = False,
        tcp__sack_blocks: list[tuple[int, int]] | None = None,
        tcp__tsval: int | None = None,
        tcp__tsecr: int | None = None,
        tcp__fastopen_cookie: bytes | None = None,
        tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__accecn1_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Interface method for TCP Socket -> FPA communication. The
        '_phtx_tcp' pipeline is marshaled onto this interface's TX
        worker via '_marshal_tx' (ring-handoff single-writer); the
        calling app / FSM-timer thread blocks for the 'TxStatus'.
        """

        return self._if._marshal_tx(
            lambda: self._phtx_tcp(
                ip__src=ip__local_address,
                ip__ttl=ip__ttl,
                ip__ecn=ip__ecn,
                ip__dscp=ip__dscp,
                tcp__flag_ns=tcp__flag_ns,
                ip__dst=ip__remote_address,
                tcp__sport=tcp__local_port,
                tcp__dport=tcp__remote_port,
                tcp__flag_syn=tcp__flag_syn,
                tcp__flag_ack=tcp__flag_ack,
                tcp__flag_fin=tcp__flag_fin,
                tcp__flag_rst=tcp__flag_rst,
                tcp__flag_psh=tcp__flag_psh,
                tcp__flag_ece=tcp__flag_ece,
                tcp__flag_cwr=tcp__flag_cwr,
                tcp__seq=tcp__seq,
                tcp__ack=tcp__ack,
                tcp__win=tcp__win,
                tcp__wscale=tcp__wscale,
                tcp__mss=tcp__mss,
                tcp__sackperm=tcp__sackperm,
                tcp__sack_blocks=tcp__sack_blocks,
                tcp__tsval=tcp__tsval,
                tcp__tsecr=tcp__tsecr,
                tcp__fastopen_cookie=tcp__fastopen_cookie,
                tcp__accecn0_counters=tcp__accecn0_counters,
                tcp__accecn1_counters=tcp__accecn1_counters,
                tcp__payload=tcp__payload,
            )
        )
