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
This module contains packet handler for the outbound IPv6 fragment extension header.

pytcp/runtime/packet_handler/packet_handler__ip6_frag__tx.py

ver 3.0.10
"""

import secrets
from typing import TYPE_CHECKING

from net_proto import (
    IP6__HEADER__LEN,
    IP6_FRAG__HEADER__LEN,
    Icmp6Assembler,
    Ip6Assembler,
    Ip6FragAssembler,
    TcpAssembler,
    UdpAssembler,
)
from net_proto.protocols.icmp6.message.icmp6__message import Icmp6Type
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.ip.ip_frag import iter_fragment_chunks

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# RFC 6980 §5 — NDP (Neighbor Discovery Protocol) message
# types that MUST NOT use IPv6 fragmentation. A host that
# receives a fragmented NDP message silently discards it
# (RX-side gate at packet_handler__icmp6__rx.py); the TX
# side refuses to fragment in the first place.
_NDP_TYPES: frozenset[Icmp6Type] = frozenset(
    {
        Icmp6Type.ND__ROUTER_SOLICITATION,
        Icmp6Type.ND__ROUTER_ADVERTISEMENT,
        Icmp6Type.ND__NEIGHBOR_SOLICITATION,
        Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
        Icmp6Type.ND__REDIRECT,
    }
)


def is_ndp_message(ip6_payload: object, /) -> bool:
    """
    Return True if the IPv6 payload is an ICMPv6 NDP message
    (RS / RA / NS / NA / Redirect) per RFC 6980 §5. Used by
    the IPv6 fragmentation TX path to refuse fragmentation
    of NDP messages.

    Reference: RFC 6980 §5 (NDP and SEND messages MUST NOT
    use IPv6 fragmentation).
    """

    return isinstance(ip6_payload, Icmp6Assembler) and ip6_payload.message.type in _NDP_TYPES


def _generate_ip6_frag_id() -> int:
    """
    Generate a cryptographic-quality random IPv6 Fragment
    Identification value.

    Reference: RFC 7739 §5 (Fragment Identification values
    SHOULD be unpredictable to defeat fragmentation-based
    attacks). The previous monotonic '+1' counter let an
    off-path attacker guess the next value and forge fragments
    that get reassembled with legitimate ones.

    Module-level helper rather than a method so test
    infrastructure can patch it deterministically (see
    'pytcp/tests/lib/network_testcase.py') for fixture-based
    integration tests that need known IDs.
    """

    return secrets.randbelow(2**32)


class Ip6FragTxHandler:
    """
    Packet handler for the outbound IPv6 fragment extension header.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv6 fragment TX sub-handler.
        """

        self._if = interface

    def _phtx_ip6_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus:
        """
        Handle outbound IPv6 fagment extension header.
        """

        self._if._packet_stats_tx.ip6_frag__pre_assemble += 1

        # RFC 6980 §5 — NDP and SEND messages MUST NOT use
        # IPv6 fragmentation. The receiver silently discards
        # fragmented NDP per the RX-side gate at
        # packet_handler__icmp6__rx.py; the TX side refuses
        # to fragment in the first place so we never emit a
        # frame that would be discarded.
        if is_ndp_message(ip6_packet_tx.payload):
            self._if._packet_stats_tx.ip6_frag__nd_message__drop += 1
            __debug__ and log(
                "ip6",
                f"{ip6_packet_tx.tracker} - <WARN>NDP message exceeds MTU; "
                "RFC 6980 §5 forbids fragmentation; dropping</>",
            )
            return TxStatus.DROPPED__IP6__ND_FRAGMENTATION_FORBIDDEN

        if isinstance(ip6_packet_tx.payload, (TcpAssembler, UdpAssembler, Icmp6Assembler)):
            ip6_packet_tx.payload.pshdr_sum = ip6_packet_tx.pshdr_sum

        # One Fragment Identification per datagram, held as a
        # loop-local rather than on 'self' so concurrent fragmented
        # sends cannot read each other's value (which would corrupt
        # reassembly at the peer).
        ip6_frag_id = _generate_ip6_frag_id()
        ip6_tx_status: set[TxStatus] = set()
        for offset, chunk, is_last in iter_fragment_chunks(
            bytes(ip6_packet_tx.payload),
            max_chunk_bytes=self._if._interface_mtu - IP6__HEADER__LEN - IP6_FRAG__HEADER__LEN,
        ):
            ip6_frag_tx = Ip6FragAssembler(
                ip6_frag__next=ip6_packet_tx.next,
                ip6_frag__offset=offset,
                ip6_frag__flag_mf=not is_last,
                ip6_frag__id=ip6_frag_id,
                ip6_frag__payload=chunk,
            )
            __debug__ and log("ip6", f"{ip6_frag_tx.tracker} - {ip6_frag_tx}")
            self._if._packet_stats_tx.ip6_frag__send += 1
            ip6_tx_status.add(
                self._if._phtx_ip6(
                    ip6__src=ip6_packet_tx.src,
                    ip6__dst=ip6_packet_tx.dst,
                    # RFC 2474 §3 / RFC 8200 §4.5: every fragment's
                    # outer IPv6 header inherits the original's DSCP +
                    # ECN; copy them from the source packet rather than
                    # zeroing the per-fragment Traffic Class.
                    ip6__dscp=ip6_packet_tx.dscp,
                    ip6__ecn=ip6_packet_tx.ecn,
                    ip6__payload=ip6_frag_tx,
                )
            )

        # Return the most severe code.
        for tx_status in [
            TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6,
            TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS,
            TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        ]:
            if tx_status in ip6_tx_status:
                return tx_status

        return TxStatus.DROPPED__IP6__EXT_FRAG_UNKNOWN
