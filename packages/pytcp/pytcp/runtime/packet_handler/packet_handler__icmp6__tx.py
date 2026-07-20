############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains packet handler for the outbound ICMPv6 packets.

pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py

ver 3.0.8
"""

import struct
from typing import TYPE_CHECKING

from net_addr import Buffer, Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6Message,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOption,
    Icmp6NdOptionNonce,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6Type,
    IpProto,
    Tracker,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__done import (
    Icmp6Mld1MessageDone,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    Icmp6Mld1MessageReport,
    MldVersion,
)
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__router_alert import (
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
    Ip6HbhOptionRouterAlert,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv6 MLD destinations (RFC 3810 §5.2.14 / RFC 2710 §3): an MLDv2
# Report goes to the all-MLDv2-routers group; the all-nodes group is
# never reported (RFC 3810 §6).
MLD__ALL_MLDV2_ROUTERS = Ip6Address("ff02::16")
MLD__ALL_NODES = Ip6Address("ff02::1")


class Icmp6TxHandler:
    """
    The outbound ICMPv6 packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phtx_icmp6(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv6 packets.
        """

        self._if._packet_stats_tx.icmp6__pre_assemble += 1

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=icmp6__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}")

        match icmp6__message.type, icmp6__message.code:
            case Icmp6Type.ECHO_REPLY, _:
                self._if._packet_stats_tx.icmp6__echo_reply__send += 1
            case Icmp6Type.ECHO_REQUEST, _:
                self._if._packet_stats_tx.icmp6__echo_request__send += 1
            case (
                Icmp6Type.DESTINATION_UNREACHABLE,
                Icmp6DestinationUnreachableCode.PORT,
            ):
                self._if._packet_stats_tx.icmp6__destination_unreachable__port__send += 1
            case Icmp6Type.PARAMETER_PROBLEM, _:
                self._if._packet_stats_tx.icmp6__parameter_problem__send += 1
            case Icmp6Type.ND__ROUTER_SOLICITATION, _:
                self._if._packet_stats_tx.icmp6__nd__router_solicitation__send += 1
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT, _:
                self._if._packet_stats_tx.icmp6__nd__router_advertisement__send += 1
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION, _:
                self._if._packet_stats_tx.icmp6__nd__neighbor_solicitation__send += 1
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT, _:
                self._if._packet_stats_tx.icmp6__nd__neighbor_advertisement__send += 1
            case Icmp6Type.MLD2__REPORT, _:
                self._if._packet_stats_tx.icmp6__mld2__report__send += 1
            case _:
                # Defensive drop: unsupported ICMPv6 type/code shouldn't
                # reach the TX path (the call sites enumerate their
                # message types), but if one does, count + drop is
                # robust where 'raise' would crash the calling thread.
                self._if._packet_stats_tx.icmp6__unknown__drop += 1
                __debug__ and log(
                    "icmp6",
                    f"{icmp6_packet_tx.tracker} - <CRIT>Dropping unsupported ICMPv6 "
                    f"type {icmp6__message.type}, code {icmp6__message.code}</>",
                )
                return TxStatus.DROPPED__ICMP6__UNKNOWN

        return self._if._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=icmp6_packet_tx,
        )

    def _send_icmp6_nd_dad_message(
        self,
        *,
        ip6_unicast_candidate: Ip6Address,
        nonce: bytes | None = None,
    ) -> None:
        """
        Send out ICMPv6 ND Duplicate Address Detection message.
        When 'nonce' is supplied, the probe carries a Nonce option
        per RFC 7527 §4.1 (Enhanced DAD); the caller tracks the
        emitted nonce so the NS-RX path can drop loop-hairpin
        echoes of our own probe.
        """

        options: list[Icmp6NdOption] = []
        if nonce is not None:
            options.append(Icmp6NdOptionNonce(nonce=nonce))

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=Ip6Address(),
                ip6__dst=ip6_unicast_candidate.solicited_node_multicast,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=ip6_unicast_candidate,
                    options=Icmp6NdOptions(*options),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 ND DAD message for " f"{ip6_unicast_candidate}, tx_status: {tx_status}",
            )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send out ICMPv6 Multicast Listener Report for given list of
        addresses, wrapped in a Hop-by-Hop Options header carrying
        the Router Alert option (value=MLD) so MLD-aware routers
        intercept the report per RFC 3810 §5 + RFC 2711.

        Hop Limit is fixed at 1 per RFC 3810 §5.2.13 (MLDv2 messages
        are link-local).
        """

        # All-Multicast-Nodes (ff02::1) is never advertised (RFC 3810
        # §6); a 'set' deduplicates the membership list.
        groups = {group for group in self._if._ip6_multicast if group != Ip6Address("ff02::1")}
        if not groups:
            return

        # RFC 3810 §8.3.1 report-form selection: while the interface
        # is in MLDv1 Host Compatibility Mode (an MLDv1 Query was heard
        # within the §8.2.1 Older Version Querier Present timeout),
        # emit one MLDv1 Report (type 131) per group instead of the
        # single aggregated MLDv2 Report (type 143). The querier that
        # speaks only MLDv1 cannot parse a type-143 Report.
        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            for group in groups:
                self._send_icmp6_mld1_report(group)
            return

        # MLDv2: one aggregated Report (CHANGE_TO_EXCLUDE per group) to
        # the all-MLDv2-routers address.
        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                        multicast_address=group,
                    )
                    for group in groups
                ],
            ),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::16"))

    def _send_icmp6_mld1_report(self, group: Ip6Address, /) -> None:
        """
        Send an MLDv1 Multicast Listener Report (type 131) for 'group'.

        Reference: RFC 2710 §3 / RFC 3810 §8.3.1.

        Per RFC 2710 §3 an MLDv1 Report is sent to the multicast
        address being reported (so the destination is 'group' itself),
        wrapped in the same Hop-by-Hop Router Alert carrier as the
        MLDv2 Report, with Hop Limit 1.
        """

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld1MessageReport(multicast_address=group),
        )
        self._if._packet_stats_tx.icmp6__mld1__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=group)

    def _send_icmp6_mld1_done(self, group: Ip6Address, /) -> None:
        """
        Send an MLDv1 Multicast Listener Done (type 132) for 'group'.

        Reference: RFC 2710 §3 (MLDv1 Done sent to all-routers ff02::2).
        Reference: RFC 3810 §8.3.2 (emit MLDv1 Done while in v1 mode).
        """

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld1MessageDone(multicast_address=group),
        )
        self._if._packet_stats_tx.icmp6__mld1__done__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::2"))

    def _send_icmp6_mld_leave_all(self) -> None:
        """
        Announce departure from every joined IPv6 multicast group, for
        the stack-shutdown graceful-leave path.

        Reference: RFC 3810 §6.1 (graceful leave on shutdown).

        All-nodes (ff02::1) is never reported (RFC 3810 §6). While in
        MLDv1 Host Compatibility Mode one MLDv1 Done is emitted per group;
        otherwise a single aggregated MLDv2 State Change Report carries a
        CHANGE_TO_INCLUDE record per group.
        """

        groups = {group for group in self._if._ip6_multicast if group != Ip6Address("ff02::1")}
        if not groups:
            return

        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            for group in groups:
                self._send_icmp6_mld1_done(group)
            return

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                        multicast_address=group,
                    )
                    for group in groups
                ],
            ),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::16"))

    def _emit_mld2_report(self, records: list[Icmp6Mld2MulticastAddressRecord], /) -> None:
        """
        Assemble and emit a single aggregated MLDv2 State Change Report
        (type 143) carrying 'records' to the all-MLDv2-routers group
        ff02::16, wrapped in the Hop-by-Hop Router Alert carrier
        (RFC 3810 §5.2.14). A report with no records is not emitted.
        """

        if not records:
            return

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(records=records),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=MLD__ALL_MLDV2_ROUTERS)

    @staticmethod
    def _mld_state_change_records(
        group: Ip6Address,
        old: Ip6MulticastFilter,
        new: Ip6MulticastFilter,
        /,
    ) -> list[Icmp6Mld2MulticastAddressRecord]:
        """
        Compute the MLDv2 difference records for a group's filter change
        per the RFC 3810 §6.1 table (the "non-listener" state is
        INCLUDE{}): a filter-mode change yields one CHANGE_TO_INCLUDE /
        CHANGE_TO_EXCLUDE record carrying the new source list; a
        within-mode source change yields ALLOW_NEW_SOURCES and/or
        BLOCK_OLD_SOURCES records (empty ones are omitted). The IPv6
        analogue of the IGMPv3 '_state_change_records'.
        """

        if old.mode is new.mode:
            if old.mode is Ip6MulticastFilterMode.INCLUDE:
                allow, block = new.sources - old.sources, old.sources - new.sources
            else:
                allow, block = old.sources - new.sources, new.sources - old.sources
            records: list[Icmp6Mld2MulticastAddressRecord] = []
            if allow:
                records.append(
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(allow, key=int),
                    )
                )
            if block:
                records.append(
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(block, key=int),
                    )
                )
            return records

        record_type = (
            Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE
            if new.mode is Ip6MulticastFilterMode.EXCLUDE
            else Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE
        )
        return [
            Icmp6Mld2MulticastAddressRecord(
                type=record_type,
                multicast_address=group,
                source_addresses=sorted(new.sources, key=int),
            )
        ]

    def _send_mld_state_change(
        self,
        group: Ip6Address,
        /,
        *,
        old: Ip6MulticastFilter,
        new: Ip6MulticastFilter,
    ) -> None:
        """
        Emit an unsolicited state-change Report for 'group' describing the
        transition from filter 'old' to filter 'new' (RFC 3810 §6.1) in
        the form dictated by the interface's Host Compatibility Mode
        (§8.3). In MLDv2 mode the Report carries the source-bearing §6.1
        difference records; in MLDv1 mode it degrades to the coarse
        Report / Done (MLDv1 has no source concept), keyed only off the
        reception edge. The all-nodes group ff02::1 is never reported
        (RFC 3810 §6). The IPv6 analogue of '_send_igmp_state_change'.
        """

        if group == MLD__ALL_NODES:
            return

        # The coarse MLDv1 form keys only off the reception edge — a
        # source-only change within a still-joined membership is invisible
        # to an older-version querier.
        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            if new.has_reception and not old.has_reception:
                self._send_icmp6_mld1_report(group)
            elif old.has_reception and not new.has_reception:
                self._send_icmp6_mld1_done(group)
            return

        self._emit_mld2_report(self._mld_state_change_records(group, old, new))

    def __send_icmp6_mld_via_hbh_ra(self, icmp6_packet_tx: Icmp6Assembler, /, *, ip6__dst: Ip6Address) -> None:
        """
        Emit an MLD ICMPv6 message ('icmp6_packet_tx') wrapped in a
        Hop-by-Hop Options header carrying the Router Alert option
        (value=MLD, RFC 2711) so MLD-aware routers intercept it
        (RFC 3810 §5 / RFC 2710 §3), with Hop Limit 1 (link-local).

        Shared by the MLDv2 aggregate Report and the per-group MLDv1
        Reports — the only differences are the ICMPv6 message and the
        destination.
        """

        ip6__src = self._if.ip6_unicast[0] if self._if.ip6_unicast else Ip6Address()

        # Pre-compute the ICMPv6 pseudo-header sum used to finalise the
        # ICMPv6 checksum. RFC 4443 §2.3: the pseudo-header carries
        # 'src + dst + Upper-Layer Packet Length + Next Header = 58'
        # regardless of the extension headers between IPv6 and ICMPv6,
        # so it is computed here — 'Ip6Assembler' only auto-injects
        # pshdr_sum when the immediate IPv6 payload is the transport
        # message, not when it is a Hop-by-Hop extension header.
        pseudo_header = struct.pack(
            "! 16s 16s L BBBB",
            bytes(ip6__src),
            bytes(ip6__dst),
            len(icmp6_packet_tx),
            0,
            0,
            0,
            int(IpProto.ICMP6),
        )
        icmp6_packet_tx.pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))

        icmp6_buffers: list[Buffer] = []
        icmp6_packet_tx.assemble(icmp6_buffers)
        icmp6_bytes = b"".join(bytes(buf) for buf in icmp6_buffers)

        # HBH = 2-byte prefix + 4-byte Router Alert + 2-byte PadN(0) = 8 octets.
        hbh_packet_tx = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.ICMP6,
            ip6_hbh__options=Ip6HbhOptions(
                Ip6HbhOptionRouterAlert(value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD),
                Ip6HbhOptionPadN(b""),
            ),
            ip6_hbh__payload=icmp6_bytes,
            echo_tracker=icmp6_packet_tx.tracker,
        )

        self._if._packet_stats_tx.icmp6__pre_assemble += 1

        tx_status = self._if._marshal_tx(
            lambda: self._if._phtx_ip6(
                ip6__src=ip6__src,
                ip6__dst=ip6__dst,
                ip6__hop=1,
                ip6__payload=hbh_packet_tx,
            )
        )

        if tx_status in {TxStatus.PASSED__ETHERNET__TO_TX_RING, TxStatus.PASSED__IP6__TO_TX_RING}:
            __debug__ and log("stack", f"Sent out ICMPv6 Multicast Listener Report (HBH+RA) to {ip6__dst}")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 Multicast Listener Report (HBH+RA) to {ip6__dst}, tx_status: {tx_status}",
            )

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send out ICMPv6 ND Router Solicitation.
        """

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=self._if.ip6_unicast[0],
                ip6__dst=Ip6Address("ff02::2"),
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageRouterSolicitation(
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=self._if._mac_unicast),
                    ),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Router Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Router Solicitation, {tx_status}",
            )

    def send_icmp6_neighbor_solicitation(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a multicast ICMPv6 Neighbor Solicitation — the
        INCOMPLETE-state form (RFC 4861 §7.2.2). The IPv6
        destination is the target's solicited-node multicast
        address.
        """

        # Pick appropriate source address
        ip6__src = Ip6Address()
        for ip6_host in self._if._ip6_ifaddr:
            if icmp6_ns_target_address in ip6_host.network:
                ip6__src = ip6_host.address

        # Send out ND Neighbor Solicitation message
        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=icmp6_ns_target_address.solicited_node_multicast,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=icmp6_ns_target_address,
                    options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self._if._mac_unicast)),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Neighbor Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Neighbor Solicitation, {tx_status}",
            )

    def send_icmp6_neighbor_solicitation_unicast(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a unicast ICMPv6 Neighbor Solicitation — the
        NUD_PROBE-state form (RFC 4861 §7.3.3). The IPv6
        destination is the target address itself, NOT the
        solicited-node multicast group; the cached neighbour's
        MAC resolves at the Ethernet TX layer via the ND
        cache's PROBE-state entry. RFC 4861 §4.3 SHOULDs
        including the SLLA option in unicast solicitations,
        which we do (matches Linux).

        Used by 'NdCache._solicit_ns' when the FSM enters
        NUD_PROBE — the cached_mac is non-None, so the cache
        already has a working entry and only needs to confirm
        liveness. This saves segment-wide multicast bandwidth
        relative to a full re-resolution.
        """

        # Pick appropriate source address — same logic as the
        # multicast variant since the target is on a known
        # local subnet (we already have a cache entry for it).
        ip6__src = Ip6Address()
        for ip6_host in self._if._ip6_ifaddr:
            if icmp6_ns_target_address in ip6_host.network:
                ip6__src = ip6_host.address

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=icmp6_ns_target_address,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=icmp6_ns_target_address,
                    options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self._if._mac_unicast)),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                f"Sent out unicast ICMPv6 ND Neighbor Solicitation for {icmp6_ns_target_address}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out unicast ICMPv6 ND Neighbor Solicitation for "
                f"{icmp6_ns_target_address}, {tx_status}",
            )

    def send_icmp6_neighbor_advertisement(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        target_address: Ip6Address,
        flag_r: bool = False,
        flag_s: bool = False,
        flag_o: bool = False,
        include_tlla: bool = True,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Enqueue an ICMPv6 ND Neighbor Advertisement (RFC 4861
        §4.4 wire format). Hop limit hard-set to 255 per
        §7.1.2.

        The 'flag_r' / 'flag_s' / 'flag_o' kwargs map to the
        wire R(outer) / S(olicited) / O(verride) flags. The
        canonical solicited-NA reply path uses flag_s=True; the
        gratuitous form (RFC 9131 §3) uses flag_o=True with
        flag_s=False. 'include_tlla' attaches the host's MAC
        as a TLLA option — required for solicited replies and
        for gratuitous announcements.

        RFC 4429 §3.3: when 'ip6__src' is currently OPTIMISTIC
        the Override flag is forcibly cleared regardless of the
        caller-requested value, so peers do not overwrite an
        existing cache entry on the basis of an unverified
        address.
        """

        from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState

        if self._if._icmp6_dad__states.get(ip6__src) is Icmp6DadState.OPTIMISTIC:
            flag_o = False

        options = Icmp6NdOptions(Icmp6NdOptionTlla(tlla=self._if._mac_unicast)) if include_tlla else Icmp6NdOptions()

        self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=ip6__dst,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                    flag_r=flag_r,
                    flag_s=flag_s,
                    flag_o=flag_o,
                    target_address=target_address,
                    options=options,
                ),
                echo_tracker=echo_tracker,
            )
        )

    def send_icmp6_neighbor_advertisement_gratuitous(
        self,
        *,
        ip6_unicast: Ip6Address,
    ) -> None:
        """
        Enqueue 'icmp6.gratuitous_na_count' gratuitous Neighbor
        Advertisement messages for 'ip6_unicast' — the IPv6
        analogue of RFC 5227 §2.3 ARP Announcement, formalised
        by RFC 9131 §3 (host attachment). The wire shape:

          - Target Address = 'ip6_unicast'
          - flag_o (Override) = True (overrides any cache
            entry for this address — the whole point)
          - flag_s (Solicited) = False (unsolicited)
          - Destination = ff02::1 (all-nodes link-local
            multicast — every on-link host receives it)
          - TLLA option carries the host's MAC

        Operators tune the emit count via the
        'icmp6.gratuitous_na_count' sysctl (default 1; 0 is the
        kill switch).
        """

        for _ in range(sysctl_iface.get_for_iface("icmp6.gratuitous_na_count", self._if._interface_name)):
            self.send_icmp6_neighbor_advertisement(
                ip6__src=ip6_unicast,
                ip6__dst=Ip6Address("ff02::1"),
                target_address=ip6_unicast,
                flag_s=False,
                flag_o=True,
                include_tlla=True,
            )

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv6 Socket -> FPA communication.
        Marshaled onto the interface's TX worker via '_marshal_tx'.
        """

        return self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__local_address,
                ip6__dst=ip6__remote_address,
                ip6__hop=ip6__hop,
                icmp6__message=icmp6__message,
            )
        )
