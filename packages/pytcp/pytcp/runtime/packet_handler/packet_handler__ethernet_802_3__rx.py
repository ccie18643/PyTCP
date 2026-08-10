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
This module contains the packet handler for inbound IEEE
802.3 Ethernet packets. Parses the 802.3 MAC framing, then
dispatches through LLC and (when present) SNAP per RFC
1042. IP / ARP / IPv6 traffic that arrives via the SNAP
encapsulation is forwarded to the regular Ethernet II
per-protocol handlers. Non-IP LLC traffic (STP BPDUs,
Cisco-proprietary protocols, Novell IPX, etc.) is logged
and dropped with protocol-specific counters so the
operator can identify what management traffic is on the
wire.

pytcp/runtime/packet_handler/packet_handler__ethernet_802_3__rx.py

ver 3.0.10
"""

from typing import TYPE_CHECKING

from net_proto import (
    Ethernet8023Parser,
    LlcParser,
    LlcSap,
    PacketRx,
    PacketValidationError,
    SnapCiscoProtocol,
    SnapOui,
    SnapParser,
)
from net_proto.lib.enums import EtherType
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class Ethernet8023RxHandler:
    """
    The inbound IEEE 802.3 Ethernet packet handler for one interface.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_ethernet_802_3(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IEEE 802.3 Ethernet packets: MAC
        filter → LLC dispatch → SNAP dispatch → forward
        to IP/ARP handlers when SNAP-encapsulated, or
        log+drop with a protocol-specific counter
        otherwise.
        """

        self._if._packet_stats_rx.ethernet_802_3__pre_parse += 1

        try:
            Ethernet8023Parser(packet_rx)

        except PacketValidationError as error:
            self._if._packet_stats_rx.ethernet_802_3__failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ether", f"{packet_rx.tracker} - {packet_rx.ethernet_802_3}")

        # Check if received packet matches any of stack MAC addresses.
        if packet_rx.ethernet_802_3.dst not in {
            self._if._mac_unicast,
            *self._if._mac_multicast,
            self._if._mac_broadcast,
        }:
            self._if._packet_stats_rx.ethernet_802_3__dst_unknown__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Ethernet 802.3 packet not destined for this " "stack, dropping",
            )
            return

        if packet_rx.ethernet_802_3.dst == self._if._mac_unicast:
            self._if._packet_stats_rx.ethernet_802_3__dst_unicast += 1

        if packet_rx.ethernet_802_3.dst in self._if._mac_multicast:
            self._if._packet_stats_rx.ethernet_802_3__dst_multicast += 1

        if packet_rx.ethernet_802_3.dst == self._if._mac_broadcast:
            self._if._packet_stats_rx.ethernet_802_3__dst_broadcast += 1

        # LLC dispatch — parse the 3-byte LLC header and
        # route by DSAP. PyTCP supports only U-frame
        # (Type 1 connectionless) LLC; I-frame and S-frame
        # variants are rejected by the parser's integrity
        # check.
        try:
            LlcParser(packet_rx)
        except PacketValidationError as error:
            self._if._packet_stats_rx.ethernet_802_3__llc_failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ether", f"{packet_rx.tracker} - {packet_rx.llc}")

        dsap = packet_rx.llc.dsap
        if dsap is LlcSap.LAYER_MGMT:
            # IEEE 802.1D Spanning Tree Protocol BPDU.
            self._if._packet_stats_rx.ethernet_802_3__llc_stp_bpdu__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <INFO>STP BPDU</> from " f"{packet_rx.ethernet_802_3.src}, dropping",
            )
            return

        if dsap is LlcSap.NOVELL_IPX:
            self._if._packet_stats_rx.ethernet_802_3__llc_novell_ipx__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <INFO>Novell IPX over 802.2</>, dropping",
            )
            return

        if dsap is LlcSap.GLOBAL:
            self._if._packet_stats_rx.ethernet_802_3__llc_global_dsap__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <INFO>Global DSAP (Novell raw 802.3)</>, dropping",
            )
            return

        if dsap is not LlcSap.SNAP:
            self._if._packet_stats_rx.ethernet_802_3__llc_unknown_dsap__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <INFO>Unknown DSAP {dsap}</> from " f"{packet_rx.ethernet_802_3.src}, dropping",
            )
            return

        # DSAP = SNAP (0xAA): parse the 5-byte SNAP header
        # and dispatch by OUI + PID.
        try:
            SnapParser(packet_rx)
        except PacketValidationError as error:
            self._if._packet_stats_rx.ethernet_802_3__snap_failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ether", f"{packet_rx.tracker} - {packet_rx.snap}")

        snap_oui = packet_rx.snap.oui
        snap_pid = packet_rx.snap.pid

        if snap_oui == SnapOui.ENCAP_ETHERTYPE:
            # RFC 1042 §"Header Format" canonical case —
            # PID is a standard EtherType, dispatch to the
            # Ethernet II protocol handlers.
            self.__dispatch_rfc1042(packet_rx, snap_pid)
            return

        if snap_oui == SnapOui.CISCO:
            self.__dispatch_snap_cisco(packet_rx, snap_pid)
            return

        # Unknown SNAP OUI (IEEE 802.1, Apple, etc., or a
        # vendor OUI we don't recognise).
        self._if._packet_stats_rx.ethernet_802_3__snap_unknown_oui__drop += 1
        __debug__ and log(
            "ether",
            f"{packet_rx.tracker} - <INFO>Unknown SNAP OUI 0x{snap_oui:06x} "
            f"PID 0x{snap_pid:04x}</> from {packet_rx.ethernet_802_3.src}, dropping",
        )

    def __dispatch_rfc1042(self, packet_rx: PacketRx, ether_type: int) -> None:
        """
        Dispatch an RFC 1042 SNAP-encapsulated frame (OUI =
        0x000000) to the regular Ethernet II protocol
        handler matching the encoded EtherType.
        """

        # EtherType is a stdlib ProtoEnum member, not an IntEnum;
        # comparisons go through 'int(...)' so equality is
        # well-defined against the int 'ether_type' value.
        if ether_type == int(EtherType.IP4):
            self._if._packet_stats_rx.ethernet_802_3__snap_rfc1042_ip4 += 1
            self._if._phrx_ip4(packet_rx)
            return
        if ether_type == int(EtherType.IP6):
            self._if._packet_stats_rx.ethernet_802_3__snap_rfc1042_ip6 += 1
            self._if._phrx_ip6(packet_rx)
            return
        if ether_type == int(EtherType.ARP):
            self._if._packet_stats_rx.ethernet_802_3__snap_rfc1042_arp += 1
            self._if._phrx_arp(packet_rx)
            return

        self._if._packet_stats_rx.ethernet_802_3__snap_rfc1042_unknown__drop += 1
        __debug__ and log(
            "ether",
            f"{packet_rx.tracker} - <INFO>RFC 1042 SNAP with unsupported " f"EtherType 0x{ether_type:04x}</>, dropping",
        )

    def __dispatch_snap_cisco(self, packet_rx: PacketRx, pid: int) -> None:
        """
        Dispatch a Cisco-OUI SNAP-encapsulated frame
        (0x00000C) by PID. PyTCP does not process Cisco
        management traffic; the handler logs the
        protocol-specific identity and drops the frame
        with a dedicated counter so log analysis can
        identify what management traffic the network is
        carrying.
        """

        match pid:
            case SnapCiscoProtocol.CDP:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_cdp__drop += 1
                proto = "CDP"
            case SnapCiscoProtocol.CGMP:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_cgmp__drop += 1
                proto = "CGMP"
            case SnapCiscoProtocol.VTP:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_vtp__drop += 1
                proto = "VTP"
            case SnapCiscoProtocol.DTP:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_dtp__drop += 1
                proto = "DTP"
            case SnapCiscoProtocol.PVST_PLUS_BPDU:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_pvst_plus__drop += 1
                proto = "PVST+ BPDU"
            case SnapCiscoProtocol.VLAN_BRIDGE:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_vlan_bridge__drop += 1
                proto = "VLAN-Bridge"
            case SnapCiscoProtocol.UDLD:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_udld__drop += 1
                proto = "UDLD"
            case _:
                self._if._packet_stats_rx.ethernet_802_3__snap_cisco_unknown__drop += 1
                proto = f"Cisco-unknown(0x{pid:04x})"

        __debug__ and log(
            "ether",
            f"{packet_rx.tracker} - <INFO>Cisco {proto}</> from " f"{packet_rx.ethernet_802_3.src}, dropping",
        )
