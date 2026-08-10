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
Integration tests for the IEEE 802.3 + LLC + SNAP dispatch
path in 'packet_handler__ethernet_802_3__rx.py'. Drives
real-world traffic patterns (STP BPDUs, Cisco
discovery / management protocols, RFC 1042 SNAP-IP,
Novell IPX) into the stack and asserts the per-protocol
counter increments fire so log analysis can identify the
management traffic on the wire.

pytcp/tests/integration/protocols/ethernet_802_3/test__ethernet_802_3__llc_snap.py

ver 3.0.10
"""

from net_proto import SnapCiscoProtocol
from net_proto.lib.enums import EtherType
from pytcp.tests.lib.ethernet_802_3_testcase import (
    CISCO_DISCOVERY__DEST_MAC,
    Ethernet8023TestCase,
)


class TestEthernet8023LlcSnapDispatch(Ethernet8023TestCase):
    """
    Dispatch tests for the IEEE 802.3 + LLC + SNAP RX path.
    """

    def test__ethernet_802_3__stp_bpdu__counted_and_dropped(self) -> None:
        """
        Ensure an IEEE 802.1D STP BPDU is parsed through
        LLC, identified by DSAP = 0x42 (LAYER_MGMT), and
        logged + dropped with the dedicated stp_bpdu
        counter so log analysis sees the spanning-tree
        traffic on the wire.

        Reference: IEEE 802.1D §9 (Spanning Tree BPDU LLC encapsulation).
        """

        # The real STP destination MAC (01:80:c2:00:00:00) is
        # a multicast the stack doesn't subscribe to, so the
        # frame would drop at MAC-filter before the LLC
        # parser runs. For dispatch-only verification, send
        # the frame to the stack unicast MAC.
        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_stp_bpdu_frame(dst_mac=STACK__MAC_ADDRESS)

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__llc_stp_bpdu__drop,
            1,
            msg="STP BPDU must bump the llc_stp_bpdu__drop counter exactly once.",
        )

    def test__ethernet_802_3__cdp__counted_and_dropped(self) -> None:
        """
        Ensure a Cisco CDP frame (OUI = 0x00000C, PID =
        0x2000) is parsed through LLC+SNAP and logged +
        dropped with the dedicated cdp counter.

        Reference: Cisco CDP wire format (802.3 + LLC SNAP, OUI 0x00000C, PID 0x2000).
        """

        frame = self._build_cisco_snap_frame(cisco_protocol=SnapCiscoProtocol.CDP)
        # The default dst MAC for the Cisco-snap builder is
        # the Cisco multicast (01:00:0c:cc:cc:cc) which the
        # stack does not subscribe to. For this test we
        # want the MAC filter to pass, so resend to the
        # stack unicast MAC.
        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.CDP,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_cdp__drop,
            1,
            msg="CDP frame must bump the snap_cisco_cdp__drop counter.",
        )

    def test__ethernet_802_3__vtp__counted_and_dropped(self) -> None:
        """
        Ensure a Cisco VTP frame is parsed and logged +
        dropped with the dedicated vtp counter.

        Reference: Cisco VTP wire format (OUI 0x00000C, PID 0x2003).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.VTP,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_vtp__drop,
            1,
            msg="VTP frame must bump the snap_cisco_vtp__drop counter.",
        )

    def test__ethernet_802_3__dtp__counted_and_dropped(self) -> None:
        """
        Ensure a Cisco DTP frame is parsed and logged +
        dropped with the dedicated dtp counter.

        Reference: Cisco DTP wire format (OUI 0x00000C, PID 0x2004).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.DTP,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_dtp__drop,
            1,
            msg="DTP frame must bump the snap_cisco_dtp__drop counter.",
        )

    def test__ethernet_802_3__pvst_plus__counted_and_dropped(self) -> None:
        """
        Ensure a Cisco PVST+ BPDU is parsed and logged +
        dropped with the dedicated pvst_plus counter.

        Reference: Cisco PVST+ wire format (OUI 0x00000C, PID 0x010B).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.PVST_PLUS_BPDU,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_pvst_plus__drop,
            1,
            msg="PVST+ BPDU must bump the snap_cisco_pvst_plus__drop counter.",
        )

    def test__ethernet_802_3__udld__counted_and_dropped(self) -> None:
        """
        Ensure a Cisco UDLD frame is parsed and logged +
        dropped with the dedicated udld counter.

        Reference: Cisco UDLD wire format (OUI 0x00000C, PID 0x0111).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.UDLD,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_udld__drop,
            1,
            msg="UDLD frame must bump the snap_cisco_udld__drop counter.",
        )

    def test__ethernet_802_3__novell_ipx__counted_and_dropped(self) -> None:
        """
        Ensure a Novell-IPX-over-802.2 frame (DSAP = SSAP =
        0xE0) is parsed and logged + dropped with the
        dedicated novell_ipx counter.

        Reference: Novell IPX-over-802.2 (legacy enterprise traffic).
        """

        frame = self._build_novell_ipx_frame()

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__llc_novell_ipx__drop,
            1,
            msg="Novell-IPX frame must bump the llc_novell_ipx__drop counter.",
        )

    def test__ethernet_802_3__rfc1042_ip4__dispatched_to_ip4(self) -> None:
        """
        Ensure an RFC 1042 SNAP-encapsulated IPv4 frame
        (OUI = 0x000000, PID = 0x0800) is dispatched to
        the regular IPv4 RX handler via the
        rfc1042_ip4 counter — closing the IP-over-SNAP
        path that Linux maintains for legacy interop.

        Reference: RFC 1042 §"Header Format" (OUI 0 + EtherType IP4).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        # A 20-byte zero-payload stub. The IP4 handler will
        # almost certainly reject it as malformed, but the
        # dispatch counter increments before the IP4
        # parser runs.
        frame = self._build_snap_ethertype_frame(
            ether_type=EtherType.IP4,
            snap_payload=b"\x00" * 20,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_rfc1042_ip4,
            1,
            msg="RFC 1042 SNAP-IP4 frame must bump the rfc1042_ip4 counter.",
        )

    def test__ethernet_802_3__rfc1042_arp__dispatched_to_arp(self) -> None:
        """
        Ensure an RFC 1042 SNAP-encapsulated ARP frame
        (OUI = 0x000000, PID = 0x0806) is dispatched to
        the regular ARP RX handler via the
        rfc1042_arp counter.

        Reference: RFC 1042 §"Header Format" (OUI 0 + EtherType ARP).
        """

        from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS

        frame = self._build_snap_ethertype_frame(
            ether_type=EtherType.ARP,
            snap_payload=b"\x00" * 28,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_rfc1042_arp,
            1,
            msg="RFC 1042 SNAP-ARP frame must bump the rfc1042_arp counter.",
        )

    def test__ethernet_802_3__cisco_multicast_dst__filtered(self) -> None:
        """
        Ensure a Cisco SNAP frame addressed to the Cisco
        multicast MAC (01:00:0c:cc:cc:cc), which the stack
        does NOT subscribe to, is filtered out at the
        MAC-filter stage with dst_unknown__drop before LLC
        / SNAP parsing fires.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.CDP,
            dst_mac=CISCO_DISCOVERY__DEST_MAC,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__dst_unknown__drop,
            1,
            msg="Cisco-multicast-dst frame must drop at MAC filter, not LLC.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_cdp__drop,
            0,
            msg="MAC-filter-dropped frame must NOT also bump the cisco_cdp counter.",
        )
