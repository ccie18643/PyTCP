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
Smoke tests for the 'Ethernet8023TestCase' integration-test harness.
Pins '_build_stp_bpdu_frame', '_build_snap_ethertype_frame',
'_build_cisco_snap_frame', '_build_novell_ipx_frame', and
'_drive_802_3_rx' so the migrated 802.3 RX/TX/LLC+SNAP integration
tests can rely on the harness shape.

pytcp/tests/integration/protocols/ethernet_802_3/test__ethernet_802_3__harness_smoke.py

ver 3.0.8
"""

from net_proto import SnapCiscoProtocol
from net_proto.lib.enums import EtherType
from pytcp.tests.lib.ethernet_802_3_testcase import (
    STP_BPDU__DEST_MAC,
    Ethernet8023TestCase,
)
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)


class TestEthernet8023HarnessSmoke(Ethernet8023TestCase):
    """
    Smoke tests for 'Ethernet8023TestCase'.
    """

    def test__ethernet_802_3__harness__build_stp_bpdu_frame_minimum_size(self) -> None:
        """
        Ensure '_build_stp_bpdu_frame' emits at least 14 (Ethernet)
        + 3 (LLC) + 35 (BPDU stub) bytes — the minimum-sized STP
        BPDU shape the smoke layer relies on.

        Reference: IEEE 802.1D §9 (Spanning Tree BPDU LLC encapsulation).
        """

        frame = self._build_stp_bpdu_frame()

        self.assertEqual(
            len(frame),
            14 + 3 + 35,
            msg=f"Default '_build_stp_bpdu_frame' must emit 52 bytes; got {len(frame)}.",
        )

    def test__ethernet_802_3__harness__build_stp_bpdu_frame_default_dst_is_stp_multicast(self) -> None:
        """
        Ensure '_build_stp_bpdu_frame' defaults the destination
        MAC to the canonical STP multicast (01:80:C2:00:00:00).

        Reference: IEEE 802.1D §9.2.7 (Bridge Group Address).
        """

        frame = self._build_stp_bpdu_frame()

        # First 6 bytes are the destination MAC.
        self.assertEqual(
            frame[:6],
            bytes(STP_BPDU__DEST_MAC),
            msg="Default STP BPDU dst MAC must be 01:80:C2:00:00:00.",
        )

    def test__ethernet_802_3__harness__build_stp_bpdu_drives_llc_stp_counter(self) -> None:
        """
        Ensure a BPDU frame sent to the stack unicast MAC routes
        through the LLC parser, is identified as STP traffic
        (DSAP = 0x42), and bumps the dedicated
        ethernet_802_3__llc_stp_bpdu__drop counter exactly once.

        Reference: IEEE 802.1D §9 (STP BPDU LLC encapsulation).
        """

        # The default 01:80:C2:00:00:00 dst is a multicast the
        # stack does not subscribe to, so address it to the stack
        # unicast MAC instead so the MAC filter accepts it.
        frame = self._build_stp_bpdu_frame(dst_mac=STACK__MAC_ADDRESS)

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__llc_stp_bpdu__drop,
            1,
            msg="STP BPDU must bump llc_stp_bpdu__drop exactly once.",
        )

    def test__ethernet_802_3__harness__build_snap_ethertype_frame_drives_rfc1042_dispatch(self) -> None:
        """
        Ensure '_build_snap_ethertype_frame' with EtherType IPv4
        routes through LLC + SNAP and dispatches to the RFC 1042
        IPv4 path, bumping ethernet_802_3__snap_rfc1042_ip4.

        Reference: RFC 1042 §"Header Format" (OUI = 0x000000, PID = EtherType).
        """

        frame = self._build_snap_ethertype_frame(
            ether_type=EtherType.IP4,
            snap_payload=b"\x00" * 20,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_rfc1042_ip4,
            1,
            msg="RFC 1042 SNAP-IP4 frame must bump snap_rfc1042_ip4 exactly once.",
        )

    def test__ethernet_802_3__harness__build_cisco_snap_frame_drives_cdp_counter(self) -> None:
        """
        Ensure '_build_cisco_snap_frame' with PID = CDP routes
        through LLC + SNAP, is recognised as a Cisco CDP frame
        (OUI 0x00000C / PID 0x2000), and bumps the
        snap_cisco_cdp__drop counter exactly once.

        Reference: Cisco CDP wire format (OUI 0x00000C, PID 0x2000).
        """

        # Cisco multicast dst is not subscribed by the stack;
        # address to the unicast MAC so MAC filter accepts.
        frame = self._build_cisco_snap_frame(
            cisco_protocol=SnapCiscoProtocol.CDP,
            dst_mac=STACK__MAC_ADDRESS,
        )

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__snap_cisco_cdp__drop,
            1,
            msg="CDP frame must bump snap_cisco_cdp__drop exactly once.",
        )

    def test__ethernet_802_3__harness__build_novell_ipx_frame_drives_novell_counter(self) -> None:
        """
        Ensure '_build_novell_ipx_frame' (DSAP = SSAP = 0xE0)
        routes through the LLC parser, is identified as Novell
        IPX, and bumps the ethernet_802_3__llc_novell_ipx__drop
        counter exactly once.

        Reference: Novell IPX-over-802.2 (legacy enterprise traffic).
        """

        frame = self._build_novell_ipx_frame()

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__llc_novell_ipx__drop,
            1,
            msg="Novell IPX frame must bump llc_novell_ipx__drop exactly once.",
        )

    def test__ethernet_802_3__harness__drive_802_3_rx_bumps_pre_parse(self) -> None:
        """
        Ensure '_drive_802_3_rx' feeds the frame into
        'PacketHandler._phrx_ethernet_802_3' so the pre-parse
        counter increments once per call. Pins the harness's
        "RX in" contract for the 802.3 family.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = self._build_stp_bpdu_frame(dst_mac=STACK__MAC_ADDRESS)

        self._drive_802_3_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet_802_3__pre_parse,
            1,
            msg="'_drive_802_3_rx' must bump ethernet_802_3__pre_parse exactly once.",
        )

    def test__ethernet_802_3__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'Ethernet8023TestCase.setUp' does not perturb the
        addresses, MAC, or host state inherited from
        'NetworkTestCase'. Migrated tests depend on the same
        baseline they got under the parent harness.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._mac_unicast,
            STACK__MAC_ADDRESS,
            msg="Inherited stack MAC must be unchanged.",
        )
        addresses = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            STACK__IP4_HOST.address,
            addresses,
            msg="Inherited stack IPv4 host must be present in '_ip4_ifaddr'.",
        )
