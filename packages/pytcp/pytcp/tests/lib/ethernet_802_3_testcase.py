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
The 'Ethernet8023TestCase' integration-test harness —
wraps 'NetworkTestCase' with frame builders for IEEE 802.3
+ LLC (+ optional SNAP) frames. Covers the canonical
real-world traffic patterns on a switched local network:

  * STP / RSTP BPDUs (DSAP = SSAP = 0x42, no SNAP)
  * RFC 1042 IP-over-SNAP (DSAP = SSAP = 0xAA, SNAP OUI=0,
    PID = EtherType)
  * Cisco SNAP (DSAP = SSAP = 0xAA, SNAP OUI = 0x00000C,
    PID = CDP / VTP / DTP / PVST+ / UDLD)
  * Novell IPX over 802.2 (DSAP = SSAP = 0xE0)
  * Novell raw 802.3 (DSAP = SSAP = 0xFF Global)

pytcp/tests/lib/ethernet_802_3_testcase.py

ver 3.0.9
"""

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.llc.llc__enums import LlcControl, LlcSap
from net_proto.protocols.snap.snap__enums import SnapCiscoProtocol, SnapOui
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

# Well-known STP destination MAC (IEEE 802.1D §9.2.7).
STP_BPDU__DEST_MAC: MacAddress = MacAddress(0x0180_C200_0000)
# Well-known Cisco discovery / management destination MAC.
CISCO_DISCOVERY__DEST_MAC: MacAddress = MacAddress(0x0100_0CCC_CCCC)


def _build_802_3_frame(*, dst_mac: MacAddress, src_mac: MacAddress, payload: bytes) -> bytes:
    """
    Build a raw IEEE 802.3 frame: 6-byte dst MAC + 6-byte
    src MAC + 2-byte dlen + LLC-and-payload bytes. The
    dlen field is computed automatically from the payload
    length.
    """

    return bytes(dst_mac) + bytes(src_mac) + len(payload).to_bytes(2) + payload


class Ethernet8023TestCase(NetworkTestCase):
    """
    Integration-test harness for the IEEE 802.3 + LLC +
    optional-SNAP RX path. Provides frame builders for
    the canonical real-world traffic patterns; tests
    consume them via '_drive_802_3_rx' and assert on
    'packet_stats_rx'.
    """

    @staticmethod
    def _build_stp_bpdu_frame(
        *,
        dst_mac: MacAddress | None = None,
        src_mac: MacAddress | None = None,
        bpdu_payload: bytes = b"\x00" * 35,  # Minimal-but-sized BPDU stub.
    ) -> bytes:
        """
        Build an IEEE 802.1D STP BPDU frame:
            DST MAC : dst_mac (default 01:80:C2:00:00:00 STP multicast)
            SRC MAC : src_mac (default HOST_A)
            DLEN    : 3 + len(bpdu_payload)
            LLC     : DSAP=0x42, SSAP=0x42, Control=0x03 (UI)
            Payload : bpdu_payload
        """

        dst = dst_mac if dst_mac is not None else STP_BPDU__DEST_MAC
        src = src_mac if src_mac is not None else HOST_A__MAC_ADDRESS
        llc_and_payload = (
            int(LlcSap.LAYER_MGMT).to_bytes(1)
            + int(LlcSap.LAYER_MGMT).to_bytes(1)
            + int(LlcControl.UI).to_bytes(1)
            + bpdu_payload
        )
        return _build_802_3_frame(
            dst_mac=dst,
            src_mac=src,
            payload=llc_and_payload,
        )

    @staticmethod
    def _build_snap_ethertype_frame(
        *,
        ether_type: EtherType,
        snap_payload: bytes,
        dst_mac: MacAddress | None = None,
        src_mac: MacAddress | None = None,
    ) -> bytes:
        """
        Build an RFC 1042 SNAP-encapsulated frame carrying
        an arbitrary EtherType payload (IP4 / IP6 / ARP).
            DST MAC : dst_mac (default STACK unicast)
            SRC MAC : src_mac (default HOST_A)
            DLEN    : 3 (LLC) + 5 (SNAP) + len(snap_payload)
            LLC     : DSAP=SSAP=0xAA, Control=UI
            SNAP    : OUI=0x000000, PID=ether_type
            Payload : snap_payload
        """

        dst = dst_mac if dst_mac is not None else STACK__MAC_ADDRESS
        src = src_mac if src_mac is not None else HOST_A__MAC_ADDRESS
        llc_snap_and_payload = (
            int(LlcSap.SNAP).to_bytes(1)
            + int(LlcSap.SNAP).to_bytes(1)
            + int(LlcControl.UI).to_bytes(1)
            + int(SnapOui.ENCAP_ETHERTYPE).to_bytes(3)
            + int(ether_type).to_bytes(2)
            + snap_payload
        )
        return _build_802_3_frame(
            dst_mac=dst,
            src_mac=src,
            payload=llc_snap_and_payload,
        )

    @staticmethod
    def _build_cisco_snap_frame(
        *,
        cisco_protocol: SnapCiscoProtocol,
        snap_payload: bytes = b"\x00\x00\x00\x00",
        dst_mac: MacAddress | None = None,
        src_mac: MacAddress | None = None,
    ) -> bytes:
        """
        Build a Cisco-OUI SNAP frame carrying one of the
        well-known Cisco-proprietary protocols (CDP / VTP /
        DTP / PVST+ / UDLD).
            DST MAC : dst_mac (default 01:00:0c:cc:cc:cc Cisco multicast)
            SRC MAC : src_mac (default HOST_A)
            LLC     : DSAP=SSAP=0xAA, Control=UI
            SNAP    : OUI=0x00000C (Cisco), PID=cisco_protocol
            Payload : snap_payload (caller-provided stub)
        """

        dst = dst_mac if dst_mac is not None else CISCO_DISCOVERY__DEST_MAC
        src = src_mac if src_mac is not None else HOST_A__MAC_ADDRESS
        llc_snap_and_payload = (
            int(LlcSap.SNAP).to_bytes(1)
            + int(LlcSap.SNAP).to_bytes(1)
            + int(LlcControl.UI).to_bytes(1)
            + int(SnapOui.CISCO).to_bytes(3)
            + int(cisco_protocol).to_bytes(2)
            + snap_payload
        )
        return _build_802_3_frame(
            dst_mac=dst,
            src_mac=src,
            payload=llc_snap_and_payload,
        )

    @staticmethod
    def _build_novell_ipx_frame(
        *,
        src_mac: MacAddress | None = None,
        ipx_payload: bytes = b"\x00" * 30,
    ) -> bytes:
        """
        Build a Novell-IPX-over-802.2 frame (DSAP = SSAP =
        0xE0). Real Novell traffic; addressed to broadcast
        by default.
        """

        src = src_mac if src_mac is not None else HOST_A__MAC_ADDRESS
        llc_and_payload = (
            int(LlcSap.NOVELL_IPX).to_bytes(1)
            + int(LlcSap.NOVELL_IPX).to_bytes(1)
            + int(LlcControl.UI).to_bytes(1)
            + ipx_payload
        )
        return _build_802_3_frame(
            dst_mac=MacAddress(0xFFFFFFFFFFFF),
            src_mac=src,
            payload=llc_and_payload,
        )

    def _drive_802_3_rx(self, *, frame: bytes) -> None:
        """
        Drive a raw 802.3 frame into the
        '_phrx_ethernet_802_3' handler.
        """

        self._packet_handler._phrx_ethernet_802_3(PacketRx(frame))
