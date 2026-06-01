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
The 'EthernetTestCase' integration-test harness — wraps
'NetworkTestCase' with frame builders for Ethernet II
(DIX / RFC 894) frames addressed to / from the canonical
fixture topology.

pytcp/tests/lib/ethernet_testcase.py

ver 3.0.8
"""

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

_BROADCAST_MAC: MacAddress = MacAddress(0xFFFFFFFFFFFF)


class EthernetTestCase(NetworkTestCase):
    """
    Integration-test harness for the Ethernet II
    'packet_handler__ethernet__rx' / '__tx' path. Provides
    frame builders that mirror the canonical fixture
    topology (STACK + HOST_A unicast, broadcast) and
    delegates the rest to NetworkTestCase.
    """

    @staticmethod
    def _build_ethernet_frame(
        *,
        dst_mac: MacAddress | None = None,
        src_mac: MacAddress | None = None,
        ether_type: EtherType = EtherType.IP4,
        payload: bytes = b"",
    ) -> bytes:
        """
        Build a raw Ethernet II frame: 6-byte dst MAC + 6-byte
        src MAC + 2-byte EtherType + payload. Defaults to
        HOST_A → STACK with EtherType IP4.
        """

        dst = dst_mac if dst_mac is not None else STACK__MAC_ADDRESS
        src = src_mac if src_mac is not None else HOST_A__MAC_ADDRESS
        return bytes(dst) + bytes(src) + int(ether_type).to_bytes(2) + payload

    @staticmethod
    def _build_broadcast_ethernet_frame(
        *,
        src_mac: MacAddress | None = None,
        ether_type: EtherType = EtherType.ARP,
        payload: bytes = b"",
    ) -> bytes:
        """
        Build a broadcast Ethernet II frame (dst MAC =
        FF:FF:FF:FF:FF:FF). Default EtherType is ARP — the
        canonical broadcast traffic on real Ethernet wires.
        """

        return EthernetTestCase._build_ethernet_frame(
            dst_mac=_BROADCAST_MAC,
            src_mac=src_mac,
            ether_type=ether_type,
            payload=payload,
        )

    def _drive_ethernet_rx(self, *, frame: bytes) -> None:
        """
        Drive a raw Ethernet II frame into the
        '_phrx_ethernet' handler. Records any frames the
        stack emits in response on 'self._frames_tx'.
        """

        self._packet_handler._phrx_ethernet(PacketRx(frame))
