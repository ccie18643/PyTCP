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
This module contains integration tests for the outbound ARP
sender-protocol-address selection honouring the per-interface
'arp.announce' sysctl (Linux net.ipv4.conf.<iface>.arp_announce).

On a multi-homed interface, mode 0 (the Linux default) sources an
outbound ARP Request from the first listed local IPv4 address
regardless of the target subnet, while modes 1 and 2 prefer a
local IPv4 whose subnet contains the target (falling back to the
first when none matches). These tests drive 'send_arp_request' to
a target on the SECOND configured subnet and assert the emitted
frame's SPA, pinning the 'arp.announce in (1, 2)' gate and the
subnet-match loop that the broader ARP suite (single-subnet
topology) does not exercise.

packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__tx__announce_selection.py

ver 3.0.9
"""

from typing import override

from net_addr import Ip4Address, Ip4IfAddr
from net_proto import ArpOperation
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.arp_testcase import (
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)

# Two local subnets on the one test interface: the first listed
# (10.0.1.7) is the mode-0 default source; the second (10.0.2.7)
# is the subnet-match source for a target in 10.0.2.0/24.
_IFADDR_SUBNET_1 = Ip4IfAddr("10.0.1.7/24")
_IFADDR_SUBNET_2 = Ip4IfAddr("10.0.2.7/24")
_TARGET_ON_SUBNET_2 = Ip4Address("10.0.2.50")


class TestArpTxAnnounceSelection(ArpTestCase):
    """
    The outbound ARP 'arp.announce' SPA-selection tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and configure the interface with two
        local IPv4 subnets so the SPA-selection modes diverge.
        """

        super().setUp()
        self._packet_handler._ip4_ifaddr = [_IFADDR_SUBNET_1, _IFADDR_SUBNET_2]

    def _expected_request(self, *, arp_spa: Ip4Address) -> bytes:
        """
        Build the broadcast ARP Request frame the handler emits
        for '_TARGET_ON_SUBNET_2' with the given source address.
        """

        return ArpTestCase._build_arp_frame(
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=STACK__MAC_ADDRESS,
            arp_oper=ArpOperation.REQUEST,
            arp_sha=STACK__MAC_ADDRESS,
            arp_spa=arp_spa,
            arp_tha=MAC__UNSPECIFIED,
            arp_tpa=_TARGET_ON_SUBNET_2,
        )

    def test__arp__tx__announce_mode0_sources_from_first_subnet(self) -> None:
        """
        Ensure that with the default 'arp.announce = 0' an outbound
        ARP Request to a target on the second subnet is sourced from
        the FIRST listed local IPv4 address, not the subnet-matching
        one — the mode-0 path must skip the subnet-match loop.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 0 default).
        """

        before = len(self._frames_tx)
        self._packet_handler.send_arp_request(arp__tpa=_TARGET_ON_SUBNET_2)

        self.assertEqual(
            self._frames_tx[before:],
            [self._expected_request(arp_spa=_IFADDR_SUBNET_1.address)],
            msg=(
                "With arp.announce=0 the outbound ARP Request must be sourced "
                "from the first listed local IPv4 (10.0.1.7), not the "
                "subnet-matching address."
            ),
        )

    def test__arp__tx__announce_mode1_sources_from_matching_subnet(self) -> None:
        """
        Ensure that with 'arp.announce = 1' an outbound ARP Request to
        a target on the second subnet is sourced from the local IPv4
        whose subnet CONTAINS the target (10.0.2.7), pinning the
        subnet-match loop and the 'arp.announce in (1, 2)' gate.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 1 subnet-match).
        """

        sysctl_module.set("arp.default.announce", 1)
        try:
            before = len(self._frames_tx)
            self._packet_handler.send_arp_request(arp__tpa=_TARGET_ON_SUBNET_2)

            self.assertEqual(
                self._frames_tx[before:],
                [self._expected_request(arp_spa=_IFADDR_SUBNET_2.address)],
                msg=(
                    "With arp.announce=1 the outbound ARP Request must be sourced "
                    "from the local IPv4 whose subnet contains the target "
                    "(10.0.2.7), not the first listed address."
                ),
            )
        finally:
            sysctl_module.reset_to_defaults()
