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
Integration tests for the RA Managed (M) / Other-config (O) flag
DHCPv6-client trigger. An inbound Router Advertisement with M=1
requests stateful DHCPv6 address configuration and O=1 requests
stateless other configuration (RFC 8415 §4 / RFC 4861 §4.2); the RA
RX handler hands the flags to the per-interface DHCPv6 client (when
installed) via 'trigger', and the client's worker debounces.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_dhcp6_trigger.py

ver 3.0.9
"""

from unittest.mock import create_autospec

from net_addr import Ip6Address, MacAddress
from pytcp.protocols.dhcp6.dhcp6__client import Dhcp6Client
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")


class TestIcmp6Nd__RaDhcp6Trigger(NdTestCase):
    """
    The RA Managed/Other-flag DHCPv6-client trigger tests.
    """

    def _drive_ra(self, *, flag_m: bool, flag_o: bool) -> None:
        """
        Drive an inbound RA carrying the given Managed / Other-config
        flags into the stack.
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                flag_m=flag_m,
                flag_o=flag_o,
            ),
        )

    def test__icmp6__nd__ra_managed_flag_triggers_stateful(self) -> None:
        """
        Ensure an RA with the Managed flag triggers the DHCPv6 client for
        stateful (managed) configuration.

        Reference: RFC 8415 §4 (Managed flag requests stateful configuration).
        """

        client = create_autospec(Dhcp6Client, spec_set=True)
        self._packet_handler._dhcp6_client = client

        self._drive_ra(flag_m=True, flag_o=False)

        client.trigger.assert_called_once_with(managed=True, other=False)

    def test__icmp6__nd__ra_other_flag_triggers_stateless(self) -> None:
        """
        Ensure an RA with the Other-config flag triggers the DHCPv6 client
        for stateless (other) configuration.

        Reference: RFC 8415 §4 (Other-config flag requests stateless configuration).
        """

        client = create_autospec(Dhcp6Client, spec_set=True)
        self._packet_handler._dhcp6_client = client

        self._drive_ra(flag_m=False, flag_o=True)

        client.trigger.assert_called_once_with(managed=False, other=True)

    def test__icmp6__nd__ra_both_flags_trigger(self) -> None:
        """
        Ensure an RA with both flags triggers the DHCPv6 client with both
        set.

        Reference: RFC 8415 §4 (Managed and Other-config flags).
        """

        client = create_autospec(Dhcp6Client, spec_set=True)
        self._packet_handler._dhcp6_client = client

        self._drive_ra(flag_m=True, flag_o=True)

        client.trigger.assert_called_once_with(managed=True, other=True)

    def test__icmp6__nd__ra_no_flags_does_not_trigger(self) -> None:
        """
        Ensure an RA with neither flag set does not trigger the DHCPv6
        client.

        Reference: RFC 4861 §4.2 (M/O flags clear -> no DHCPv6).
        """

        client = create_autospec(Dhcp6Client, spec_set=True)
        self._packet_handler._dhcp6_client = client

        self._drive_ra(flag_m=False, flag_o=False)

        client.trigger.assert_not_called()

    def test__icmp6__nd__ra_managed_flag_without_client_is_noop(self) -> None:
        """
        Ensure an RA with the Managed flag is processed without error when no
        DHCPv6 client is installed on the interface.

        Reference: RFC 4861 §6.3.4 (RA processing independent of DHCPv6).
        """

        self._packet_handler._dhcp6_client = None

        self._drive_ra(flag_m=True, flag_o=True)

        # The RA is still processed normally — the default router is learned.
        self.assertTrue(
            any(entry.address == ROUTER__LINK_LOCAL for entry in self._packet_handler._icmp6_default_routers),
            msg="The RA must be processed even when no DHCPv6 client is installed.",
        )
