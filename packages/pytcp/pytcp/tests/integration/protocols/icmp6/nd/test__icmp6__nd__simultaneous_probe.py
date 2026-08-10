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
Integration tests for the IPv6 Neighbor Discovery simultaneous-probe
DAD-conflict path (RFC 4862 §5.4.3 case (b)). When a peer probes the
same tentative address the host is currently DAD-claiming, the host
MUST treat the inbound NS as a duplicate-address signal and abort
its own DAD claim.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__simultaneous_probe.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
)

# All-nodes solicited-node multicast for the candidate address —
# RFC 4862 §5.4.2 mandates that DAD probes target the candidate's
# solicited-node multicast group.
_CANDIDATE = STACK__IP6_HOST__CANDIDATE.address
_SOLICITED_NODE_MCAST = _CANDIDATE.solicited_node_multicast
_SOLICITED_NODE_MAC = MacAddress("33:33:ff:00:00:05")


class TestIcmp6Rx__NdSimultaneousProbe(NdTestCase):
    """
    A peer's NS for our tentative DAD candidate, with source = ::
    (the DAD wire signal), must be detected as a simultaneous-
    probe conflict.
    """

    @override
    def setUp(self) -> None:
        """
        Install the candidate address as the stack's tentative
        DAD anchor so the simultaneous-probe path's gate can fire.

        Also join the candidate's solicited-node multicast MAC so
        the Ethernet RX gate accepts the inbound DAD probe — this
        is what the real DAD-claim path does before sending its
        own probes (RFC 4862 §5.4 step 2).
        """

        super().setUp()
        self._packet_handler._icmp6_nd_dad__registry.install(_CANDIDATE)
        if _SOLICITED_NODE_MAC not in self._packet_handler._mac_multicast:
            self._packet_handler._mac_multicast.append(_SOLICITED_NODE_MAC)
        if _SOLICITED_NODE_MCAST not in self._packet_handler._ip6_multicast:
            self._packet_handler._ip6_multicast_filters[_SOLICITED_NODE_MCAST] = Ip6MulticastFilter(
                Ip6MulticastFilterMode.EXCLUDE
            )

    def test__icmp6__rx__simultaneous_probe__no_tx(self) -> None:
        """
        Ensure a simultaneous DAD probe from a peer produces no
        TX frames — the host MUST abort its own DAD claim, not
        defend the address.

        Reference: RFC 4862 §5.4.3 case (b) (NS during DAD = duplicate).
        """

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=_SOLICITED_NODE_MAC,
            ip6_src=Ip6Address("::"),
            ip6_dst=_SOLICITED_NODE_MCAST,
            target=_CANDIDATE,
            slla=None,
        )

        self._drive_rx(frame=frame)

        self._assert_no_tx()

    def test__icmp6__rx__simultaneous_probe__packet_stats_rx(self) -> None:
        """
        Ensure the simultaneous-probe NS bumps the generic NS
        counter and the new DAD-conflict counter, and that the
        NS is NOT counted as a regular DAD reply or as a
        target-unknown drop.

        Reference: RFC 4862 §5.4.3 case (b) (NS during DAD = duplicate).
        """

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=_SOLICITED_NODE_MAC,
            ip6_src=Ip6Address("::"),
            ip6_dst=_SOLICITED_NODE_MCAST,
            target=_CANDIDATE,
            slla=None,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_multicast=1,
            ip6__pre_parse=1,
            ip6__dst_multicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_neighbor_solicitation=1,
            icmp6__nd_neighbor_solicitation__dad_conflict=1,
        )

    def test__icmp6__rx__simultaneous_probe__releases_dad_event(self) -> None:
        """
        Ensure the DAD-claim path can pick up the conflict — the
        per-address slot Event is set and the captured peer
        MAC remains None to signal "peer was probing, not
        advertising a final address."

        Reference: RFC 4862 §5.4.3 case (b) (NS during DAD = duplicate).
        """

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=_SOLICITED_NODE_MAC,
            ip6_src=Ip6Address("::"),
            ip6_dst=_SOLICITED_NODE_MCAST,
            target=_CANDIDATE,
            slla=None,
        )

        self._drive_rx(frame=frame)

        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(_CANDIDATE),
            msg="The DAD-conflict path must set the per-address Event.",
        )
        self.assertIsNone(
            self._packet_handler._icmp6_nd_dad__registry.peer_info(_CANDIDATE),
            msg=(
                "The DAD-conflict path must leave the captured peer info "
                "as None — the peer was probing, not advertising."
            ),
        )

    def test__icmp6__rx__simultaneous_probe__dst_must_match_us(self) -> None:
        """
        Ensure an NS for our DAD candidate that arrives at a
        DIFFERENT solicited-node multicast group is NOT treated
        as a simultaneous-probe — the gate must require the
        L3 destination to match the candidate's solicited-node
        group (otherwise off-link spoofers could trip our DAD).

        Note: PyTCP's IPv6 RX gate already drops frames addressed
        to multicast groups we have NOT joined; this test asserts
        that the simultaneous-probe path does NOT bypass that
        gate.

        Reference: RFC 4862 §5.4.2 (DAD probe destination is solicited-node multicast).
        """

        # ff02::1:ff00:99 is HOST_A's solicited-node group, not ours.
        wrong_solicited = Ip6Address("ff02::1:ff00:99")
        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=MacAddress("33:33:ff:00:00:99"),
            ip6_src=Ip6Address("::"),
            ip6_dst=wrong_solicited,
            target=_CANDIDATE,
            slla=None,
        )

        self._drive_rx(frame=frame)

        # The NS-for-not-us never reaches the icmp6 layer because
        # the IPv6-frame multicast filter drops it. Our own DAD
        # state is NOT touched.
        self.assertFalse(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(_CANDIDATE),
            msg=(
                "An NS arriving at a multicast group we do NOT belong to "
                "must NOT signal the DAD event — that would be an off-link "
                "spoof attack vector."
            ),
        )

        # Sanity-check the unused STACK__MAC_ADDRESS import.
        _ = STACK__MAC_ADDRESS
