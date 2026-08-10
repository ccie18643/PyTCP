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
Integration tests for the consumer side of the RA host-parameter
mirror — nd_linux_parity §13b. The §13a wire-state pin captured
Cur-Hop-Limit, Reachable Time, and Retrans Timer into
'Icmp6RaParameters'; this file pins the three consumer wirings:

    Cur-Hop-Limit   → IPv6 TX default hop limit (TCP/UDP traffic).
    Reachable Time  → NUD REACHABLE-state timeout (NdCache only).
    Retrans Timer   → DAD probe inter-spacing (overrides sysctl).

Each consumer falls back to its existing operator-configured
default (sysctl or hardcoded constant) when the host has not yet
observed an RA carrying the corresponding non-zero value.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_parameter_consumers.py

ver 3.0.9
"""

import threading
from typing import Any, cast, override
from unittest.mock import patch

from net_addr import Ip6Address, MacAddress
from net_proto import Ip6Parser, RawAssembler
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")


class TestIcmp6Nd__RaConsumer__TxHopLimit(NdTestCase):
    """
    'Cur-Hop-Limit' from RA becomes the default IPv6 TX hop
    limit for non-protocol-mandated outbound traffic. ND
    messages keep their RFC-mandated 255 (those callers pass
    'ip6__hop=255' explicitly).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__cur_hop_limit_consumed_by_tx(self) -> None:
        """
        Ensure an RA-advertised Cur-Hop-Limit becomes the
        effective default for an outbound IPv6 packet whose
        caller did not specify 'ip6__hop' explicitly.

        Reference: RFC 4861 §6.3.4 (Cur-Hop-Limit replaces host default).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=80,
            ),
        )
        # Drain the RA-driven gratuitous-NA (or similar) TX side
        # effects so the next assertion reads our test frame.
        self._frames_tx.clear()

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6_ADDRESS,
            ip6__payload=RawAssembler(),
        )

        # Decode the resulting IPv6 frame and assert hop == 80.
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"Expected exactly one TX frame. Got: {self._frames_tx!r}",
        )
        prx = PacketRx(self._frames_tx[0])
        EthernetParser(prx)
        Ip6Parser(prx)
        self.assertEqual(
            prx.ip6.hop,
            80,
            msg=("TX frame must carry the RA-advertised Cur-Hop-Limit " f"as its hop value. Got: hop={prx.ip6.hop}"),
        )

    def test__icmp6__nd__tx__without_ra_uses_default_hop_limit(self) -> None:
        """
        Ensure the IPv6 TX default falls back to
        'IP6__DEFAULT_HOP_LIMIT' (64) when no RA has carried
        a non-zero Cur-Hop-Limit.

        Reference: RFC 8200 §3 (IPv6 default hop limit).
        """

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6_ADDRESS,
            ip6__payload=RawAssembler(),
        )

        prx = PacketRx(self._frames_tx[-1])
        EthernetParser(prx)
        Ip6Parser(prx)
        self.assertEqual(
            prx.ip6.hop,
            64,
            msg=f"Default IPv6 hop must be 64 absent RA. Got: {prx.ip6.hop}",
        )

    def test__icmp6__nd__tx__explicit_hop_overrides_ra_default(self) -> None:
        """
        Ensure an explicit 'ip6__hop' kwarg on a TX call wins
        over the RA-advertised default — protocol-mandated
        callers (ND with 255, MLD with 1) keep their values.

        Reference: RFC 4861 §11.2 (Hop Limit on ND messages).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=80,
            ),
        )
        self._frames_tx.clear()

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6_ADDRESS,
            ip6__hop=255,
            ip6__payload=RawAssembler(),
        )

        prx = PacketRx(self._frames_tx[-1])
        EthernetParser(prx)
        Ip6Parser(prx)
        self.assertEqual(
            prx.ip6.hop,
            255,
            msg=("Explicit ip6__hop must win over RA Cur-Hop-Limit. " f"Got: {prx.ip6.hop}"),
        )


class TestIcmp6Nd__RaConsumer__DadRetransTimer(NdTestCase):
    """
    'Retrans Timer' from RA becomes the inter-probe wait used
    by the DAD loop, overriding the operator-configured
    'icmp6.retrans_timer_ms' sysctl default.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__retrans_timer_consumed_by_dad(self) -> None:
        """
        Ensure a non-zero RA-advertised Retrans-Timer overrides
        the 'icmp6.retrans_timer_ms' sysctl when the DAD loop
        computes its inter-probe wait.

        Reference: RFC 4861 §6.3.4 (Retrans Timer replaces host default).
        Reference: RFC 4862 §5.1 (DAD probe spacing).
        """

        # Drive an RA that advertises 250ms retrans_timer.
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                retrans_timer=250,
            ),
        )

        # Set the sysctl to a much larger value so we can prove
        # the override is what won. Patch threading.Event.wait
        # at the class level — the per-address Event is created
        # inside '_perform_ip6_nd_dad' so we cannot patch a
        # specific instance before the call.
        with sysctl_module.override("icmp6.default.retrans_timer_ms", 60000):
            with patch.object(
                threading.Event,
                "wait",
                return_value=False,
            ) as mock_wait:
                self._packet_handler._perform_ip6_nd_dad(
                    ip6_unicast_candidate=Ip6Address("2001:db8:0:1::42"),
                )

        timeout = mock_wait.call_args.kwargs.get("timeout")
        self.assertAlmostEqual(
            cast(float, timeout),
            0.250,
            places=4,
            msg=(
                "DAD inter-probe wait must use the RA-advertised "
                f"retrans_timer (250ms / 0.25s). Got: timeout={timeout!r}"
            ),
        )


class TestIcmp6Nd__RaConsumer__NudReachableTime(NdTestCase):
    """
    'Reachable Time' from RA pushes a per-cache override into
    the IPv6 NeighborCache (NdCache only — IPv4 ARP cache stays
    on its sysctl default).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__reachable_time_pushes_to_nd_cache(self) -> None:
        """
        Ensure an RA-advertised Reachable-Time (in ms) is
        forwarded to 'NdCache.set_reachable_time_override_ms';
        the IPv4 ARP cache is not invoked.

        Reference: RFC 4861 §6.3.4 (Reachable Time replaces host default).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                reachable_time=45000,
            ),
        )

        # 'self._nd_cache' is autospec'd — we assert against the
        # call record, not against the attribute itself (autospec
        # methods are mock callables, not real implementations).
        nd_cache_mock = cast(Any, self._nd_cache)
        nd_cache_mock.set_reachable_time_override_ms.assert_called_once_with(45000)
        arp_cache_mock = cast(Any, self._arp_cache)
        self.assertEqual(
            arp_cache_mock.set_reachable_time_override_ms.call_count,
            0,
            msg=(
                "RA-driven NUD override must not invoke ArpCache. "
                f"Got call_count={arp_cache_mock.set_reachable_time_override_ms.call_count}"
            ),
        )
