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
This module contains the 'NdTestCase' base class — a thin extension
to 'IcmpTestCase' carrying ND-specific frame builders for integration
tests of the IPv6 Neighbor Discovery RX path.

Helpers grow on demand as ND phases ship; speculative API surface is
forbidden per CLAUDE.md ("don't design for hypothetical future
requirements"). The first helper to land is
'_make_nd_redirect_frame()' for nd_linux_parity Phase 1B; subsequent
phases will add '_make_nd_ra_frame()', '_make_nd_ns_frame()', etc. as
their tests demand.

pytcp/tests/lib/nd_testcase.py

ver 3.0.9
"""

import threading
from typing import override

from net_addr import Ip6Address, MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp6Assembler,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRedirect,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOption,
    Icmp6NdOptionNonce,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6NdRoutePreference,
    Ip6Assembler,
)
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


class NdTestCase(IcmpTestCase):
    """
    Integration-test base class for IPv6 Neighbor Discovery
    behaviours. Adds 'ND-frame builder' helpers on top of
    'IcmpTestCase' so test cases can construct realistic
    Ethernet/IPv6/ICMPv6 ND frames programmatically rather than
    encoding them as hex literals (the hex-literal pattern in the
    older ICMPv6 RX integration test file is acceptable for
    one-off fixtures but does not scale to ND's per-phase variety
    of NS / NA / RS / RA / Redirect cases).
    """

    @override
    def tearDown(self) -> None:
        """
        Join any DAD daemon thread spawned during the test before the
        harness tears down 'stack'. An address-claim worker
        ('claim_ip6_address_async' -> '_perform_ip6_nd_dad') that
        outlives the fixture would otherwise reach 'stack.timer' after
        teardown removed it and raise from the daemon thread
        (unit_testing.md §10a.3). Joining here lets the worker finish
        against the still-installed 'FakeTimer'.
        """

        for thread in threading.enumerate():
            if thread.name.startswith("DAD-") and thread.is_alive():
                thread.join(timeout=5.0)

        super().tearDown()

    def _make_nd_redirect_frame(
        self,
        *,
        eth_src: MacAddress,
        eth_dst: MacAddress,
        ip6_src: Ip6Address,
        ip6_dst: Ip6Address,
        target: Ip6Address,
        destination: Ip6Address,
        tlla: MacAddress | None = None,
    ) -> bytes:
        """
        Build an Ethernet/IPv6/ICMPv6 Redirect frame for RX
        injection. Defaults the IPv6 hop limit to 255 — the value
        RFC 4861 §8.1 mandates for any inbound Redirect.

        When 'tlla' is supplied, the message carries a Target
        Link-Layer Address option (§4.6.2) — the wire signal that
        triggers the §8.3 neighbour-cache override. Pass
        'tlla=None' for the option-less form.
        """

        options_list: list[Icmp6NdOptionTlla] = []
        if tlla is not None:
            options_list.append(Icmp6NdOptionTlla(tlla=tlla))

        message = Icmp6NdMessageRedirect(
            target_address=target,
            destination_address=destination,
            options=Icmp6NdOptions(*options_list),
        )

        return bytes(
            EthernetAssembler(
                ethernet__src=eth_src,
                ethernet__dst=eth_dst,
                ethernet__payload=Ip6Assembler(
                    ip6__src=ip6_src,
                    ip6__dst=ip6_dst,
                    ip6__hop=255,
                    ip6__payload=Icmp6Assembler(icmp6__message=message),
                ),
            )
        )

    def _make_nd_ns_frame(
        self,
        *,
        eth_src: MacAddress,
        eth_dst: MacAddress,
        ip6_src: Ip6Address,
        ip6_dst: Ip6Address,
        target: Ip6Address,
        slla: MacAddress | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        """
        Build an Ethernet/IPv6/ICMPv6 Neighbor Solicitation frame
        for RX injection. Defaults the IPv6 hop limit to 255 — the
        value RFC 4861 §7.1.1 mandates.

        When 'slla' is supplied, the message carries a Source
        Link-Layer Address option (§4.6.1). For the DAD form
        (RFC 4862 §5.4.2) callers pass 'ip6_src=Ip6Address("::")'
        and 'slla=None' — RFC 4861 §7.2.2 forbids the SLLA option
        on a DAD probe.

        When 'nonce' is supplied, the message carries a Nonce
        option (RFC 7527 §4.1 Enhanced DAD); pass a 6-byte
        bytes value.
        """

        options_list: list[Icmp6NdOption] = []
        if slla is not None:
            options_list.append(Icmp6NdOptionSlla(slla=slla))
        if nonce is not None:
            options_list.append(Icmp6NdOptionNonce(nonce=nonce))

        message = Icmp6NdMessageNeighborSolicitation(
            target_address=target,
            options=Icmp6NdOptions(*options_list),
        )

        return bytes(
            EthernetAssembler(
                ethernet__src=eth_src,
                ethernet__dst=eth_dst,
                ethernet__payload=Ip6Assembler(
                    ip6__src=ip6_src,
                    ip6__dst=ip6_dst,
                    ip6__hop=255,
                    ip6__payload=Icmp6Assembler(icmp6__message=message),
                ),
            )
        )

    def _make_nd_ra_frame(
        self,
        *,
        eth_src: MacAddress,
        eth_dst: MacAddress,
        ip6_src: Ip6Address,
        ip6_dst: Ip6Address,
        router_lifetime: int,
        hop: int = 0,
        flag_m: bool = False,
        flag_o: bool = False,
        prf: Icmp6NdRoutePreference = Icmp6NdRoutePreference.MEDIUM,
        reachable_time: int = 0,
        retrans_timer: int = 0,
        options: list[Icmp6NdOption] | None = None,
    ) -> bytes:
        """
        Build an Ethernet/IPv6/ICMPv6 Router Advertisement frame
        for RX injection. Defaults the IPv6 hop limit to 255 — the
        value RFC 4861 §6.1.2 mandates for any inbound RA. The RA
        source ('ip6_src') must be link-local per the same clause;
        callers pick a 'fe80::*' address.

        Pass 'router_lifetime=0' for the "no longer a default
        router" form per RFC 4861 §6.3.4. 'prf' defaults to
        MEDIUM per RFC 4191 §2.2 (the wire encoding 00). The
        'options' kwarg defaults to an empty list — callers add
        Prefix-Information, SLLA, MTU, RDNSS etc. as their tests
        need.
        """

        message = Icmp6NdMessageRouterAdvertisement(
            hop=hop,
            flag_m=flag_m,
            flag_o=flag_o,
            prf=prf,
            router_lifetime=router_lifetime,
            reachable_time=reachable_time,
            retrans_timer=retrans_timer,
            options=Icmp6NdOptions(*(options or [])),
        )

        return bytes(
            EthernetAssembler(
                ethernet__src=eth_src,
                ethernet__dst=eth_dst,
                ethernet__payload=Ip6Assembler(
                    ip6__src=ip6_src,
                    ip6__dst=ip6_dst,
                    ip6__hop=255,
                    ip6__payload=Icmp6Assembler(icmp6__message=message),
                ),
            )
        )
