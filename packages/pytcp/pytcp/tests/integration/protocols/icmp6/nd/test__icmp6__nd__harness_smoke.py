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
Smoke tests for the 'NdTestCase' integration-test harness. Pins the
ND-specific frame builders '_make_nd_redirect_frame',
'_make_nd_ns_frame', and '_make_nd_ra_frame' — each round-trips
through the production Ethernet → IPv6 → ICMPv6 parser chain — so
the migrated ND tests under 'protocols/icmp6/nd/' can rely on the
builders' wire shape, option-bearing variants, and the RFC-mandated
hop=255 default.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__harness_smoke.py

ver 3.0.8
"""

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import (
    EthernetParser,
    EtherType,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRedirect,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptionNonce,
    Icmp6NdOptionPi,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6NdRoutePreference,
    Icmp6Parser,
    Ip6Parser,
    IpProto,
    PacketRx,
)
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

# Link-local source used by RA cases — RFC 4861 §6.1.2 mandates an
# RA source be a link-local address.
_ROUTER__LL_IP6_ADDRESS = Ip6Address("fe80::1")
_ROUTER__MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

# All-nodes IPv6 multicast address for RAs.
_IP6__ALL_NODES = Ip6Address("ff02::1")
# All-nodes Ethernet multicast MAC (33:33:00:00:00:01).
_ETH__ALL_NODES = MacAddress(0x333300000001)


def _parse_to_icmp6(frame: bytes) -> Icmp6Parser:
    """
    Walk a frame produced by the NdTestCase builders through the
    production Ethernet → IPv6 → ICMPv6 parser chain and return
    the ICMPv6 parser instance.
    """

    packet_rx = PacketRx(frame)
    EthernetParser(packet_rx)
    if packet_rx.ethernet.type is not EtherType.IP6:
        raise AssertionError(f"Expected IPv6 EtherType, got {packet_rx.ethernet.type!r}.")
    Ip6Parser(packet_rx)
    if packet_rx.ip6.next is not IpProto.ICMP6:
        raise AssertionError(f"Expected ICMP6 next-header, got {packet_rx.ip6.next!r}.")
    Icmp6Parser(packet_rx)
    return packet_rx.icmp6


class TestNdHarnessSmoke(NdTestCase):
    """
    Smoke tests for 'NdTestCase'.
    """

    def test__nd__harness__make_redirect_frame_round_trips(self) -> None:
        """
        Ensure '_make_nd_redirect_frame' (option-less form) emits a
        frame whose Ethernet, IPv6 and ICMPv6 layers all parse and
        whose ICMPv6 message is an Icmp6NdMessageRedirect carrying
        the supplied target / destination addresses.

        Reference: RFC 4861 §8 (Redirect message format).
        """

        target_addr = Ip6Address("2001:db8:0:1::42")
        dest_addr = Ip6Address("2001:db8:0:2::99")

        frame = self._make_nd_redirect_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=STACK__IP6_HOST.address,
            target=target_addr,
            destination=dest_addr,
        )

        icmp6 = _parse_to_icmp6(frame)
        self.assertIsInstance(
            icmp6.message,
            Icmp6NdMessageRedirect,
            msg="Redirect frame must decode into Icmp6NdMessageRedirect.",
        )
        assert isinstance(icmp6.message, Icmp6NdMessageRedirect)
        self.assertEqual(
            icmp6.message.target_address,
            target_addr,
            msg="Redirect target_address must round-trip through the assembler.",
        )
        self.assertEqual(
            icmp6.message.destination_address,
            dest_addr,
            msg="Redirect destination_address must round-trip through the assembler.",
        )

    def test__nd__harness__make_redirect_frame_defaults_hop_to_255(self) -> None:
        """
        Ensure '_make_nd_redirect_frame' sets the IPv6 hop limit
        to the mandated 255 so the receiver does not drop the
        inbound Redirect.

        Reference: RFC 4861 §8.1 (Receiver MUST drop Redirect with hop_limit != 255).
        """

        frame = self._make_nd_redirect_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=STACK__IP6_HOST.address,
            target=Ip6Address("2001:db8:0:1::42"),
            destination=Ip6Address("2001:db8:0:2::99"),
        )

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip6Parser(packet_rx)

        self.assertEqual(
            packet_rx.ip6.hop,
            255,
            msg="Redirect frame must default IPv6 hop limit to 255 per RFC 4861 §8.1.",
        )

    def test__nd__harness__make_redirect_frame_carries_tlla_when_supplied(self) -> None:
        """
        Ensure '_make_nd_redirect_frame' with 'tlla=...' includes a
        Target Link-Layer Address option in the wire frame.

        Reference: RFC 4861 §4.6.2 (Target Link-Layer Address option).
        """

        frame = self._make_nd_redirect_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=STACK__IP6_HOST.address,
            target=Ip6Address("2001:db8:0:1::42"),
            destination=Ip6Address("2001:db8:0:2::99"),
            tlla=HOST_A__MAC_ADDRESS,
        )

        icmp6 = _parse_to_icmp6(frame)
        assert isinstance(icmp6.message, Icmp6NdMessageRedirect)

        tlla_options = [opt for opt in icmp6.message.options if isinstance(opt, Icmp6NdOptionTlla)]
        self.assertEqual(
            len(tlla_options),
            1,
            msg="Redirect with 'tlla' kwarg must include exactly one TLLA option.",
        )
        self.assertEqual(
            tlla_options[0].tlla,
            HOST_A__MAC_ADDRESS,
            msg="TLLA option value must round-trip through the assembler.",
        )

    def test__nd__harness__make_ns_frame_round_trips(self) -> None:
        """
        Ensure '_make_nd_ns_frame' (option-less form) emits a frame
        that decodes into Icmp6NdMessageNeighborSolicitation with
        the supplied target_address.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation message format).
        """

        # NS sanity requires ip6_dst to match either the target
        # or its solicited-node multicast (RFC 4861 §7.1.1). The
        # simplest legal shape is dst == target.
        target_addr = STACK__IP6_HOST.address

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=HOST_A__IP6_ADDRESS,
            ip6_dst=target_addr,
            target=target_addr,
        )

        icmp6 = _parse_to_icmp6(frame)
        self.assertIsInstance(
            icmp6.message,
            Icmp6NdMessageNeighborSolicitation,
            msg="NS frame must decode into Icmp6NdMessageNeighborSolicitation.",
        )
        assert isinstance(icmp6.message, Icmp6NdMessageNeighborSolicitation)
        self.assertEqual(
            icmp6.message.target_address,
            target_addr,
            msg="NS target_address must round-trip through the assembler.",
        )

    def test__nd__harness__make_ns_frame_defaults_hop_to_255(self) -> None:
        """
        Ensure '_make_nd_ns_frame' sets the IPv6 hop limit to
        the mandated 255 so the receiver does not drop the
        inbound Neighbor Solicitation.

        Reference: RFC 4861 §7.1.1 (Receiver MUST drop NS with hop_limit != 255).
        """

        # dst == target so the NS sanity check (RFC 4861 §7.1.1)
        # accepts the frame; this test only needs the IPv6 header
        # to be inspectable.
        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=HOST_A__IP6_ADDRESS,
            ip6_dst=STACK__IP6_HOST.address,
            target=STACK__IP6_HOST.address,
        )

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip6Parser(packet_rx)

        self.assertEqual(
            packet_rx.ip6.hop,
            255,
            msg="NS frame must default IPv6 hop limit to 255 per RFC 4861 §7.1.1.",
        )

    def test__nd__harness__make_ns_frame_carries_slla_when_supplied(self) -> None:
        """
        Ensure '_make_nd_ns_frame' with 'slla=...' includes a
        Source Link-Layer Address option carrying the supplied
        MAC.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=HOST_A__IP6_ADDRESS,
            ip6_dst=STACK__IP6_HOST.address,
            target=STACK__IP6_HOST.address,
            slla=HOST_A__MAC_ADDRESS,
        )

        icmp6 = _parse_to_icmp6(frame)
        assert isinstance(icmp6.message, Icmp6NdMessageNeighborSolicitation)

        slla_options = [opt for opt in icmp6.message.options if isinstance(opt, Icmp6NdOptionSlla)]
        self.assertEqual(
            len(slla_options),
            1,
            msg="NS with 'slla' kwarg must include exactly one SLLA option.",
        )
        self.assertEqual(
            slla_options[0].slla,
            HOST_A__MAC_ADDRESS,
            msg="SLLA option value must round-trip through the assembler.",
        )

    def test__nd__harness__make_ns_frame_carries_nonce_when_supplied(self) -> None:
        """
        Ensure '_make_nd_ns_frame' with 'nonce=...' includes a
        Nonce option carrying the supplied 6-byte value (RFC 7527
        Enhanced DAD).

        Reference: RFC 7527 §4.1 (Nonce option for Enhanced DAD).
        """

        nonce = b"\x01\x02\x03\x04\x05\x06"

        # DAD probe form (RFC 4862 §5.4.2): ip6_src unspecified,
        # dst is the solicited-node multicast of the target
        # (RFC 4861 §7.2.1).
        target_addr = STACK__IP6_HOST.address
        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=Ip6Address("::"),
            ip6_dst=target_addr.solicited_node_multicast,
            target=target_addr,
            nonce=nonce,
        )

        icmp6 = _parse_to_icmp6(frame)
        assert isinstance(icmp6.message, Icmp6NdMessageNeighborSolicitation)

        nonce_options = [opt for opt in icmp6.message.options if isinstance(opt, Icmp6NdOptionNonce)]
        self.assertEqual(
            len(nonce_options),
            1,
            msg="NS with 'nonce' kwarg must include exactly one Nonce option.",
        )
        self.assertEqual(
            bytes(nonce_options[0].nonce),
            nonce,
            msg="Nonce option value must round-trip through the assembler verbatim.",
        )

    def test__nd__harness__make_ra_frame_round_trips(self) -> None:
        """
        Ensure '_make_nd_ra_frame' emits a frame that decodes into
        Icmp6NdMessageRouterAdvertisement carrying the supplied
        router_lifetime and the default MEDIUM route preference.

        Reference: RFC 4861 §4.2 (Router Advertisement message format).
        Reference: RFC 4191 §2.2 (Route preference encoding, MEDIUM = 0b00).
        """

        frame = self._make_nd_ra_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=_ETH__ALL_NODES,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=_IP6__ALL_NODES,
            router_lifetime=1800,
        )

        icmp6 = _parse_to_icmp6(frame)
        self.assertIsInstance(
            icmp6.message,
            Icmp6NdMessageRouterAdvertisement,
            msg="RA frame must decode into Icmp6NdMessageRouterAdvertisement.",
        )
        assert isinstance(icmp6.message, Icmp6NdMessageRouterAdvertisement)
        self.assertEqual(
            icmp6.message.router_lifetime,
            1800,
            msg="RA router_lifetime must round-trip through the assembler.",
        )
        self.assertIs(
            icmp6.message.prf,
            Icmp6NdRoutePreference.MEDIUM,
            msg="Default RA prf must be MEDIUM per RFC 4191 §2.2 wire encoding 00.",
        )

    def test__nd__harness__make_ra_frame_defaults_hop_to_255(self) -> None:
        """
        Ensure '_make_nd_ra_frame' sets the IPv6 hop limit to
        the mandated 255 so the receiver does not drop the
        inbound Router Advertisement.

        Reference: RFC 4861 §6.1.2 (Receiver MUST drop RA with hop_limit != 255).
        """

        frame = self._make_nd_ra_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=_ETH__ALL_NODES,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=_IP6__ALL_NODES,
            router_lifetime=1800,
        )

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip6Parser(packet_rx)

        self.assertEqual(
            packet_rx.ip6.hop,
            255,
            msg="RA frame must default IPv6 hop limit to 255 per RFC 4861 §6.1.2.",
        )

    def test__nd__harness__make_ra_frame_carries_options_list(self) -> None:
        """
        Ensure '_make_nd_ra_frame' with an explicit 'options=[...]'
        list propagates each option through to the wire frame.
        Pins the harness contract that future RA tests can append
        PI / SLLA / MTU / RDNSS options as their tests demand.

        Reference: RFC 4861 §4.6 (RA options); §4.6.2 (PI option).
        """

        prefix = Ip6Network("2001:db8:abcd::/64")
        pi_option = Icmp6NdOptionPi(
            flag_l=True,
            flag_a=True,
            valid_lifetime=86400,
            preferred_lifetime=14400,
            prefix=prefix,
        )

        frame = self._make_nd_ra_frame(
            eth_src=_ROUTER__MAC_ADDRESS,
            eth_dst=_ETH__ALL_NODES,
            ip6_src=_ROUTER__LL_IP6_ADDRESS,
            ip6_dst=_IP6__ALL_NODES,
            router_lifetime=1800,
            options=[pi_option],
        )

        icmp6 = _parse_to_icmp6(frame)
        assert isinstance(icmp6.message, Icmp6NdMessageRouterAdvertisement)

        pi_options = [opt for opt in icmp6.message.options if isinstance(opt, Icmp6NdOptionPi)]
        self.assertEqual(
            len(pi_options),
            1,
            msg="RA with one PI in 'options=' must carry exactly one PI in the wire frame.",
        )
        self.assertEqual(
            pi_options[0].prefix,
            prefix,
            msg="PI prefix must round-trip through the assembler.",
        )

    def test__nd__harness__inherits_icmp_test_case_surface(self) -> None:
        """
        Ensure NdTestCase inherits the 'IcmpTestCase' surface — the
        '_drive_rx', '_parse_tx_icmp6', and 'FakeTimer' helpers stay
        available on the subclass so migrated ND tests can compose
        ND frame builders with the ICMPv6 probe + clock controls.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Both attributes / methods come from IcmpTestCase; this
        # smoke pins that NdTestCase does not shadow or break them.
        self.assertTrue(
            hasattr(self, "_drive_rx"),
            msg="NdTestCase must inherit IcmpTestCase._drive_rx.",
        )
        self.assertTrue(
            hasattr(self, "_parse_tx_icmp6"),
            msg="NdTestCase must inherit IcmpTestCase._parse_tx_icmp6.",
        )
        self.assertTrue(
            hasattr(self, "_advance"),
            msg="NdTestCase must inherit IcmpTestCase._advance (FakeTimer).",
        )

    def test__nd__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'NdTestCase.setUp' does not perturb the addresses,
        MAC, or host state inherited transitively from
        'NetworkTestCase' via 'IcmpTestCase'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._mac_unicast,
            STACK__MAC_ADDRESS,
            msg="Inherited stack MAC must be unchanged.",
        )
        addresses = {host.address for host in self._packet_handler._ip6_ifaddr}
        self.assertIn(
            STACK__IP6_HOST.address,
            addresses,
            msg="Inherited stack IPv6 host must be present in '_ip6_ifaddr'.",
        )
