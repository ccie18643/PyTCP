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
This module contains unit tests for the 'Icmp6RxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp6__rx.py

ver 3.0.8
"""

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, cast
from unittest import TestCase
from unittest.mock import create_autospec, patch

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptionPi,
    Icmp6NdOptions,
    Ip6Assembler,
    Ip6Parser,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.packet_handler.packet_handler__icmp6__rx import Icmp6RxHandler

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP6_ADDRESS = Ip6Address("2001:db8:0:1::7")
STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the RX-stat counters, the DAD/RA link-layer state, and the
    cross-protocol TX / state-mutator entry points the ICMPv6 RX
    sub-handler reaches through 'self._if', recording each TX call. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._interface_name: str | None = None
        self._icmp6_nd_dad__registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()
        self._icmp6_ra__event = threading.Semaphore(0)
        self._icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self._nd_cache: NdCache | None = None
        # The RA RX handler consults '_dhcp6_client' to trigger the
        # DHCPv6 client on the RA Managed/Other flags; the stub has none.
        self._dhcp6_client = None

        self.icmp6_tx_calls: list[dict[str, object]] = []

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        return [STACK__IP6_ADDRESS]

    def _phtx_icmp6(self, **kwargs: object) -> TxStatus:
        self.icmp6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    # Stub the cross-mixin TX helper that the NS RX handler now
    # delegates to (post-§5 refactor). Records the call into the
    # same 'icmp6_tx_calls' list used by '_phtx_icmp6' so existing
    # assertions on TX dispatch continue to work.
    def send_icmp6_neighbor_advertisement(self, **kwargs: object) -> None:
        self.icmp6_tx_calls.append(kwargs)

    # Stub the default-router-list mutator added with the §11
    # parity work. The test base only exercises the prefix
    # harvest path; the default-router list is covered by the
    # integration tests in
    # 'pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__default_router_list.py'.
    def _update_icmp6_default_router(self, **kwargs: object) -> None:
        self.icmp6_tx_calls.append({"_update_icmp6_default_router": kwargs})

    # Stub the SLAAC prefix-table mutator added with the §12a
    # parity work. Same rationale as above — covered by
    # 'pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_address_tracking.py'.
    def _update_icmp6_slaac_address(self, **kwargs: object) -> None:
        self.icmp6_tx_calls.append({"_update_icmp6_slaac_address": kwargs})

    # Stub the temporary-address mutator added with the §18b
    # RFC 8981 wiring. Records the call into the same
    # 'icmp6_tx_calls' list so existing assertions on TX
    # dispatch continue to work.
    def _update_icmp6_temp_address(self, **kwargs: object) -> None:
        self.icmp6_tx_calls.append({"_update_icmp6_temp_address": kwargs})

    # Stub the RA-header parameter-mirror mutator added with the
    # §13 parity work. Covered by integration tests in
    # 'pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_parameters.py'.
    def _update_icmp6_ra_parameters(self, **kwargs: object) -> None:
        self.icmp6_tx_calls.append({"_update_icmp6_ra_parameters": kwargs})


def _packet_rx_from_ip6_icmp6(ip6_frame: bytes) -> PacketRx:
    """
    Build a 'PacketRx' parsed through 'Ip6Parser' so that the frame
    pointer is positioned at the ICMPv6 header.
    """

    packet_rx = PacketRx(ip6_frame)
    Ip6Parser(packet_rx)
    return packet_rx


def _build_icmp6_frame(
    *,
    src: Ip6Address,
    dst: Ip6Address,
    message: object,
    hop: int = 255,
) -> bytes:
    """
    Build an IPv6+ICMPv6 wire frame carrying 'message'. Defaults the
    IPv6 hop limit to 255, which is required by RFC 4861 for ND
    messages; caller can override for non-ND packets.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__hop=hop,
            ip6__payload=Icmp6Assembler(icmp6__message=message),  # type: ignore[arg-type]
        )
    )


class _Icmp6RxTestBase(TestCase):
    """
    Common setUp for the ICMPv6 RX tests.
    """

    def setUp(self) -> None:
        self._if = _StubInterface()
        self._icmp6_rx = Icmp6RxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()
        # The ND cache is now injected per-interface; assign the mock
        # to the handler's own '_nd_cache' rather than patching the
        # global 'stack.nd_cache' (which the RX path no longer reads).
        self._nd_cache = create_autospec(NdCache, spec_set=True)
        self._if._nd_cache = self._nd_cache

    def tearDown(self) -> None:
        self._sockets_patch.stop()


class TestPacketHandlerIcmp6RxParse(_Icmp6RxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__icmp6__rx__parse_fail_drops(self) -> None:
        """
        Ensure a malformed ICMPv6 frame is counted in
        'icmp6__failed_parse__drop'.

        Reference: RFC 4443 (ICMPv6 message processing).
        """

        ip6 = bytearray(
            _build_icmp6_frame(
                src=HOST_A__IP6,
                dst=STACK__IP6_ADDRESS,
                message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
            )
        )
        # Corrupt the ICMPv6 checksum (bytes 42-43 = IPv6 40-byte header + 2).
        ip6[42] = 0xDE
        ip6[43] = 0xAD

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(bytes(ip6)))

        self.assertEqual(
            self._if._packet_stats_rx.icmp6__pre_parse,
            1,
            msg="icmp6__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__failed_parse__drop,
            1,
            msg="Malformed ICMPv6 must be counted in icmp6__failed_parse__drop.",
        )


class TestPacketHandlerIcmp6RxEcho(_Icmp6RxTestBase):
    """
    The ICMPv6 Echo Request/Reply dispatch tests.
    """

    def test__stack__packet_handler__icmp6__rx__echo_request_triggers_reply(self) -> None:
        """
        Ensure an ICMPv6 Echo Request produces an Echo Reply with
        src=our-dst and dst=peer.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=Icmp6MessageEchoRequest(id=42, seq=7, data=b"hello"),
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            self._if._packet_stats_rx.icmp6__echo_request__respond_echo_reply,
            1,
            msg="Echo Request must be counted in icmp6__echo_request__respond_echo_reply.",
        )
        self.assertEqual(
            len(self._if.icmp6_tx_calls),
            1,
            msg="Echo Request must invoke exactly one _phtx_icmp6.",
        )
        call = self._if.icmp6_tx_calls[0]
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)
        self.assertEqual(call["ip6__dst"], HOST_A__IP6)
        self.assertIsInstance(call["icmp6__message"], Icmp6MessageEchoReply)


class TestPacketHandlerIcmp6RxNd(_Icmp6RxTestBase):
    """
    The ICMPv6 ND (Neighbor Discovery) dispatch tests.
    """

    def test__stack__packet_handler__icmp6__rx__fragmented_neighbor_solicitation_dropped(self) -> None:
        """
        Ensure a Neighbor Solicitation that arrived as IPv6
        fragments and was reassembled by the IPv6 fragment-RX
        path is silently dropped at the ICMPv6 dispatch layer
        (no upper-layer dispatch, no NA reply), and the
        'icmp6__nd_message__fragmented__drop' counter
        increments.

        Reference: RFC 6980 §5 (nodes MUST silently ignore ND
        / SEND messages on receipt if fragmented).
        """

        ns_message = Icmp6NdMessageNeighborSolicitation(
            target_address=STACK__IP6_ADDRESS,
            options=Icmp6NdOptions(),
        )
        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=ns_message,
        )

        # Mark the inbound packet as having been reassembled
        # from fragments, mimicking what 'PacketHandlerIp6FragRx'
        # would have set on the reassembled 'PacketRx'.
        packet_rx = _packet_rx_from_ip6_icmp6(ip6)
        packet_rx.was_fragmented = True

        self._icmp6_rx._phrx_icmp6(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_message__fragmented__drop,
            1,
            msg=("A fragmented ND message must increment " "'icmp6__nd_message__fragmented__drop'."),
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation,
            0,
            msg="A fragmented NS must not progress to the per-type counter.",
        )
        self.assertEqual(
            self._if.icmp6_tx_calls,
            [],
            msg="A fragmented ND message must not trigger any TX dispatch.",
        )

    def test__stack__packet_handler__icmp6__rx__fragmented_echo_request_passes_through(self) -> None:
        """
        Ensure the silent-discard scope is limited to ND /
        SEND messages — a fragmented ICMPv6 Echo Request
        (not an ND message) must still reach the echo-reply
        path. Regression-pin for the gate's ND-only scope.

        Reference: RFC 6980 §5 (silent-discard scope is ND /
        SEND messages only, not all ICMPv6).
        """

        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"x"),
        )

        packet_rx = _packet_rx_from_ip6_icmp6(ip6)
        packet_rx.was_fragmented = True

        self._icmp6_rx._phrx_icmp6(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_message__fragmented__drop,
            0,
            msg="Echo Request must not bump the ND-fragmented-drop counter.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__echo_request__respond_echo_reply,
            1,
            msg="A fragmented Echo Request must still produce an Echo Reply.",
        )

    def test__stack__packet_handler__icmp6__rx__router_advertisement__non_autonomous_prefix_dropped(self) -> None:
        """
        Ensure a Prefix Information option whose Autonomous flag
        is clear is silently filtered out of the SLAAC candidate
        list and the 'icmp6__nd_router_advertisement__prefix_info__drop'
        counter increments. Without the A bit, SLAAC must not
        derive an address from the prefix.

        Reference: RFC 4862 §5.5.3 (e)(1) (PI without A flag is
        ignored for address autoconfiguration).
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=False,  # SLAAC ineligible.
                    flag_r=False,
                    valid_lifetime=86400,
                    preferred_lifetime=14400,
                    prefix=Ip6Network("2001:db8:0:1::/64"),
                ),
            ),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            self._if._icmp6_ra__prefixes,
            [],
            msg=("A non-autonomous Prefix Information option must not be added to " "'_icmp6_ra__prefixes'."),
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_router_advertisement__prefix_info__drop,
            1,
            msg=(
                "A filtered Prefix Information option must increment "
                "'icmp6__nd_router_advertisement__prefix_info__drop'."
            ),
        )

    def test__stack__packet_handler__icmp6__rx__router_advertisement__link_local_prefix_dropped(self) -> None:
        """
        Ensure a Prefix Information option whose prefix is the
        link-local prefix is silently filtered out of the SLAAC
        candidate list. SLAAC must not derive a global address
        from the link-local prefix.

        Reference: RFC 4862 §5.5.3 (e)(2) (PI for the link-local
        prefix is ignored).
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=True,
                    flag_r=False,
                    valid_lifetime=86400,
                    preferred_lifetime=14400,
                    prefix=Ip6Network("fe80::/64"),
                ),
            ),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            self._if._icmp6_ra__prefixes,
            [],
            msg="A link-local Prefix Information option must not be added to '_icmp6_ra__prefixes'.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_router_advertisement__prefix_info__drop,
            1,
            msg="A link-local PI option must bump the prefix_info drop counter.",
        )

    def test__stack__packet_handler__icmp6__rx__router_advertisement__preferred_gt_valid_dropped(self) -> None:
        """
        Ensure a Prefix Information option whose preferred
        lifetime exceeds its valid lifetime is silently filtered
        out — the option is malformed per the lifetime-ordering
        invariant and SLAAC must not consume it.

        Reference: RFC 4862 §5.5.3 (e)(3) (preferred_lifetime
        MUST NOT exceed valid_lifetime).
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=True,
                    flag_r=False,
                    valid_lifetime=3600,
                    preferred_lifetime=7200,  # > valid_lifetime — invalid.
                    prefix=Ip6Network("2001:db8:0:1::/64"),
                ),
            ),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            self._if._icmp6_ra__prefixes,
            [],
            msg=("A PI option with preferred_lifetime > valid_lifetime must not " "be added to '_icmp6_ra__prefixes'."),
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_router_advertisement__prefix_info__drop,
            1,
            msg=("A PI option with preferred_lifetime > valid_lifetime must bump " "the prefix_info drop counter."),
        )

    def test__stack__packet_handler__icmp6__rx__router_advertisement__valid_prefix_admitted(self) -> None:
        """
        Ensure a well-formed Prefix Information option (A flag
        set, non-link-local prefix, preferred_lifetime <=
        valid_lifetime) is admitted to the SLAAC candidate list.
        Regression-pin for the happy path past the new filters.

        Reference: RFC 4862 §5.5.3 (e)(4) (well-formed PI option
        contributes to the prefix list).
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=True,
                    flag_r=False,
                    valid_lifetime=86400,
                    preferred_lifetime=14400,
                    prefix=Ip6Network("2001:db8:0:1::/64"),
                ),
            ),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            len(self._if._icmp6_ra__prefixes),
            1,
            msg="A well-formed PI option must be admitted to '_icmp6_ra__prefixes'.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp6__nd_router_advertisement__prefix_info__drop,
            0,
            msg="A well-formed PI option must not bump the drop counter.",
        )

    def test__stack__packet_handler__icmp6__rx__router_advertisement_counted(self) -> None:
        """
        Ensure an ICMPv6 RA from a link-local source is dispatched and
        counted. The parser requires the src to be link-local, so the
        fixture uses fe80::1 rather than a GUA.

        Reference: RFC 4861 §6.1.2 (Router Advertisement src MUST be link-local).
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertGreaterEqual(
            self._if._packet_stats_rx.icmp6__nd_router_advertisement,
            1,
            msg="Router Advertisement must be counted in icmp6__nd_router_advertisement.",
        )

    def test__stack__packet_handler__icmp6__rx__neighbor_solicitation_counts(self) -> None:
        """
        Ensure an ICMPv6 NS targeting our address is counted. The RX
        handler exercises the DAD / ND-cache paths which are patched
        out via the stub _phtx_icmp6.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation).
        """

        ns_message = Icmp6NdMessageNeighborSolicitation(
            target_address=STACK__IP6_ADDRESS,
            options=Icmp6NdOptions(),
        )
        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=ns_message,
        )

        self._icmp6_rx._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertGreaterEqual(
            self._if._packet_stats_rx.icmp6__nd_neighbor_solicitation,
            1,
            msg="Neighbor Solicitation must be counted in icmp6__nd_neighbor_solicitation.",
        )
