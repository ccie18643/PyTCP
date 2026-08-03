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
This module contains unit tests for the 'Icmp6TxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp6__tx.py

ver 3.0.9
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase

from net_addr import Ip6Address, Ip6IfAddr, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6Mld2MessageReport,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    MldVersion,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState
from pytcp.runtime.packet_handler.packet_handler__icmp6__tx import Icmp6TxHandler

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


STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")
STACK__IP6_ADDRESS = STACK__IP6_HOST.address
STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the TX-stat counters, the IPv6 addressing state, the
    Optimistic-DAD state map, and the IPv6 TX seam ('_phtx_ip6') the
    ICMPv6 TX sub-handler reaches through 'self._if', recording each
    call. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def _marshal_tx_async(
        self, run: Callable[[], TxStatus], /, *, on_complete: Callable[[], None] | None = None
    ) -> None:
        # Fire-and-forget marshaled entry (IGMP / MLD control messages);
        # with no TX worker under test, run the callable inline and fire
        # the completion hook, discarding the 'TxStatus'.
        run()
        if on_complete is not None:
            on_complete()

    def __init__(self, *, ip6_multicast: list[Ip6Address] | None = None) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._interface_name: str | None = None
        self._ip6_ifaddr = [STACK__IP6_HOST]
        self._ip6_multicast = ip6_multicast if ip6_multicast is not None else []
        self._icmp6_dad__states: dict[Ip6Address, Icmp6DadState] = {}

        self.ip6_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        return [STACK__IP6_ADDRESS]

    def _mld_host_compatibility_mode(self) -> MldVersion:
        # Default MLDv2 mode (no MLDv1 querier heard); the MLDv1
        # compatibility-fallback path is exercised by the dedicated
        # 'test__icmp6__mld1_compat' integration suite.
        return MldVersion.V2

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return self.ip6_tx_status


def _make_icmp6_tx(*, ip6_multicast: list[Ip6Address] | None = None) -> tuple[Icmp6TxHandler, _StubInterface]:
    """
    Build an 'Icmp6TxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(ip6_multicast=ip6_multicast)
    return Icmp6TxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)), interface


class TestPacketHandlerIcmp6Tx(TestCase):
    """
    The 'Icmp6TxHandler._phtx_icmp6' behaviour tests.
    """

    @override
    def setUp(self) -> None:
        self._handler, self._if = _make_icmp6_tx()

    def test__stack__packet_handler__icmp6__tx__echo_reply_counted(self) -> None:
        """
        Ensure an Echo Reply increments 'icmp6__echo_reply__send' and
        forwards to '_phtx_ip6'.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        status = self._handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoReply(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._if._packet_stats_tx.icmp6__echo_reply__send, 1)
        self.assertEqual(len(self._if.ip6_tx_calls), 1)
        self.assertIsInstance(self._if.ip6_tx_calls[0]["ip6__payload"], Icmp6Assembler)

    def test__stack__packet_handler__icmp6__tx__echo_request_counted(self) -> None:
        """
        Ensure an Echo Request increments 'icmp6__echo_request__send'.

        Reference: RFC 4443 §4.1 (Echo Request).
        """

        self._handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(self._if._packet_stats_tx.icmp6__echo_request__send, 1)


class TestPacketHandlerIcmp6TxConvenienceHelpers(TestCase):
    """
    The ICMPv6 convenience-helper tests.
    """

    @override
    def setUp(self) -> None:
        self._handler, self._if = _make_icmp6_tx()

    def _last_call(self) -> dict[str, object]:
        self.assertEqual(
            len(self._if.ip6_tx_calls),
            1,
            msg="Exactly one _phtx_ip6 call is expected from each helper.",
        )
        return self._if.ip6_tx_calls[0]

    def test__stack__packet_handler__icmp6__tx__dad_message_uses_unspecified_src_hop_255(self) -> None:
        """
        Ensure '_send_icmp6_nd_dad_message' sends an NS from 0:: to the
        candidate's solicited-node multicast with hop=255.

        Reference: RFC 4862 §5.4 (Duplicate Address Detection).
        """

        candidate = Ip6Address("2001:db8:0:1::100")
        self._handler._send_icmp6_nd_dad_message(ip6_unicast_candidate=candidate)

        call = self._last_call()
        self.assertEqual(call["ip6__src"], Ip6Address())
        self.assertEqual(call["ip6__dst"], candidate.solicited_node_multicast)
        self.assertEqual(call["ip6__hop"], 255)
        self.assertIsInstance(call["ip6__payload"], Icmp6Assembler)
        self.assertEqual(
            self._if._packet_stats_tx.icmp6__nd__neighbor_solicitation__send,
            1,
            msg="DAD message must be counted as an NS send.",
        )

    def test__stack__packet_handler__icmp6__tx__mld_report_skips_all_nodes(self) -> None:
        """
        Ensure '_send_icmp6_multicast_listener_report' filters out
        ff02::1 (all-nodes) and sends an MLDv2 report for the rest.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report).
        """

        group = Ip6Address("ff02::1:3")
        handler, iface = _make_icmp6_tx(ip6_multicast=[Ip6Address("ff02::1"), group])
        handler._send_icmp6_multicast_listener_report()

        self.assertEqual(len(iface.ip6_tx_calls), 1)
        call = iface.ip6_tx_calls[0]
        self.assertEqual(call["ip6__dst"], Ip6Address("ff02::16"))
        self.assertEqual(call["ip6__hop"], 1)
        # The MLDv2 Report is wrapped in an HBH+RouterAlert per RFC
        # 3810 §5 + RFC 2711, so the IPv6 payload is an Ip6HbhAssembler.
        from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler

        self.assertIsInstance(call["ip6__payload"], Ip6HbhAssembler)
        self.assertEqual(
            iface._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted.",
        )

    def test__stack__packet_handler__icmp6__tx__mld_report_skipped_when_only_all_nodes(self) -> None:
        """
        Ensure no MLDv2 report is emitted when the only joined group
        is ff02::1 (it is excluded from the report set).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report).
        """

        handler, iface = _make_icmp6_tx(ip6_multicast=[Ip6Address("ff02::1")])
        handler._send_icmp6_multicast_listener_report()

        self.assertEqual(
            iface.ip6_tx_calls,
            [],
            msg="MLDv2 report must not be sent when only the all-nodes group is joined.",
        )

    def test__stack__packet_handler__icmp6__tx__router_solicitation_targets_all_routers(self) -> None:
        """
        Ensure '_send_icmp6_nd_router_solicitation' addresses ff02::2
        (all-routers) with hop=255 and includes an SLLA option.

        Reference: RFC 4861 §6.3.7 (Router Solicitation transmission).
        """

        self._handler._send_icmp6_nd_router_solicitation()

        call = self._last_call()
        self.assertEqual(call["ip6__dst"], Ip6Address("ff02::2"))
        self.assertEqual(call["ip6__hop"], 255)

    def test__stack__packet_handler__icmp6__tx__neighbor_solicitation_targets_snm(self) -> None:
        """
        Ensure 'send_icmp6_neighbor_solicitation' addresses the target's
        solicited-node multicast with hop=255 and picks src from the
        matching stack host.

        Reference: RFC 4861 §7.2.2 (Neighbor Solicitation transmission).
        """

        target = HOST_A__IP6
        self._handler.send_icmp6_neighbor_solicitation(icmp6_ns_target_address=target)

        call = self._last_call()
        self.assertEqual(call["ip6__dst"], target.solicited_node_multicast)
        self.assertEqual(call["ip6__hop"], 255)
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)

    def test__stack__packet_handler__icmp6__tx__neighbor_solicitation_unicast_targets_directly(self) -> None:
        """
        Ensure 'send_icmp6_neighbor_solicitation_unicast'
        addresses the target IPv6 address directly (NOT the
        solicited-node multicast group) with hop=255 — the
        NUD_PROBE-state form. The cached neighbour's MAC
        resolves at the Ethernet TX layer via the ND cache's
        PROBE-state entry.

        Reference: RFC 4861 §7.3.3 (unicast NS for PROBE).
        """

        target = HOST_A__IP6
        self._handler.send_icmp6_neighbor_solicitation_unicast(icmp6_ns_target_address=target)

        call = self._last_call()
        self.assertEqual(
            call["ip6__dst"],
            target,
            msg=(
                "Unicast NS must use the target address itself as ip6__dst, " "not the solicited-node multicast group."
            ),
        )
        self.assertEqual(call["ip6__hop"], 255)
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)

    def test__stack__packet_handler__icmp6__tx__send_icmp6_packet_forwards(self) -> None:
        """
        Ensure the public 'send_icmp6_packet' helper forwards its
        arguments to '_phtx_icmp6'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler.send_icmp6_packet(
            ip6__local_address=STACK__IP6_ADDRESS,
            ip6__remote_address=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._if._packet_stats_tx.icmp6__echo_request__send, 1)


class TestPacketHandlerIcmp6TxNeighborAdvertisement(TestCase):
    """
    The 'send_icmp6_neighbor_advertisement' helper tests
    (nd_linux_parity §5 — refactor of the previously-inline NA
    emission code from the NS RX handler into a public TX
    helper).
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub handler.
        """

        self._handler, self._if = _make_icmp6_tx()

    def _last_payload(self) -> object:
        """
        Return the ICMPv6 message object inside the last
        '_phtx_ip6' call's payload.
        """

        from net_proto import Icmp6Assembler

        self.assertEqual(len(self._if.ip6_tx_calls), 1)
        payload = self._if.ip6_tx_calls[0]["ip6__payload"]
        assert isinstance(payload, Icmp6Assembler)
        return payload._message

    def test__stack__packet_handler__icmp6__tx__send_na__solicited_with_tlla(self) -> None:
        """
        Ensure 'send_icmp6_neighbor_advertisement' with
        flag_s=True, flag_o=False emits a solicited NA carrying
        the stack's TLLA at hop_limit=255.

        Reference: RFC 4861 §4.4 (NA wire format), §7.2.4 (NS-response NA).
        """

        from net_proto import Icmp6NdMessageNeighborAdvertisement

        self._handler.send_icmp6_neighbor_advertisement(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            target_address=STACK__IP6_ADDRESS,
            flag_r=False,
            flag_s=True,
            flag_o=False,
        )

        call = self._if.ip6_tx_calls[0]
        self.assertEqual(call["ip6__hop"], 255)
        msg = self._last_payload()
        assert isinstance(msg, Icmp6NdMessageNeighborAdvertisement)
        self.assertEqual(msg.flag_s, True)
        self.assertEqual(msg.flag_o, False)
        self.assertEqual(msg.target_address, STACK__IP6_ADDRESS)
        self.assertEqual(msg.options.tlla, STACK__MAC_UNICAST)

    def test__stack__packet_handler__icmp6__tx__send_na__unsolicited_override(self) -> None:
        """
        Ensure 'send_icmp6_neighbor_advertisement' with
        flag_s=False, flag_o=True emits an unsolicited
        override NA — the wire shape mandated for gratuitous
        announcements.

        Reference: RFC 9131 §3 (gratuitous NA wire format).
        """

        from net_proto import Icmp6NdMessageNeighborAdvertisement

        self._handler.send_icmp6_neighbor_advertisement(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address("ff02::1"),
            target_address=STACK__IP6_ADDRESS,
            flag_r=False,
            flag_s=False,
            flag_o=True,
        )

        msg = self._last_payload()
        assert isinstance(msg, Icmp6NdMessageNeighborAdvertisement)
        self.assertEqual(msg.flag_s, False)
        self.assertEqual(msg.flag_o, True)
        self.assertEqual(self._if.ip6_tx_calls[0]["ip6__dst"], Ip6Address("ff02::1"))


class TestPacketHandlerIcmp6TxGratuitousNa(TestCase):
    """
    The 'send_icmp6_neighbor_advertisement_gratuitous' tests —
    nd_linux_parity §6 (RFC 9131 §3).
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub handler. Restore sysctl defaults at
        teardown so per-test overrides do not leak.
        """

        self._handler, self._if = _make_icmp6_tx()
        self.addCleanup(self._reset_sysctls)

    def _reset_sysctls(self) -> None:
        """
        Roll any per-test 'icmp6.gratuitous_na_count' override
        back to the registered default.
        """

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()

    def test__stack__packet_handler__icmp6__tx__gratuitous_na__default_count_emits_one(self) -> None:
        """
        Ensure with the default 'icmp6.gratuitous_na_count = 1'
        the gratuitous-NA helper emits exactly one NA targeting
        the all-nodes link-local multicast (ff02::1) with the
        unsolicited+override flag pattern.

        Reference: RFC 9131 §3 (gratuitous NA on host attachment).
        """

        from net_proto import Icmp6NdMessageNeighborAdvertisement

        self._handler.send_icmp6_neighbor_advertisement_gratuitous(
            ip6_unicast=STACK__IP6_ADDRESS,
        )

        self.assertEqual(
            len(self._if.ip6_tx_calls),
            1,
            msg="Default icmp6.gratuitous_na_count must produce exactly one NA.",
        )
        call = self._if.ip6_tx_calls[0]
        self.assertEqual(
            call["ip6__src"],
            STACK__IP6_ADDRESS,
            msg="Gratuitous NA src must be the host's address.",
        )
        self.assertEqual(
            call["ip6__dst"],
            Ip6Address("ff02::1"),
            msg="Gratuitous NA dst must be all-nodes link-local multicast.",
        )
        from net_proto import Icmp6Assembler

        payload = call["ip6__payload"]
        assert isinstance(payload, Icmp6Assembler)
        msg = payload._message
        assert isinstance(msg, Icmp6NdMessageNeighborAdvertisement)
        self.assertFalse(msg.flag_s, msg="Gratuitous NA must NOT set the Solicited flag.")
        self.assertTrue(msg.flag_o, msg="Gratuitous NA MUST set the Override flag.")
        self.assertEqual(
            msg.target_address,
            STACK__IP6_ADDRESS,
            msg="Gratuitous NA target must be the host's address.",
        )
        self.assertEqual(
            msg.options.tlla,
            STACK__MAC_UNICAST,
            msg="Gratuitous NA must carry the host's TLLA.",
        )

    def test__stack__packet_handler__icmp6__tx__gratuitous_na__sysctl_override_emits_three(self) -> None:
        """
        Ensure 'icmp6.gratuitous_na_count = 3' produces exactly
        three NAs — the loop honours the live sysctl value
        rather than baking the count at import time.

        Reference: PyTCP sysctl framework (operator-tunable count).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("icmp6.default.gratuitous_na_count", 3):
            self._handler.send_icmp6_neighbor_advertisement_gratuitous(
                ip6_unicast=STACK__IP6_ADDRESS,
            )

        self.assertEqual(
            len(self._if.ip6_tx_calls),
            3,
            msg="Three NAs must be emitted when icmp6.gratuitous_na_count = 3.",
        )

    def test__stack__packet_handler__icmp6__tx__gratuitous_na__sysctl_count_zero_emits_none(self) -> None:
        """
        Ensure 'icmp6.gratuitous_na_count = 0' suppresses
        gratuitous NA emission entirely — operators who need
        the kill-switch (security-sensitive deployments where
        announcement is unwelcome) get it for free from the
        registered count.

        Reference: PyTCP sysctl framework (zero-count kill switch).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("icmp6.default.gratuitous_na_count", 0):
            self._handler.send_icmp6_neighbor_advertisement_gratuitous(
                ip6_unicast=STACK__IP6_ADDRESS,
            )

        self.assertEqual(
            self._if.ip6_tx_calls,
            [],
            msg="Zero-count must suppress gratuitous NA emission entirely.",
        )


class TestPacketHandlerIcmp6TxUnsupported(TestCase):
    """
    The unsupported-type behaviour tests.
    """

    def test__stack__packet_handler__icmp6__tx__mld2_report_counted(self) -> None:
        """
        Ensure an MLDv2 Report is counted in 'icmp6__mld2__report__send'
        — the positive baseline case for the type-dispatch match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_icmp6_tx()
        handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address("ff02::16"),
            ip6__hop=1,
            icmp6__message=Icmp6Mld2MessageReport(records=[]),
        )

        self.assertEqual(
            iface._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted in icmp6__mld2__report__send.",
        )

    def test__stack__packet_handler__icmp6__tx__unsupported_type_drops(self) -> None:
        """
        Ensure an unsupported ICMPv6 type/code combination is dropped
        with 'TxStatus.DROPPED__ICMP6__UNKNOWN' and bumps the
        'icmp6__unknown__drop' counter — defensive over a 'raise'
        that would crash the calling thread. ICMPv6 Destination
        Unreachable code=ADDRESS is not in the supported match arms
        (only PORT and NO_ROUTE are).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_icmp6_tx()
        status = handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__hop=64,
            icmp6__message=Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.ADDRESS,
                data=b"\x00" * 40,
            ),
        )

        self.assertIs(
            status,
            TxStatus.DROPPED__ICMP6__UNKNOWN,
            msg="Unsupported ICMPv6 type must return DROPPED__ICMP6__UNKNOWN.",
        )
        self.assertEqual(
            iface._packet_stats_tx.icmp6__unknown__drop,
            1,
            msg="Unsupported ICMPv6 type must bump 'icmp6__unknown__drop'.",
        )
