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
This module contains unit tests for the 'ArpRxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec, patch

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpAssembler, ArpOperation
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.runtime.packet_handler.packet_handler__arp__rx import ArpRxHandler

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2

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


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP4_ADDRESS = STACK__IP4_HOST.address

STACK__IP4_HOST__CANDIDATE = Ip4IfAddr("10.0.1.5/24")
STACK__IP4_ADDRESS__CANDIDATE = STACK__IP4_HOST__CANDIDATE.address

HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
HOST_B__MAC = MacAddress("02:00:00:00:00:92")
HOST_B__IP4 = Ip4Address("10.0.1.92")
OFF_NET__IP4 = Ip4Address("192.168.99.99")

MAC__BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")
MAC__UNSPEC = MacAddress()
IP4__UNSPEC = Ip4Address("0.0.0.0")


def _arp_frame(
    *,
    oper: ArpOperation,
    sha: MacAddress,
    spa: Ip4Address,
    tha: MacAddress,
    tpa: Ip4Address,
) -> bytes:
    """
    Build an ARP wire frame using 'ArpAssembler'. The handler consumes
    the frame starting at the ARP header; no Ethernet prefix is added.
    """

    return bytes(
        ArpAssembler(
            arp__oper=oper,
            arp__sha=sha,
            arp__spa=spa,
            arp__tha=tha,
            arp__tpa=tpa,
        )
    )


def _make_packet_rx(
    frame: bytes,
    *,
    ethernet_dst: MacAddress,
    ethernet_src: MacAddress = HOST_A__MAC,
) -> PacketRx:
    """
    Build a 'PacketRx' that looks like one that has already passed the
    Ethernet layer: frame starts at the ARP header and 'ethernet' is a
    SimpleNamespace carrying the src/dst MACs the parser/handler read.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ethernet = SimpleNamespace(  # type: ignore[assignment]
        dst=ethernet_dst,
        src=ethernet_src,
    )
    return packet_rx


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries exactly the state and cross-call surface the ARP RX
    sub-handler reads through 'self._if'. A purpose-built double is
    used rather than 'create_autospec(PacketHandlerL2)' because the
    god-class still carries 'TYPE_CHECKING'-only annotations that
    'inspect.signature' (which autospec walks) cannot evaluate at
    runtime — that smell is exactly what the composition refactor is
    removing.
    """

    def __init__(self, *, interface_name: str | None = None) -> None:
        """
        Initialize the stub interface. The spy records the arguments
        passed to the TX-side reply the RX handler invokes.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip4_ifaddr = [STACK__IP4_HOST]
        self._arp_cache: ArpCache | None = None
        self._interface_name = interface_name

        self.arp_replies_sent: list[dict[str, object]] = []

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Mirror the PacketHandler's '_ip4_unicast' property helper.
        """

        return [host.address for host in self._ip4_ifaddr]

    def _send_arp_reply(self, **kwargs: object) -> None:
        """
        Record the ARP-reply TX arguments for assertions.
        """

        self.arp_replies_sent.append(kwargs)


class _ArpRxTestBase(TestCase):
    """
    Common setUp for ARP RX tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the ARP RX sub-handler over a stub interface and inject
        the mock ARP cache it updates on inbound ARP.
        """

        self._if = _StubInterface()

        # The ARP cache is injected per-interface; assign the mock to
        # the stub interface's own '_arp_cache' (the RX path reads it
        # through 'self._if').
        self._arp_cache = create_autospec(ArpCache, spec_set=True)
        self._if._arp_cache = self._arp_cache

        self._arp_rx = ArpRxHandler(interface=cast("PacketHandlerL2", self._if))


class TestPacketHandlerArpRxParseFail(_ArpRxTestBase):
    """
    The ARP parser-failure tests.
    """

    def test__stack__packet_handler__arp__rx__malformed_frame_drops(self) -> None:
        """
        Ensure a truncated ARP frame fails parsing and is counted in
        'arp__failed_parse__drop'.

        Reference: RFC 826 (ARP packet validation).
        """

        truncated = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )[:10]

        packet_rx = _make_packet_rx(truncated, ethernet_dst=STACK__MAC_UNICAST)
        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__pre_parse,
            1,
            msg="arp__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__failed_parse__drop,
            1,
            msg="Malformed frame must be counted in arp__failed_parse__drop.",
        )


class TestPacketHandlerArpRxRequest(_ArpRxTestBase):
    """
    The ARP-request handling tests.
    """

    def test__stack__packet_handler__arp__rx__looped_request_drop(self) -> None:
        """
        Ensure an ARP request originating from our own MAC is treated
        as a loop and dropped.

        Reference: RFC 5227 §2.1.1 (self-loopback NOTE).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=STACK__MAC_UNICAST,
            spa=STACK__IP4_ADDRESS,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(
            frame,
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=STACK__MAC_UNICAST,
        )

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__looped__drop,
            1,
            msg="Looped own-MAC ARP request must be counted in arp__op_request__looped__drop.",
        )
        self.assertEqual(
            self._if.arp_replies_sent,
            [],
            msg="Looped ARP request must not trigger a reply.",
        )

    def test__stack__packet_handler__arp__rx__gratuitous_request(self) -> None:
        """
        Ensure a broadcast gratuitous ARP request (spa == tpa) is
        counted and populates the ARP cache.

        Reference: RFC 826 (gratuitous ARP wire shape).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__gratuitous,
            1,
            msg="Gratuitous ARP request must be counted in arp__op_request__gratuitous.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__update_arp_cache,
            1,
            msg="Gratuitous ARP request must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__tpa_unknown(self) -> None:
        """
        Ensure an ARP request for a TPA not in our unicast list is
        counted and no reply is sent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=OFF_NET__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__tpa_unknown,
            1,
            msg="ARP request for a TPA not owned by the stack must be counted as tpa_unknown.",
        )
        self.assertEqual(
            self._if.arp_replies_sent,
            [],
            msg="ARP request for an unknown TPA must not trigger a reply.",
        )

    def test__stack__packet_handler__arp__rx__probe(self) -> None:
        """
        Ensure an ARP probe (spa=0.0.0.0) for one of our TPAs is
        counted, a reply is sent, and the cache is NOT updated (spa
        fails the 'in host.network' test).

        Reference: RFC 5227 §2.5 (Reply to Probe Requests).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=IP4__UNSPEC,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__probe,
            1,
            msg="ARP probe request for a stack TPA must be counted.",
        )
        self.assertEqual(
            len(self._if.arp_replies_sent),
            1,
            msg="Probe request must trigger exactly one ARP reply.",
        )
        reply = self._if.arp_replies_sent[0]
        self.assertEqual(
            reply["arp__spa"],
            STACK__IP4_ADDRESS,
            msg="Probe reply spa must be our stack IP.",
        )
        self.assertEqual(
            reply["arp__tpa"],
            IP4__UNSPEC,
            msg="Probe reply tpa must echo the probe spa (unspecified).",
        )

    def test__stack__packet_handler__arp__rx__regular_request_replies_and_updates_cache(self) -> None:
        """
        Ensure a regular ARP request for one of our TPAs is counted,
        triggers a reply, and populates the ARP cache with spa<->sha.

        Reference: RFC 826 (ARP request → reply + cache update).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__tpa_stack,
            1,
            msg="Regular ARP request for our TPA must be counted as tpa_stack.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__respond,
            1,
            msg="Regular ARP request must trigger a respond stat.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__op_request__update_arp_cache,
            1,
            msg="Regular ARP request must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__unknown_operation_rejected_at_parse(self) -> None:
        """
        Ensure an ARP frame carrying an unknown operation code is
        rejected at parse time (sanity check), not by the handler's
        match-case fallthrough. The parser's sanity validation
        forbids 'is_unknown' operations.

        Reference: RFC 826 (ARP operation field).
        """

        valid = bytearray(
            _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
        )
        # Rewrite the 'oper' field (bytes 6-7) to a value neither
        # REQUEST (1) nor REPLY (2).
        valid[6:8] = (0x00FF).to_bytes(2)

        packet_rx = _make_packet_rx(bytes(valid), ethernet_dst=STACK__MAC_UNICAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__failed_parse__drop,
            1,
            msg="Unknown ARP operation must be rejected at parse time (arp__failed_parse__drop).",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__op_unknown__drop,
            0,
            msg="The match-case fallthrough must not fire; parser blocks unknown opers first.",
        )

    def test__stack__packet_handler__arp__rx__unknown_operation_handler_fallthrough_counts_drop(self) -> None:
        """
        Ensure the '_phrx_arp' match-case fallthrough for an operation
        that is neither REQUEST nor REPLY bumps 'arp__op_unknown__drop'
        without raising. The branch is unreachable through the real
        parser (which rejects 'is_unknown' opers at parse time), so it
        is exercised here by stubbing the parser to install an unknown
        operation; this guards against a future ArpOperation member the
        parser accepts but the handler does not dispatch crashing the
        RX thread.

        Reference: RFC 5494 §3 (additional ARP operation codes).
        """

        def _stub_parser(pkt: PacketRx) -> None:
            pkt.arp = SimpleNamespace(oper=ArpOperation.from_int(0x00FF))  # type: ignore[assignment]

        packet_rx = _make_packet_rx(
            _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            ),
            ethernet_dst=STACK__MAC_UNICAST,
        )

        with patch(
            "pytcp.runtime.packet_handler.packet_handler__arp__rx.ArpParser",
            side_effect=_stub_parser,
        ):
            self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_unknown__drop,
            1,
            msg="The handler's unknown-operation fallthrough must bump arp__op_unknown__drop.",
        )


class TestPacketHandlerArpRxReply(_ArpRxTestBase):
    """
    The ARP-reply handling tests.
    """

    def test__stack__packet_handler__arp__rx__looped_reply_drop(self) -> None:
        """
        Ensure an ARP reply originating from our own MAC is dropped
        as a loop.

        Reference: RFC 5227 §2.1.1 (self-loopback NOTE).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=STACK__MAC_UNICAST,
            spa=STACK__IP4_ADDRESS,
            tha=HOST_A__MAC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(
            frame,
            ethernet_dst=HOST_A__MAC,
            ethernet_src=STACK__MAC_UNICAST,
        )

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_reply__looped__drop,
            1,
            msg="Looped own-MAC ARP reply must be counted in arp__op_reply__looped__drop.",
        )

    def test__stack__packet_handler__arp__rx__reply_direct_updates_cache(self) -> None:
        """
        Ensure a direct ARP reply (ethernet.dst == stack unicast MAC)
        is counted and updates the ARP cache.

        Reference: RFC 826 (cache update on Reply).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=STACK__MAC_UNICAST,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=STACK__MAC_UNICAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_reply__direct,
            1,
            msg="Direct ARP reply must be counted in arp__op_reply__direct.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.arp__op_reply__update_arp_cache,
            1,
            msg="Direct ARP reply must update the ARP cache.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__reply_gratuitous(self) -> None:
        """
        Ensure a broadcast gratuitous ARP reply (spa == tpa, tha=0) is
        counted and updates the ARP cache.

        Reference: RFC 826 (gratuitous Reply wire shape).
        """

        frame = _arp_frame(
            oper=ArpOperation.REPLY,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=HOST_A__IP4,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.arp__op_reply__gratuitous,
            1,
            msg="Gratuitous ARP reply must be counted in arp__op_reply__gratuitous.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )


class TestPacketHandlerArpRxPolicySysctls(_ArpRxTestBase):
    """
    The 'arp.accept' / 'arp.ignore' RX-policy sysctl tests.

    Pin that the inbound-ARP handling honours the registered
    sysctl values: 'arp.accept' gates whether off-subnet
    senders update the cache, and 'arp.ignore = 2' drops
    Requests whose sender IP is not on any of our local
    subnets (Linux's 'net.ipv4.conf.<iface>.arp_ignore' mode
    2 semantics).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test override does not
        leak into subsequent tests' baselines.
        """

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__stack__packet_handler__arp__rx__arp_accept_default_drops_off_subnet_cache_update(self) -> None:
        """
        Ensure that with the default 'arp.accept = 0', an ARP
        Request whose sender IP is NOT on any of our local
        subnets does NOT update the ARP cache. The conservative
        default protects against trusting ARP from unknown
        networks (gratuitous-ARP cache poisoning from off-link
        attackers).

        Reference: Linux net.ipv4.conf.<iface>.arp_accept (mode 0: reject off-subnet).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=OFF_NET__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_not_called()

    def test__stack__packet_handler__arp__rx__arp_accept_one_admits_off_subnet_cache_update(self) -> None:
        """
        Ensure that with 'arp.accept = 1', an ARP Request
        whose sender IP is NOT on any of our local subnets
        DOES update the cache. Operators on multi-VLAN setups
        or behind ARP proxies may need this to learn next-hops
        outside their primary subnet.

        Reference: Linux net.ipv4.conf.<iface>.arp_accept (mode 1: admit off-subnet).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.accept", 1):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=OFF_NET__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_default_replies(self) -> None:
        """
        Ensure that with the default 'arp.ignore = 1', an ARP
        Request from an on-subnet sender for one of our
        configured IPs receives a Reply — current PyTCP
        baseline behaviour, restated against the live sysctl
        value.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 1: reply only if target configured).
        """

        frame = _arp_frame(
            oper=ArpOperation.REQUEST,
            sha=HOST_A__MAC,
            spa=HOST_A__IP4,
            tha=MAC__UNSPEC,
            tpa=STACK__IP4_ADDRESS,
        )
        packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)

        self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            len(self._if.arp_replies_sent),
            1,
            msg="With arp.ignore=1 (default), an on-subnet Request for our IP must trigger a Reply.",
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_drops_off_subnet_sender(self) -> None:
        """
        Ensure that with 'arp.ignore = 2', an ARP Request
        whose sender IP (SPA) is NOT on any of our local
        subnets is silently dropped without sending a Reply,
        even when its target IP IS one of ours. Linux's mode-2
        "sender-subnet-match" semantics — used to tighten
        anti-spoofing on hosts that should only answer ARPs
        from neighbours.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2: sender-subnet-match).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.ignore", 2):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if.arp_replies_sent,
            [],
            msg=(
                "With arp.ignore=2, an off-subnet sender must NOT receive an ARP "
                "Reply even when the target IP is one of ours."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_still_replies_on_subnet_sender(self) -> None:
        """
        Ensure 'arp.ignore = 2' still permits Replies when the
        sender IS on one of our local subnets — mode 2 is
        about REJECTING off-subnet senders, not about adding
        an extra rejection on legitimate neighbours.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2: on-subnet sender admitted).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.ignore", 2):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            len(self._if.arp_replies_sent),
            1,
            msg=(
                "With arp.ignore=2, an on-subnet sender for our target IP must "
                "still receive a Reply — mode 2 only rejects off-subnet senders."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_eight_drops_all_replies(self) -> None:
        """
        Ensure 'arp.ignore = 8' (kill switch) suppresses every
        Reply regardless of sender subnet, target match, or any
        other gate — Linux's mode 8 "do not reply for all local
        addresses" semantics.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 kill-switch).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.ignore", 8):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if.arp_replies_sent,
            [],
            msg=(
                "With arp.ignore=8, even a legitimate on-subnet Request for "
                "our IP must NOT receive a Reply — kill switch is unconditional."
            ),
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_two_still_updates_cache(self) -> None:
        """
        Ensure 'arp.ignore = 2' suppresses only the Reply and
        does NOT bypass cache learning when an off-subnet
        sender is admitted via 'arp.accept = 1'. Pins the fix
        for a latent bug where mode-2 used 'return' to drop the
        Reply, which also short-circuited the unconditional
        cache-update tail and silently ate every cache learn
        from off-subnet neighbours during anti-spoof mode.
        Linux's 'arp_ignore' affects only the reply path; cache
        behaviour is gated by 'arp_accept'.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 2 affects reply path only).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.ignore", 2), sysctl_module.override("arp.default.accept", 1):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=OFF_NET__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self.assertEqual(
            self._if.arp_replies_sent,
            [],
            msg="arp.ignore=2 must drop the Reply when SPA is off-subnet.",
        )
        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=OFF_NET__IP4,
            mac_address=HOST_A__MAC,
        )

    def test__stack__packet_handler__arp__rx__arp_ignore_eight_still_updates_cache(self) -> None:
        """
        Ensure 'arp.ignore = 8' suppresses only the Reply and
        does NOT bypass cache learning — mode 8's contract is
        "go silent on the wire," not "stop learning who is on
        the segment." Cache updates from inbound ARP let TCP
        reach the peer once it initiates traffic.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 affects reply path only).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.ignore", 8):
            frame = _arp_frame(
                oper=ArpOperation.REQUEST,
                sha=HOST_A__MAC,
                spa=HOST_A__IP4,
                tha=MAC__UNSPEC,
                tpa=STACK__IP4_ADDRESS,
            )
            packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
            self._arp_rx._phrx_arp(packet_rx)

        self._arp_cache.add_entry.assert_called_once_with(
            ip4_address=HOST_A__IP4,
            mac_address=HOST_A__MAC,
        )
