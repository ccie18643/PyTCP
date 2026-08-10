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
This module contains unit tests for the 'ArpTxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__tx.py

ver 3.0.10
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpAssembler, ArpOperation
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__arp__tx import ArpTxHandler

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
STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
MAC__BROADCAST = MacAddress(0xFFFFFFFFFFFF)
MAC__UNSPEC = MacAddress()
IP4__UNSPEC = Ip4Address()


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries exactly the state and cross-call surface the ARP TX
    sub-handler reaches through 'self._if' (the TX marshal seam and
    the Ethernet TX path), plus spies that record every
    '_phtx_ethernet' call. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' because the god-class still
    carries 'TYPE_CHECKING'-only annotations that 'inspect.signature'
    (which autospec walks) cannot evaluate at runtime — the smell the
    composition refactor is removing.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def __init__(
        self,
        *,
        ip4_support: bool = True,
        ip4_unicast: list[Ip4Address] | None = None,
        ip4_host: list[Ip4IfAddr] | None = None,
        interface_name: str | None = None,
    ) -> None:
        """
        Initialize the stub interface and record every _phtx_ethernet call.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip4_support = ip4_support
        self._interface_name = interface_name
        if ip4_host is not None:
            self._ip4_ifaddr: list[Ip4IfAddr] = list(ip4_host)
            self._ip4_unicast_list = [host.address for host in self._ip4_ifaddr]
        else:
            self._ip4_unicast_list = list(ip4_unicast) if ip4_unicast is not None else [STACK__IP4_ADDRESS]
            self._ip4_ifaddr = [Ip4IfAddr(f"{addr}/24") for addr in self._ip4_unicast_list]

        # Spy: record every call to _phtx_ethernet.
        self.ethernet_tx_calls: list[dict[str, object]] = []
        self.ethernet_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Return the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast_list

    def _phtx_ethernet(self, **kwargs: object) -> TxStatus:
        """
        Record the call and return the configured TxStatus.
        """

        self.ethernet_tx_calls.append(kwargs)
        return self.ethernet_tx_status


def _make_arp_tx(
    *,
    ip4_support: bool = True,
    ip4_unicast: list[Ip4Address] | None = None,
    ip4_host: list[Ip4IfAddr] | None = None,
) -> tuple[ArpTxHandler, _StubInterface]:
    """
    Build an 'ArpTxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(ip4_support=ip4_support, ip4_unicast=ip4_unicast, ip4_host=ip4_host)
    return ArpTxHandler(interface=cast("PacketHandlerL2", interface)), interface


class TestPacketHandlerArpTx(TestCase):
    """
    The 'PacketHandlerArpTx._phtx_arp' behaviour tests.
    """

    def test__stack__packet_handler__arp__tx__ip4_disabled_drops(self) -> None:
        """
        Ensure the handler drops ARP packets when IPv4 is disabled and
        does not invoke the Ethernet TX path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_arp_tx(ip4_support=False)

        status = handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=MAC__UNSPEC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            status,
            TxStatus.DROPPED__ARP__NO_PROTOCOL_SUPPORT,
            msg="ARP TX with IPv4 disabled must return DROPPED__ARP__NO_PROTOCOL_SUPPORT.",
        )
        self.assertEqual(
            iface._packet_stats_tx.arp__no_proto_support__drop,
            1,
            msg="arp__no_proto_support__drop must be incremented on the disabled-IPv4 path.",
        )
        self.assertEqual(
            iface.ethernet_tx_calls,
            [],
            msg="IPv4-disabled drop must not hit the Ethernet TX layer.",
        )

    def test__stack__packet_handler__arp__tx__request_forwarded_to_ethernet(self) -> None:
        """
        Ensure an ARP request is counted, assembled, and forwarded to
        the Ethernet TX layer with the assembled ARP payload.

        Reference: RFC 826 (ARP Request wire format).
        """

        handler, iface = _make_arp_tx()

        status = handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=MAC__UNSPEC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="ARP TX must return the TxStatus returned by the Ethernet TX layer.",
        )
        self.assertEqual(
            iface._packet_stats_tx.arp__pre_assemble,
            1,
            msg="arp__pre_assemble must be incremented on the TX entry.",
        )
        self.assertEqual(
            iface._packet_stats_tx.arp__op_request__send,
            1,
            msg="arp__op_request__send must be incremented on REQUEST.",
        )
        self.assertEqual(
            len(iface.ethernet_tx_calls),
            1,
            msg="Exactly one _phtx_ethernet call must have been issued.",
        )
        call = iface.ethernet_tx_calls[0]
        self.assertEqual(
            call["ethernet__src"],
            STACK__MAC_UNICAST,
            msg="Ethernet src must be passed through verbatim.",
        )
        self.assertEqual(
            call["ethernet__dst"],
            MAC__BROADCAST,
            msg="Ethernet dst must be passed through verbatim.",
        )
        self.assertIsInstance(
            call["ethernet__payload"],
            ArpAssembler,
            msg="Ethernet payload must be an ArpAssembler instance.",
        )

    def test__stack__packet_handler__arp__tx__reply_uses_reply_stat(self) -> None:
        """
        Ensure an ARP reply increments 'arp__op_reply__send' and
        forwards the assembled packet.

        Reference: RFC 826 (ARP Reply wire format).
        """

        handler, iface = _make_arp_tx()

        handler._phtx_arp(
            ethernet__src=STACK__MAC_UNICAST,
            ethernet__dst=HOST_A__MAC,
            arp__oper=ArpOperation.REPLY,
            arp__sha=STACK__MAC_UNICAST,
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=HOST_A__MAC,
            arp__tpa=HOST_A__IP4,
        )

        self.assertEqual(
            iface._packet_stats_tx.arp__op_reply__send,
            1,
            msg="arp__op_reply__send must be incremented on REPLY.",
        )
        self.assertEqual(
            iface._packet_stats_tx.arp__op_request__send,
            0,
            msg="arp__op_request__send must NOT be incremented on REPLY.",
        )


class TestPacketHandlerArpTxConvenienceHelpers(TestCase):
    """
    The convenience helper (_send_arp_reply / send_arp_request /
    send_arp_unicast_request) tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh stub handler for each case.
        """

        self._handler, self._if = _make_arp_tx()

    def _last_call(self) -> dict[str, object]:
        """
        Return the kwargs passed to the single expected _phtx_ethernet
        call from each helper.
        """

        self.assertEqual(
            len(self._if.ethernet_tx_calls),
            1,
            msg="Exactly one _phtx_ethernet call is expected from each ARP helper.",
        )
        return self._if.ethernet_tx_calls[0]

    def test__stack__packet_handler__arp__tx__reply_helper_targets_requester(self) -> None:
        """
        Ensure '_send_arp_reply' unicasts a REPLY back to the requester
        MAC with stack MAC as src.

        Reference: RFC 826 (ARP Reply unicast back to requester).
        """

        self._handler._send_arp_reply(
            arp__spa=STACK__IP4_ADDRESS,
            arp__tha=HOST_A__MAC,
            arp__tpa=HOST_A__IP4,
        )

        call = self._last_call()
        self.assertEqual(call["ethernet__src"], STACK__MAC_UNICAST)
        self.assertEqual(call["ethernet__dst"], HOST_A__MAC)
        payload = call["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.oper, ArpOperation.REPLY)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tha, HOST_A__MAC)
        self.assertEqual(payload.tpa, HOST_A__IP4)

    def test__stack__packet_handler__arp__tx__request_uses_first_ip4_unicast(self) -> None:
        """
        Ensure 'send_arp_request' uses the first stack IPv4 unicast
        address as spa when one is configured.

        Reference: RFC 826 (Sender Protocol Address sourcing).
        """

        self._handler.send_arp_request(arp__tpa=HOST_A__IP4)

        payload = self._last_call()["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(payload.spa, STACK__IP4_ADDRESS)
        self.assertEqual(payload.tpa, HOST_A__IP4)

    def test__stack__packet_handler__arp__tx__request_defaults_spa_unspecified_when_empty(self) -> None:
        """
        Ensure 'send_arp_request' falls back to spa = 0.0.0.0 when the
        stack has no IPv4 unicast address.

        Reference: RFC 826 (Sender Protocol Address sourcing).
        """

        handler, iface = _make_arp_tx(ip4_unicast=[])
        handler.send_arp_request(arp__tpa=HOST_A__IP4)

        payload = iface.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            IP4__UNSPEC,
            msg="send_arp_request must fall back to spa=0.0.0.0 when no stack IPv4 is configured.",
        )

    def test__stack__packet_handler__arp__tx__unicast_request_targets_cached_mac(self) -> None:
        """
        Ensure 'send_arp_unicast_request' emits an ARP Request
        whose Ethernet destination is the caller-supplied MAC
        (not the broadcast address), so a cache-refresh probe
        wakes up only the cached neighbour rather than every
        host on the segment.

        Reference: RFC 1122 §2.3.2.1 IMPL (2) (unicast cache-refresh probe).
        """

        self._handler.send_arp_unicast_request(
            arp__tpa=HOST_A__IP4,
            ethernet__dst=HOST_A__MAC,
        )

        call = self._last_call()
        self.assertEqual(
            call["ethernet__src"],
            STACK__MAC_UNICAST,
            msg="Unicast refresh probe must use stack MAC as Ethernet source.",
        )
        self.assertEqual(
            call["ethernet__dst"],
            HOST_A__MAC,
            msg=(
                "Unicast refresh probe must use the cached neighbour MAC as "
                "Ethernet destination, not the broadcast address — that is "
                "the whole point of the unicast variant."
            ),
        )
        payload = call["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.oper,
            ArpOperation.REQUEST,
            msg="Unicast refresh probe is an ARP Request, not a Reply.",
        )
        self.assertEqual(
            payload.sha,
            STACK__MAC_UNICAST,
            msg="Sender hardware address must be our own MAC.",
        )
        self.assertEqual(
            payload.spa,
            STACK__IP4_ADDRESS,
            msg="Sender protocol address must be our own IPv4 (refresh probe is from us).",
        )
        self.assertEqual(
            payload.tpa,
            HOST_A__IP4,
            msg="Target protocol address must be the IP whose entry is being refreshed.",
        )


class TestPacketHandlerArpTxAnnounceSysctl(TestCase):
    """
    The 'arp.announce' source-IP-selection sysctl tests — pin
    that 'send_arp_request' / 'send_arp_unicast_request' pick
    the SPA according to the registered mode value.
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub handler with two local IPv4 hosts on
        distinct subnets so the subnet-match branch is
        observable.
        """

        self._handler, self._if = _make_arp_tx(
            ip4_host=[
                Ip4IfAddr("10.0.1.7/24"),
                Ip4IfAddr("192.168.5.20/24"),
            ],
        )

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a per-test override never
        leaks into a subsequent test's baseline.
        """

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()

    def test__stack__packet_handler__arp__tx__announce_default_uses_first_listed(self) -> None:
        """
        Ensure with the default 'arp.announce = 0',
        'send_arp_request' uses the first listed local IPv4
        address as SPA regardless of which subnet contains the
        target — Linux's "use any local address" semantics.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 0 default).
        """

        self._handler.send_arp_request(arp__tpa=Ip4Address("192.168.5.99"))

        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            Ip4Address("10.0.1.7"),
            msg=(
                "arp.announce=0 must select the first listed local IPv4 "
                "even when a different listed IP is in the target's subnet."
            ),
        )

    def test__stack__packet_handler__arp__tx__announce_one_picks_subnet_match(self) -> None:
        """
        Ensure with 'arp.announce = 1', 'send_arp_request'
        prefers the local IPv4 whose configured subnet contains
        the target IP — Linux's "prefer in-subnet sender"
        semantics.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 1 in-subnet).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.announce", 1):
            self._handler.send_arp_request(arp__tpa=Ip4Address("192.168.5.99"))

        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            Ip4Address("192.168.5.20"),
            msg=("arp.announce=1 must select the local IP whose subnet contains " "the target."),
        )

    def test__stack__packet_handler__arp__tx__announce_one_falls_back_when_no_subnet_match(self) -> None:
        """
        Ensure with 'arp.announce = 1', when no local IP's
        subnet contains the target, the helper falls back to
        the first listed IP (mode-0 default) rather than
        sending with SPA = 0.0.0.0.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 1 fall back to mode 2 when no match).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.announce", 1):
            self._handler.send_arp_request(arp__tpa=Ip4Address("172.16.0.1"))

        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            Ip4Address("10.0.1.7"),
            msg=("arp.announce=1 with no subnet match must fall back to the " "first listed local IP, not 0.0.0.0."),
        )

    def test__stack__packet_handler__arp__tx__announce_two_picks_subnet_match(self) -> None:
        """
        Ensure with 'arp.announce = 2', the helper picks the
        same subnet-match-with-fallback as mode 1 — PyTCP has
        no notion of "primary IP" beyond first-listed, so
        modes 1 and 2 collapse to the same behaviour today.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 2 best-local-address).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.announce", 2):
            self._handler.send_arp_request(arp__tpa=Ip4Address("192.168.5.99"))

        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            Ip4Address("192.168.5.20"),
            msg="arp.announce=2 must pick the subnet-matching local IP.",
        )

    def test__stack__packet_handler__arp__tx__announce_unicast_request_honours_mode(self) -> None:
        """
        Ensure 'send_arp_unicast_request' (the cache-refresh
        unicast probe) also routes its SPA selection through
        the 'arp.announce' helper.

        Reference: Linux net.ipv4.conf.<iface>.arp_announce (mode 1 in-subnet).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("arp.default.announce", 1):
            self._handler.send_arp_unicast_request(
                arp__tpa=Ip4Address("192.168.5.99"),
                ethernet__dst=MacAddress("02:00:00:00:00:91"),
            )

        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, ArpAssembler)
        self.assertEqual(
            payload.spa,
            Ip4Address("192.168.5.20"),
            msg=("send_arp_unicast_request must honour 'arp.announce' the same " "way 'send_arp_request' does."),
        )
