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
This module contains unit tests for the 'EthernetTxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ethernet__tx.py

ver 3.0.10
"""

from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec, patch

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from net_proto import (
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
    RawAssembler,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.fib import Route, RouteProtocol, RouteTable
from pytcp.runtime.packet_handler.packet_handler__ethernet__tx import (
    EthernetTxHandler,
)
from pytcp.runtime.tx_ring import TxRing

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
STACK__IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")
STACK__IP6_GATEWAY = Ip6Address("fe80::1")

STACK__IP4_HOST__NO_GW = Ip4IfAddr("192.168.99.7/24")
STACK__IP6_HOST__NO_GW = Ip6IfAddr("2001:db8:0:99::7/64")

GATEWAY_MAC = MacAddress("02:00:00:00:00:01")
HOST_A__MAC = MacAddress("02:00:00:00:00:91")
HOST_A__IP4 = Ip4Address("10.0.1.91")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
HOST_B__IP4 = Ip4Address("10.0.1.92")  # ARP miss
HOST_B__IP6 = Ip6Address("2001:db8:0:1::92")  # ND miss
HOST_C__IP4 = Ip4Address("10.0.2.50")  # external-net
HOST_C__IP6 = Ip6Address("2001:db8:0:2::50")  # external-net


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries the TX-stat counters, the stack MAC / address lists, the
    'ifindex', and (injected by the test 'setUp') the TX ring and the
    ARP / ND caches the Ethernet TX sub-handler reaches through
    'self._if'. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which autospec
    walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        """
        Initialize the stub interface with the bare attributes the
        sub-handler reads.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ifindex = 1
        self._ip4_ifaddr = [STACK__IP4_HOST]
        self._ip6_ifaddr = [STACK__IP6_HOST]
        # Injected by the test 'setUp' (per-interface TX ring + caches).
        self._tx_ring: TxRing | None = None
        self._arp_cache: ArpCache | None = None
        self._nd_cache: NdCache | None = None


def _make_ethernet_tx() -> tuple[EthernetTxHandler, _StubInterface]:
    """
    Build an 'EthernetTxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface()
    return (
        EthernetTxHandler(interface=cast("PacketHandlerL2", interface)),
        interface,
    )


def _build_ip4_assembler(*, src: Ip4Address, dst: Ip4Address) -> Ip4Assembler:
    """
    Build a minimal 'Ip4Assembler' fixture with the given addresses.
    """

    return Ip4Assembler(ip4__src=src, ip4__dst=dst, ip4__payload=RawAssembler())


def _build_ip6_assembler(*, src: Ip6Address, dst: Ip6Address) -> Ip6Assembler:
    """
    Build a minimal 'Ip6Assembler' fixture with the given addresses.
    """

    return Ip6Assembler(ip6__src=src, ip6__dst=dst, ip6__payload=RawAssembler())


class _EthernetTxTestBase(TestCase):
    """
    Common setUp/tearDown for the Ethernet TX unit tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the stub handler, inject mock TX ring / neighbor caches,
        and patch the FIB singletons.
        """

        self._handler, self._if = _make_ethernet_tx()

        # TX ring and neighbor caches are now injected per-interface;
        # assign the mocks to the handler's own attributes rather than
        # patching the global 'stack.*' singletons (which the send-out
        # / resolution paths no longer read).
        self._tx_ring = create_autospec(TxRing, spec_set=True)
        self._if._tx_ring = self._tx_ring

        self._arp_cache = create_autospec(ArpCache, spec_set=True)
        self._nd_cache = create_autospec(NdCache, spec_set=True)
        self._if._arp_cache = self._arp_cache
        self._if._nd_cache = self._nd_cache

        # Post-Phase-2 the Ethernet-TX next hop is decided by the
        # FIB. Patch fresh real RouteTables (real lookup logic,
        # not a mock) pre-populated with a default route via the
        # STACK gateways so the extnet (off-link) tests resolve
        # via the gateway. The localnet tests rely on the
        # synthesized connected route from '_ip*_ifaddr'; the
        # 'no_gateway' tests remove the default route to exercise
        # the no-route drop.
        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self._ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=STACK__IP4_GATEWAY,
                protocol=RouteProtocol.BOOT,
            )
        )
        self._ip6_fib.add(
            route=Route(
                destination=Ip6Network("::/0"),
                gateway=STACK__IP6_GATEWAY,
                protocol=RouteProtocol.BOOT,
            )
        )
        # 'create=True' — 'stack.ip4_fib' / 'ip6_fib' are
        # module-level names that are only bound by 'init()' /
        # 'mock__init()'; this unit file does not run either, so
        # the attribute may be absent when the file runs alone.
        self._ip4_fib_patch = patch.object(stack, "ip4_fib", self._ip4_fib, create=True)
        self._ip6_fib_patch = patch.object(stack, "ip6_fib", self._ip6_fib, create=True)
        self._ip4_fib_patch.start()
        self._ip6_fib_patch.start()

        # Default cache responses: miss for everyone.
        self._arp_cache.find_entry.return_value = None
        self._nd_cache.find_entry.return_value = None

    @override
    def tearDown(self) -> None:
        """
        Restore the patched FIB singletons.
        """

        self._ip4_fib_patch.stop()
        self._ip6_fib_patch.stop()


class TestPacketHandlerEthernetTxDirect(_EthernetTxTestBase):
    """
    The direct-path tests (dst already specified, no IP lookup needed).
    """

    def test__stack__packet_handler__ethernet__tx__specified_dst_sends(self) -> None:
        """
        Ensure a specified dst MAC is sent directly and neither the ARP
        cache nor the ND cache is consulted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler._phtx_ethernet(
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Handler must return PASSED__ETHERNET__TO_TX_RING when dst is already specified.",
        )
        self._tx_ring.enqueue.assert_called_once()
        self._arp_cache.find_entry.assert_not_called()
        self._nd_cache.find_entry.assert_not_called()
        self.assertEqual(
            self._if._packet_stats_tx.ethernet__dst_spec__send,
            1,
            msg="ethernet__dst_spec__send must be incremented on the direct-send path.",
        )

    def test__stack__packet_handler__ethernet__tx__fills_unspecified_src(self) -> None:
        """
        Ensure an unspecified src MAC is filled with the stack unicast
        MAC and 'ethernet__src_unspec__fill' is incremented.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ethernet(
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.src,
            STACK__MAC_UNICAST,
            msg="The enqueued packet's src MAC must be set to the stack unicast MAC.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet__src_unspec__fill,
            1,
            msg="ethernet__src_unspec__fill must be incremented when src is unspecified.",
        )

    def test__stack__packet_handler__ethernet__tx__honors_specified_src(self) -> None:
        """
        Ensure a specified src MAC is not overwritten and
        'ethernet__src_spec' is incremented.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        custom_src = MacAddress("02:00:00:00:00:aa")
        self._handler._phtx_ethernet(
            ethernet__src=custom_src,
            ethernet__dst=HOST_A__MAC,
            ethernet__payload=RawAssembler(),
        )

        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.src,
            custom_src,
            msg="The enqueued packet's src MAC must equal the supplied src.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet__src_spec,
            1,
            msg="ethernet__src_spec must be incremented when a src MAC is supplied.",
        )

    def test__stack__packet_handler__ethernet__tx__raw_payload_unknown_proto_drops(self) -> None:
        """
        Ensure a RawAssembler payload (neither IPv4 nor IPv6) with an
        unspecified dst MAC is dropped because no resolution path applies.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler._phtx_ethernet(ethernet__payload=RawAssembler())

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL,
            msg="Handler must return DROPPED__ETHERNET__DST_RESOLUTION_FAIL for Raw payload with unspecified dst.",
        )
        self._tx_ring.enqueue.assert_not_called()
        self.assertEqual(
            self._if._packet_stats_tx.ethernet__dst_unspec__drop,
            1,
            msg="ethernet__dst_unspec__drop must be incremented on the fallthrough drop.",
        )


class TestPacketHandlerEthernetTxIp6Lookup(_EthernetTxTestBase):
    """
    The IPv6-lookup path tests.
    """

    def test__stack__packet_handler__ethernet__tx__ip6_multicast_dst_uses_multicast_mac(self) -> None:
        """
        Ensure an IPv6 multicast destination resolves to its derived
        multicast MAC without consulting the ND cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip6 = _build_ip6_assembler(
            src=STACK__IP6_HOST.address,
            dst=Ip6Address("ff02::1"),
        )

        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 multicast must resolve to multicast MAC and be enqueued.",
        )
        self._nd_cache.find_entry.assert_not_called()
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            Ip6Address("ff02::1").multicast_mac,
            msg="Destination MAC must match the IPv6 multicast MAC derivation.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_localnet_nd_cache_hit(self) -> None:
        """
        Ensure an IPv6 on-link destination resolves via the ND cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._nd_cache.find_entry.return_value = HOST_A__MAC

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_A__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 localnet ND cache hit must enqueue with the cached MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            HOST_A__MAC,
            msg="Destination MAC must be the one returned by the ND cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_localnet_nd_cache_miss(self) -> None:
        """
        Ensure an IPv6 on-link destination is dropped when the ND cache
        has no matching entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_B__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS,
            msg="IPv6 localnet ND cache miss must drop with DST_ND_CACHE_MISS.",
        )
        self._tx_ring.enqueue.assert_not_called()

    def test__stack__packet_handler__ethernet__tx__ip6_localnet_nd_miss_enqueues_pending(self) -> None:
        """
        Ensure an IPv6 on-link destination that misses the ND cache
        also calls 'nd_cache.enqueue_pending(...)' so the dropped
        Ethernet packet can be redelivered once a Neighbor
        Advertisement resolves the destination MAC.

        Reference: RFC 1122 §2.3.2.2 (save at least one unresolved packet).
        Reference: RFC 4861 §7.2.2 (NS multicast for INCOMPLETE state).
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_B__IP6)
        self._handler._phtx_ethernet(ethernet__payload=ip6)

        self._nd_cache.enqueue_pending.assert_called_once()
        kwargs = self._nd_cache.enqueue_pending.call_args.kwargs
        self.assertEqual(
            kwargs["ip6_address"],
            HOST_B__IP6,
            msg=(
                "enqueue_pending must be keyed by the unresolved destination IP "
                "so 'add_entry' on the matching Neighbor Advertisement can find and flush it."
            ),
        )
        self.assertIs(
            kwargs["ethernet_packet_tx"].payload,
            ip6,
            msg=(
                "The queued EthernetAssembler must wrap the original IPv6 "
                "payload so the post-resolution flush re-emits the same packet."
            ),
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_uses_gateway_mac(self) -> None:
        """
        Ensure an IPv6 off-link destination resolves via the gateway MAC
        from the ND cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._nd_cache.find_entry.return_value = GATEWAY_MAC

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_C__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv6 extnet gateway ND cache hit must enqueue with the gateway MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            GATEWAY_MAC,
            msg="Destination MAC must be the gateway MAC returned by the ND cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_no_gateway(self) -> None:
        """
        Ensure an IPv6 off-link destination is dropped when the source
        host has no default gateway configured.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._if._ip6_ifaddr = [STACK__IP6_HOST__NO_GW]
        # No default route ⇒ the off-link destination has no
        # route (the post-Phase-2 "no route to host" drop).
        self._ip6_fib.remove(destination=Ip6Network("::/0"))

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST__NO_GW.address, dst=Ip6Address("2001:db8:0:ffff::1"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6,
            msg="IPv6 extnet without a gateway must drop with DST_NO_GATEWAY_IP6.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_gateway_nd_miss(self) -> None:
        """
        Ensure an IPv6 off-link destination is dropped when the gateway
        is configured but the ND cache has no entry for it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_C__IP6)
        status = self._handler._phtx_ethernet(ethernet__payload=ip6)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS,
            msg="IPv6 extnet with a gateway but ND miss must drop with DST_GATEWAY_ND_CACHE_MISS.",
        )

    def test__stack__packet_handler__ethernet__tx__ip6_extnet_gateway_nd_miss_enqueues_pending(self) -> None:
        """
        Ensure an IPv6 off-link destination whose gateway misses the ND
        cache also calls 'nd_cache.enqueue_pending(...)' keyed by the
        gateway's IPv6 address so the dropped Ethernet packet can be
        redelivered once a Neighbor Advertisement from the gateway
        resolves the gateway MAC.

        Reference: RFC 1122 §2.3.2.2 (save at least one unresolved packet).
        Reference: RFC 4861 §6.3.4 (default-router selection / gateway MAC resolution).
        """

        self._nd_cache.find_entry.return_value = None

        ip6 = _build_ip6_assembler(src=STACK__IP6_HOST.address, dst=HOST_C__IP6)
        self._handler._phtx_ethernet(ethernet__payload=ip6)

        self._nd_cache.enqueue_pending.assert_called_once()
        kwargs = self._nd_cache.enqueue_pending.call_args.kwargs
        self.assertEqual(
            kwargs["ip6_address"],
            STACK__IP6_GATEWAY,
            msg=(
                "enqueue_pending must be keyed by the gateway's IPv6 address — "
                "the unresolved next-hop, not the final destination."
            ),
        )
        self.assertIs(
            kwargs["ethernet_packet_tx"].payload,
            ip6,
            msg=(
                "The queued EthernetAssembler must wrap the original IPv6 "
                "payload so the post-resolution flush re-emits the same packet."
            ),
        )


class TestPacketHandlerEthernetTxIp4Lookup(_EthernetTxTestBase):
    """
    The IPv4-lookup path tests.
    """

    def test__stack__packet_handler__ethernet__tx__ip4_multicast_dst(self) -> None:
        """
        Ensure an IPv4 multicast destination resolves to its derived
        multicast MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=Ip4Address("224.0.0.1"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 multicast must resolve to multicast MAC and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            Ip4Address("224.0.0.1").multicast_mac,
            msg="Destination MAC must match the IPv4 multicast MAC derivation.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_limited_broadcast(self) -> None:
        """
        Ensure an IPv4 255.255.255.255 destination resolves to the
        all-ones broadcast MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=Ip4Address("255.255.255.255"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 limited broadcast must resolve to FF:FF:FF:FF:FF:FF and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            MacAddress(0xFFFFFFFFFFFF),
            msg="Destination MAC must be FF:FF:FF:FF:FF:FF for limited broadcast.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_network_broadcast(self) -> None:
        """
        Ensure an IPv4 destination equal to the source host's network
        broadcast resolves to the all-ones broadcast MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=STACK__IP4_HOST.network.broadcast)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 network broadcast must resolve to FF:FF:FF:FF:FF:FF and be enqueued.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            MacAddress(0xFFFFFFFFFFFF),
            msg="Destination MAC must be FF:FF:FF:FF:FF:FF for network broadcast.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_localnet_arp_hit(self) -> None:
        """
        Ensure an IPv4 on-link destination resolves via the ARP cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = HOST_A__MAC

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_A__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 localnet ARP cache hit must enqueue with the cached MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            HOST_A__MAC,
            msg="Destination MAC must match the ARP cache response.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_uses_injected_arp_cache(self) -> None:
        """
        Ensure IPv4 neighbor resolution consults the handler's own
        injected '_arp_cache' and never reaches through to the global
        'stack.arp_cache'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = HOST_A__MAC

        global_cache = create_autospec(ArpCache, spec_set=True)
        with patch.object(stack, "arp_cache", global_cache, create=True):
            ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_A__IP4)
            self._handler._phtx_ethernet(ethernet__payload=ip4)

        self._arp_cache.find_entry.assert_called_once_with(ip4_address=HOST_A__IP4)
        global_cache.find_entry.assert_not_called()

    def test__stack__packet_handler__ethernet__tx__ip4_localnet_arp_miss(self) -> None:
        """
        Ensure an IPv4 on-link destination is dropped when the ARP cache
        has no matching entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_B__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_ARP_CACHE_MISS,
            msg="IPv4 localnet ARP cache miss must drop with DST_ARP_CACHE_MISS.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_localnet_arp_miss_enqueues_pending(self) -> None:
        """
        Ensure an IPv4 on-link destination that misses the ARP cache
        also calls 'arp_cache.enqueue_pending(...)' so the dropped
        Ethernet packet can be redelivered once an ARP Reply
        resolves the destination MAC.

        Reference: RFC 1122 §2.3.2.2 (save at least one unresolved packet).
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_B__IP4)
        self._handler._phtx_ethernet(ethernet__payload=ip4)

        self._arp_cache.enqueue_pending.assert_called_once()
        kwargs = self._arp_cache.enqueue_pending.call_args.kwargs
        self.assertEqual(
            kwargs["ip4_address"],
            HOST_B__IP4,
            msg=(
                "enqueue_pending must be keyed by the unresolved destination IP "
                "so 'add_entry' on the matching ARP Reply can find and flush it."
            ),
        )
        self.assertIs(
            kwargs["ethernet_packet_tx"].payload,
            ip4,
            msg=(
                "The queued EthernetAssembler must wrap the original IPv4 "
                "payload so the post-resolution flush re-emits the same packet."
            ),
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_uses_gateway_mac(self) -> None:
        """
        Ensure an IPv4 off-link destination resolves via the gateway MAC
        from the ARP cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = GATEWAY_MAC

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_C__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="IPv4 extnet gateway ARP cache hit must enqueue with the gateway MAC.",
        )
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.dst,
            GATEWAY_MAC,
            msg="Destination MAC must be the gateway MAC returned by the ARP cache.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_no_gateway(self) -> None:
        """
        Ensure an IPv4 off-link destination is dropped when the source
        host has no default gateway configured.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._if._ip4_ifaddr = [STACK__IP4_HOST__NO_GW]
        # No default route ⇒ the off-link destination has no
        # route (the post-Phase-2 "no route to host" drop).
        self._ip4_fib.remove(destination=Ip4Network("0.0.0.0/0"))

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST__NO_GW.address, dst=Ip4Address("10.10.10.10"))
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4,
            msg="IPv4 extnet without a gateway must drop with DST_NO_GATEWAY_IP4.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_gateway_arp_miss(self) -> None:
        """
        Ensure an IPv4 off-link destination is dropped when the gateway
        is configured but the ARP cache has no entry for it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_C__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=ip4)

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            msg="IPv4 extnet with a gateway but ARP miss must drop with DST_GATEWAY_ARP_CACHE_MISS.",
        )

    def test__stack__packet_handler__ethernet__tx__ip4_extnet_gateway_arp_miss_enqueues_pending(self) -> None:
        """
        Ensure an IPv4 off-link destination whose gateway misses the
        ARP cache calls 'arp_cache.enqueue_pending(...)' keyed by the
        gateway IP (not the off-subnet destination IP) so the
        dropped Ethernet packet can be redelivered once the
        gateway's MAC has been resolved.

        Reference: RFC 1122 §2.3.2.2 (save at least one unresolved packet).
        """

        self._arp_cache.find_entry.return_value = None

        ip4 = _build_ip4_assembler(src=STACK__IP4_HOST.address, dst=HOST_C__IP4)
        self._handler._phtx_ethernet(ethernet__payload=ip4)

        self._arp_cache.enqueue_pending.assert_called_once()
        kwargs = self._arp_cache.enqueue_pending.call_args.kwargs
        self.assertEqual(
            kwargs["ip4_address"],
            STACK__IP4_GATEWAY,
            msg=(
                "enqueue_pending for an off-subnet destination must be keyed by "
                "the gateway IP — that's the IP the future ARP Reply resolves, "
                f"not the original packet's IP destination ({HOST_C__IP4})."
            ),
        )
        self.assertIs(
            kwargs["ethernet_packet_tx"].payload,
            ip4,
            msg=(
                "The queued EthernetAssembler must wrap the original IPv4 "
                "payload so the post-resolution flush re-emits the same packet."
            ),
        )

    def test__stack__packet_handler__ethernet__tx__ip4_frag_payload_routes_like_ip4(self) -> None:
        """
        Ensure an 'Ip4FragAssembler' payload goes through the same IPv4
        routing logic as a plain 'Ip4Assembler' — the handler treats
        both the same way.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._arp_cache.find_entry.return_value = HOST_A__MAC

        frag = Ip4FragAssembler(ip4_frag__src=STACK__IP4_HOST.address, ip4_frag__dst=HOST_A__IP4)
        status = self._handler._phtx_ethernet(ethernet__payload=frag)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Ip4FragAssembler payload must route via the IPv4 ARP path.",
        )
