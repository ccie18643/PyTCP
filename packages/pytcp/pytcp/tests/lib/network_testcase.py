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
This module contains base testcase for PyTCP Packet Handler tests.

pytcp/tests/lib/network_testcase.py

ver 3.0.8
"""

from typing import Any, cast, override
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
from net_proto.lib.buffer import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.protocols.ip6 import ip6__constants as ip6__constants_module
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.packet_handler import (
    PacketHandlerL2,
    PacketHandlerL3,
    packet_handler__ip6_frag__tx,
)
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.timer import Timer
from pytcp.runtime.tx_ring import TxRing
from pytcp.tests.lib.fake_timer import FakeTimer

# # #  IPv4
#
#           .7  10.0.1.0/24  .1          .1  10.0.2.0/24  .50
#   [STACK] ------------------- [ROUTER] -------------------- [HOST C]
#             |
#             |   .91
#             |------ [HOST A] (working arp cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working arp cache resolution)
#

# # #  IPv6
#
#        .7  2001:db8:0:1::/64  .1    .1  2001:db8:0:2::/64  .50
#        .7  fe80::/64          .1    .1  fe80::             .50
#   [STACK] ------------------- [ROUTER A] -------------------- [HOST C]
#             |
#             |    .2
#             |------ [ROUTER B] (not working nd cache resolution)
#             |
#             |   .91
#             |------ [HOST A] (working nd cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working nd cache resolution)
#

# Set the PyTCP stack candidate addressing for DAD tests.
STACK__IP4_HOST__CANDIDATE = Ip4IfAddr("10.0.1.5/24")
STACK__IP6_HOST__CANDIDATE = Ip6IfAddr("2001:db8:0:1::5/64")

# Set the PyTCP stack addressing.
STACK__MAC_ADDRESS = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK__IP4_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")
STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")
STACK__IP6_GATEWAY = Ip6Address("fe80::1")
STACK__IP6_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

# Set the test device's addressing.
HOST_A__MAC_ADDRESS = MacAddress("02:00:00:00:00:91")
HOST_A__IP4_ADDRESS = Ip4Address("10.0.1.91")
HOST_A__IP6_ADDRESS = Ip6Address("2001:db8:0:1::91")
HOST_B__IP4_ADDRESS = Ip4Address("10.0.1.92")
HOST_B__IP6_ADDRESS = Ip6Address("2001:db8:0:1::92")
HOST_C__IP4_ADDRESS = Ip4Address("10.0.2.50")
HOST_C__IP6_ADDRESS = Ip6Address("2001:db8:0:2::50")
ROUTER_B__IP6_ADDRESS = Ip6Address("fe80::2")

# Set common addresses.
MAC__UNSPECIFIED = MacAddress("00:00:00:00:00:00")
MAC__BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")
IP4__UNSPECIFIED = Ip4Address("0.0.0.0")
IP4__BROADCAST__LIMITED = Ip4Address("255.255.255.255")
IP4__MULTICAST__ALL_NODES = Ip4Address("224.0.0.1")
IP6__UNSPECIFIED = Ip6Address("::")
IP6__MULTICAST__ALL_NODES = Ip6Address("ff02::1")
IP6__MULTICAST__ALL_ROUTERS = Ip6Address("ff02::2")
IP6__MULTICAST__MLD2_ROUTERS = Ip6Address("ff02::16")

# Pre-populated address tables consumed by the mocked 'find_entry'
# dispatchers. Unknown lookups raise to preserve the strict-mock
# semantics the original testslide harness enforced.
_ARP_CACHE__FIND_ENTRY__TABLE: dict[Ip4Address, MacAddress | None] = {
    HOST_A__IP4_ADDRESS: HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS: None,
    STACK__IP4_GATEWAY: STACK__IP4_GATEWAY_MAC_ADDRESS,
}
_ND_CACHE__FIND_ENTRY__TABLE: dict[Ip6Address, MacAddress | None] = {
    HOST_A__IP6_ADDRESS: HOST_A__MAC_ADDRESS,
    HOST_B__IP6_ADDRESS: None,
    STACK__IP6_GATEWAY: STACK__IP6_GATEWAY_MAC_ADDRESS,
    ROUTER_B__IP6_ADDRESS: None,
}

# Stack globals that 'NetworkTestCase.setUp' patches and
# 'NetworkTestCase.tearDown' restores. Stored as a list so the
# snapshot is taken in a stable order.
_STACK__PATCHED_ATTRS: tuple[str, ...] = (
    "LOG__CHANNEL",
    "IP6__SUPPORT",
    "IP4__SUPPORT",
    "IP4__ACCEPT_SOURCE_ROUTE",
    "INTERFACE__TAP__MTU",
    "INTERFACE__TUN__MTU",
    "UDP__ECHO_NATIVE",
    "link_local",
    "stack_running",
)


class AddedInterface:
    """
    Handle to an extra interface installed by
    'NetworkTestCase._add_interface' — the multi-homed-host test
    affordance. Exposes the per-interface packet handler, the list of
    frames that interface has emitted (its own mocked TX ring records
    into it), and a 'drive_rx' that feeds an inbound frame into THIS
    interface and returns the frames it produced in response.
    """

    def __init__(self, *, handler: PacketHandlerL2, frames_tx: list[bytes]) -> None:
        self.handler = handler
        self.frames_tx = frames_tx

    @property
    def ifindex(self) -> int:
        """
        Return the registry index this interface was allocated.
        """

        return self.handler._ifindex

    def drive_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into this interface's handler and return the TX
        frames it produced as a direct result.
        """

        before = len(self.frames_tx)
        self.handler._phrx_ethernet(PacketRx(frame))
        return list(self.frames_tx[before:])


class NetworkTestCase(TestCase):
    """
    Base class for all unit tests that require mock network.
    """

    _frames_tx: list[bytes]

    _packet_handler: PacketHandlerL2
    # The boot interface's mocked neighbor caches (also bound to
    # '_packet_handler._arp_cache' / '._nd_cache'). Typed 'Any' so tests
    # can assert on the autospec mock surface ('confirm_reachability',
    # 'reset_mock', 'find_entry.side_effect') without per-call casts.
    _arp_cache: Any
    _nd_cache: Any

    _stack__attr_snapshot: dict[str, object]
    _ip6_flow_label_generation_prior: int
    _interfaces_snapshot: dict[int, PacketHandlerL2 | PacketHandlerL3]
    _packet_sockets_prior: list[Any]
    _sockets_prior: dict[Any, Any]
    _icmp_echo_sockets_prior: dict[Any, Any]
    _timer: FakeTimer
    _timer_prior: Timer | None

    @override
    def setUp(self) -> None:
        """
        Prepare the test case.
        """

        self.maxDiff = None

        super().setUp()

        # Snapshot the stack globals we are about to mutate so
        # 'tearDown' can restore them and avoid leaking test-only
        # values (e.g. an empty 'LOG__CHANNEL') into unrelated tests.
        self._stack__attr_snapshot = {name: stack.__dict__[name] for name in _STACK__PATCHED_ATTRS}

        # Snapshot the RFC 6437 flow-label generation toggle so
        # 'tearDown' restores production behaviour (default 1 —
        # auto-emit). The harness pins it to 0 for the duration
        # of each test so existing golden-frame fixtures (which
        # encode flow=0 in their IPv6 header word) continue to
        # match without per-fixture regeneration. A dedicated
        # integration test
        # ('test__ip6__rfc6437_flow_label.py') flips this back
        # to 1 inside its own setUp to exercise the auto-wire.
        self._ip6_flow_label_generation_prior = ip6__constants_module.IP6__FLOW_LABEL_GENERATION
        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = 0

        # Patch the PyTCP stack settings to values suitable for unit tests.
        stack.__dict__.update(
            {
                "LOG__CHANNEL": set(),
                "IP6__SUPPORT": True,
                "IP4__SUPPORT": True,
                "INTERFACE__TAP__MTU": 1500,
                "INTERFACE__TUN__MTU": 1500,
                "UDP__ECHO_NATIVE": True,
            }
        )

        # Create mock Packet Handler object and prepare it for tests.

        def _mock_enqueue(packet_tx: EthernetAssembler) -> None:
            """
            Mock 'TxRing.enqueue()' method to record the assembled frames.
            """

            buffers: list[Buffer] = []
            packet_tx.assemble(buffers)
            frame_tx = b"".join(buffers)

            self.assertEqual(
                frame_tx,
                bytes(packet_tx),
                msg="TxRing mock: 'assemble()' output must equal 'bytes(packet_tx)'.",
            )

            self._frames_tx.append(frame_tx)

        # Mock the TxRing so we can record the assembled frames.
        mock_TxRing = create_autospec(TxRing, spec_set=True)
        mock_TxRing.enqueue.side_effect = _mock_enqueue
        # 'dispatch' is the ring-handoff marshaling boundary; with no
        # real worker thread under test, run the marshaled '_phtx_*'
        # callable inline so frames land in the mocked 'enqueue' above
        # and the caller still sees the real 'TxStatus'.
        mock_TxRing.dispatch.side_effect = lambda run: run()
        # Phase 4b fire-and-forget marshaling boundary — run the
        # callable inline (discard the result) so async sends still
        # land frames in the mocked 'enqueue' under test.
        mock_TxRing.dispatch_async.side_effect = lambda run: run()

        # Mock the ArpCache so we can get predictable responses.
        def _mock_arp_find_entry(*, ip4_address: Ip4Address) -> MacAddress | None:
            """
            Mock 'ArpCache.find_entry()' — dispatch on 'ip4_address' via
            the pre-populated table; raise on unknown keys.
            """

            if ip4_address not in _ARP_CACHE__FIND_ENTRY__TABLE:
                raise AssertionError(f"Unexpected 'ArpCache.find_entry' call. Got: {ip4_address=}")

            return _ARP_CACHE__FIND_ENTRY__TABLE[ip4_address]

        mock_ArpCache = create_autospec(ArpCache, spec_set=True)
        mock_ArpCache.find_entry.side_effect = _mock_arp_find_entry
        mock_ArpCache.add_entry.return_value = None

        # Mock the NdCache so we can get predictable responses.
        def _mock_nd_find_entry(*, ip6_address: Ip6Address) -> MacAddress | None:
            """
            Mock 'NdCache.find_entry()' — dispatch on 'ip6_address' via
            the pre-populated table; raise on unknown keys.
            """

            if ip6_address not in _ND_CACHE__FIND_ENTRY__TABLE:
                raise AssertionError(f"Unexpected 'NdCache.find_entry' call. Got: {ip6_address=}")

            return _ND_CACHE__FIND_ENTRY__TABLE[ip6_address]

        mock_NdCache = create_autospec(NdCache, spec_set=True)
        mock_NdCache.find_entry.side_effect = _mock_nd_find_entry
        mock_NdCache.add_entry.return_value = None

        # Expose the boot interface's neighbor-cache mocks as harness
        # handles so tests assert on the egress interface's own caches
        # ('_packet_handler._{arp,nd}_cache', which 'mock__init' binds to
        # these same objects) instead of the retired 'stack.{arp,nd}_cache'
        # singletons.
        self._arp_cache = mock_ArpCache
        self._nd_cache = mock_NdCache

        # Prepare PacketHandler object to be used with the tests.
        self._packet_handler = PacketHandlerL2(
            mac_address=STACK__MAC_ADDRESS,
            interface_mtu=1500,
        )

        self._packet_handler._mac_multicast = [STACK__IP6_HOST.address.solicited_node_multicast.multicast_mac]
        self._packet_handler._ip4_ifaddr = [STACK__IP4_HOST]
        self._packet_handler._ip4_multicast_filters = {
            IP4__MULTICAST__ALL_NODES: Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE)
        }
        self._packet_handler._ip6_ifaddr = [STACK__IP6_HOST]
        self._packet_handler._ip6_multicast = [
            IP6__MULTICAST__ALL_NODES,
            STACK__IP6_HOST.address.solicited_node_multicast,
        ]
        self._packet_handler._ip4_ifaddr_candidate = [STACK__IP4_HOST__CANDIDATE]
        self._packet_handler._ip6_ifaddr_candidate = [STACK__IP6_HOST__CANDIDATE]

        # Initialize the list holding the frames "sent" by mock TxRing.
        self._frames_tx = []

        # Install an inert 'FakeTimer' as the shared 'stack.timer' so the
        # event-driven scheduling paths (IGMP/MLD state-change retransmit,
        # the IGMP query-response timer, TCP timers) resolve a Timer here
        # exactly as in a started stack, instead of branching on its
        # absence. The FakeTimer spawns no thread and fires nothing until
        # a test advances it, so it is invisible to tests that never do.
        # 'IcmpTestCase' overrides this with its own advanceable FakeTimer
        # via a second 'mock__init'.
        self._timer_prior = stack.__dict__.get("timer")
        self._timer = FakeTimer()
        # Restore the shared 'stack.timer' via addCleanup (registered
        # here, before any test-body 'addCleanup(socket.close)') so it
        # runs LAST in LIFO cleanup order — a socket close fired in
        # cleanup still reaches a live Timer through the IGMP/MLD leave +
        # compatibility-mode paths. (tearDown runs before doCleanups, so
        # restoring there would strand those close callbacks.)
        self.addCleanup(self._restore_stack_timer)

        stack.mock__init(
            mock__tx_ring=cast(TxRing, mock_TxRing),
            mock__arp_cache=cast(ArpCache, mock_ArpCache),
            mock__nd_cache=cast(NdCache, mock_NdCache),
            mock__packet_handler=self._packet_handler,
            mock__timer=cast(Timer, self._timer),
        )

        # Pre-install the fixture default routes (STACK gateways)
        # so the topology has a next hop for off-link traffic.
        # 'mock__init' rebuilt the two FIBs
        # fresh (empty) on the line above, so this install runs
        # once per test with no leak and needs no tearDown
        # restore (same lifecycle as the mocked packet handler /
        # address / link singletons). The harness installs into
        # the FIB directly — the Route API mutation surface
        # (Phase 3) does not exist yet; this mirrors the existing
        # 'packet_handler._ip4_ifaddr = [...]' scaffolding.
        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=STACK__IP4_GATEWAY,
                protocol=RouteProtocol.BOOT,
            )
        )
        stack.ip6_fib.add(
            route=Route(
                destination=Ip6Network("::/0"),
                gateway=STACK__IP6_GATEWAY,
                protocol=RouteProtocol.BOOT,
            )
        )

        # Override the production RFC 7739 random Fragment ID
        # generator with a deterministic counter so fixture-
        # based fragmentation tests can assert specific
        # Identification field values. Each call returns 1, 2,
        # 3, ..., matching the legacy monotonic-counter
        # behaviour the existing fixtures were authored
        # against.
        self._frag_id_counter: list[int] = [0]

        def _det_frag_id() -> int:
            self._frag_id_counter[0] += 1
            return self._frag_id_counter[0]

        self._frag_id_patch = patch.object(
            packet_handler__ip6_frag__tx,
            "_generate_ip6_frag_id",
            side_effect=_det_frag_id,
        )
        self._frag_id_patch.start()

        # Snapshot the interface registry (just the boot interface that
        # 'mock__init' installed) so any extra interface a test adds via
        # '_add_interface' is removed in 'tearDown' and cannot leak into
        # a sibling test (§5.4 module-state-on-touch).
        self._interfaces_snapshot = dict(stack.interfaces)

        # Snapshot + clear the process-wide AF_PACKET socket registry so
        # a packet socket a test binds (and the RX tap delivers to) does
        # not leak into a sibling test, and so a leaked registration from
        # an earlier unit test cannot make this test's tap deliver to a
        # stale socket (§5.4 module-state-on-touch).
        self._packet_sockets_prior = stack.packet_sockets.snapshot()
        stack.packet_sockets.clear()

        # Snapshot + clear the process-wide TCP/UDP socket table. It is a
        # module-level singleton that 'mock__init' does NOT rebuild, so a
        # socket a test binds (and any port it holds) would otherwise
        # accumulate across the run and make a later explicit 'bind' to the
        # same port fail — an order-dependent flake (§5.4
        # module-state-on-touch).
        self._sockets_prior = dict(stack.sockets)
        stack.sockets.clear()

        # Snapshot + clear the process-wide ICMP Echo ('ping') socket
        # registry for the same reason (§5.4 module-state-on-touch).
        self._icmp_echo_sockets_prior = dict(stack.icmp_echo_sockets)
        stack.icmp_echo_sockets.clear()

    def _add_interface(
        self,
        *,
        mac_address: MacAddress,
        ip4_host: Ip4IfAddr | None = None,
        ip6_host: Ip6IfAddr | None = None,
        arp_entries: dict[Ip4Address, MacAddress | None] | None = None,
        nd_entries: dict[Ip6Address, MacAddress | None] | None = None,
        interface_mtu: int = 1500,
    ) -> AddedInterface:
        """
        Install an additional L2 interface alongside the boot interface
        — the multi-homed-host (N>1) test affordance. Builds a real
        'PacketHandlerL2' with its OWN mocked TX ring (recording into a
        per-interface frame list), its own ARP / ND caches driven by the
        supplied 'arp_entries' / 'nd_entries' tables (unknown lookups
        raise, matching the boot interface's strict-mock semantics), and
        the supplied addresses; registers it in 'stack.interfaces' under
        a freshly allocated ifindex. Returns an 'AddedInterface' handle.
        The registry is restored in 'tearDown' from the setUp snapshot.
        """

        frames_tx: list[bytes] = []

        def _enqueue(packet_tx: EthernetAssembler) -> None:
            buffers: list[Buffer] = []
            packet_tx.assemble(buffers)
            frames_tx.append(b"".join(buffers))

        mock_tx_ring = create_autospec(TxRing, spec_set=True)
        mock_tx_ring.enqueue.side_effect = _enqueue
        mock_tx_ring.dispatch.side_effect = lambda run: run()
        mock_tx_ring.dispatch_async.side_effect = lambda run: run()

        # RX is injected directly via 'drive_rx' (calling '_phrx_ethernet'),
        # never read off this ring — but a real interface owns one, and
        # 'remove_interface' / '_stop_interface' assert its presence, so a
        # fully-shaped interface needs the (otherwise inert) mock here.
        mock_rx_ring = create_autospec(RxRing, spec_set=True)

        arp_table = dict(arp_entries or {})

        def _arp_find(*, ip4_address: Ip4Address) -> MacAddress | None:
            if ip4_address not in arp_table:
                raise AssertionError(f"Unexpected 'ArpCache.find_entry' call. Got: {ip4_address=}")
            return arp_table[ip4_address]

        mock_arp_cache = create_autospec(ArpCache, spec_set=True)
        mock_arp_cache.find_entry.side_effect = _arp_find
        mock_arp_cache.add_entry.return_value = None

        nd_table = dict(nd_entries or {})

        def _nd_find(*, ip6_address: Ip6Address) -> MacAddress | None:
            if ip6_address not in nd_table:
                raise AssertionError(f"Unexpected 'NdCache.find_entry' call. Got: {ip6_address=}")
            return nd_table[ip6_address]

        mock_nd_cache = create_autospec(NdCache, spec_set=True)
        mock_nd_cache.find_entry.side_effect = _nd_find
        mock_nd_cache.add_entry.return_value = None

        handler = PacketHandlerL2(mac_address=mac_address, interface_mtu=interface_mtu)
        handler._ip4_ifaddr = [ip4_host] if ip4_host is not None else []
        handler._ip4_multicast_filters = {IP4__MULTICAST__ALL_NODES: Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE)}
        handler._ip6_ifaddr = [ip6_host] if ip6_host is not None else []
        if ip6_host is not None:
            handler._mac_multicast = [ip6_host.address.solicited_node_multicast.multicast_mac]
            handler._ip6_multicast = [
                IP6__MULTICAST__ALL_NODES,
                ip6_host.address.solicited_node_multicast,
            ]
        handler._tx_ring = cast(TxRing, mock_tx_ring)
        handler._rx_ring = cast(RxRing, mock_rx_ring)
        handler._arp_cache = cast(ArpCache, mock_arp_cache)
        handler._nd_cache = cast(NdCache, mock_nd_cache)
        handler._route_api = stack.route

        # 'add' allocates the next free ifindex (boot interface is 1) and
        # stamps it onto the handler, under the registry lock.
        stack.interfaces.add(handler)

        return AddedInterface(handler=handler, frames_tx=frames_tx)

    @override
    def tearDown(self) -> None:
        """
        Restore the stack globals patched in 'setUp' so test-only
        values do not leak into unrelated tests run in the same
        process.
        """

        self._frag_id_patch.stop()

        # Drop any interface a test added via '_add_interface', restoring
        # the registry to the boot-interface-only snapshot from setUp.
        stack.interfaces.clear()
        stack.interfaces.update(self._interfaces_snapshot)

        # Restore the AF_PACKET socket registry to its pre-test snapshot.
        stack.packet_sockets.clear()
        for packet_sock in self._packet_sockets_prior:
            stack.packet_sockets.register(packet_sock)

        # Restore the TCP/UDP socket table to its pre-test snapshot.
        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

        # Restore the ICMP Echo ('ping') socket registry.
        stack.icmp_echo_sockets.clear()
        stack.icmp_echo_sockets.update(self._icmp_echo_sockets_prior)

        stack.__dict__.update(self._stack__attr_snapshot)

        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = self._ip6_flow_label_generation_prior

        super().tearDown()

    def _restore_stack_timer(self) -> None:
        """
        Restore (or remove) the shared 'stack.timer' installed in setUp
        so the FakeTimer does not leak into unrelated tests. Runs via
        'addCleanup' (after tearDown and after any test-body socket-close
        cleanups) so a close fired in cleanup still reaches a live Timer.
        """

        if self._timer_prior is None:
            stack.__dict__.pop("timer", None)
        else:
            stack.timer = self._timer_prior
