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
Stack lifecycle module — owns the init / start / stop /
mock__init entry points. Extracted from
'pytcp/stack/__init__.py' (Phase 2 of the directory restructure
at 'docs/refactor/pytcp_directory_restructure.md') so the
sibling 'pytcp/stack/__init__.py' shrinks to constants +
singleton declarations + interface helpers.

The lifecycle functions read and write the module-level
singletons that still live on 'pytcp.stack' via
'import pytcp.stack as _stack; _stack.X = Y'. Same pattern
the test harness uses for snapshot/restore.

pytcp/stack/lifecycle.py

ver 3.0.10
"""

from typing import Any

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx, PacketStatsTx
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.dhcp6.dhcp6__client import Dhcp6Client
from pytcp.protocols.dns.dns__resolver import DnsResolver
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.runtime.fib import RouteTable
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import (
    PacketHandlerL2,
    PacketHandlerL3,
    PacketHandlerLoopback,
)
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.timer import Timer
from pytcp.runtime.tx_ring import TxRing
from pytcp.stack.activity_introspect import ActivityIntrospectApi
from pytcp.stack.address import AddressApi
from pytcp.stack.link import LinkApi
from pytcp.stack.membership import MembershipApi
from pytcp.stack.membership6 import Membership6Api
from pytcp.stack.neighbor import NeighborApi
from pytcp.stack.resolver import ResolverApi
from pytcp.stack.route import RouteApi, install_boot_default_routes
from pytcp.stack.socket_introspect import SocketIntrospectApi


def mock__init(
    *,
    mock__timer: Timer | None = None,
    mock__tx_ring: TxRing | None = None,
    mock__rx_ring: RxRing | None = None,
    mock__arp_cache: ArpCache | None = None,
    mock__nd_cache: NdCache | None = None,
    mock__packet_handler: PacketHandlerL2 | None = None,
    mock__address: AddressApi | None = None,
    mock__link: LinkApi | None = None,
    mock__route: RouteApi | None = None,
    mock__dhcp4_client: Dhcp4Client | None = None,
    mock__dhcp6_client: Dhcp6Client | None = None,
    mock__loopback: bool = False,
) -> None:
    """
    Initialize stack components for unit testing.

    'mock__loopback' opts a test into a real loopback interface
    registered in 'stack.interfaces' alongside the mocked boot handler —
    off by default so the broad harness suite is unaffected by the extra
    interface. The integration harness registers 'lo' via its own
    '_register_loopback' helper instead (after snapshotting the registry
    so tearDown removes it).
    """

    import pytcp.stack as _stack

    # Reset the Link API running flag per test so it does not
    # leak from a prior test that called 'stack.start()'. The
    # unit test corpus does not normally call start/stop, so
    # the default 'False' is the right reset value.
    _stack.stack_running = False

    if mock__timer is not None:
        _stack.timer = mock__timer

    if mock__packet_handler is not None:
        # Inject the RX / TX rings into the handler the same way the
        # real 'init()' does, so a test exercising the loop /
        # send-out paths through 'mock__init' dequeues from / enqueues
        # onto the handler's own rings. Harness tests that drive RX via
        # '_phrx_ethernet' directly don't pass 'mock__rx_ring' and leave
        # that None; the TX harness passes 'mock__tx_ring' and asserts on
        # its recorded frames.
        mock__packet_handler.attach_rings(rx_ring=mock__rx_ring, tx_ring=mock__tx_ring)
        # Bind the per-interface neighbor caches to the handler the
        # same way 'init()' does (both directions), so the RX/TX
        # cache lookups go through the handler's own caches and the
        # caches' solicit / flush callbacks route back through the
        # owning handler rather than the global shims. 'attach_caches'
        # requires the ND cache (always present in production); when a
        # narrow test passes only the ARP cache, bind it on its own.
        if mock__nd_cache is not None:
            mock__packet_handler.attach_caches(
                arp_cache=mock__arp_cache,
                nd_cache=mock__nd_cache,
                iface_name=None,
            )
        elif mock__arp_cache is not None:
            mock__packet_handler.attach_arp_cache(mock__arp_cache)
        # Register the handler in the per-ifindex interface registry
        # keyed by its own ifindex (default 1 for the harness's sole
        # interface). Only when a handler is passed — a timer-only
        # 'mock__init' (e.g. IcmpTestCase's second call) must NOT wipe
        # the registry the first call populated. Rebuild the table fresh
        # (same reconstruct-per-test lifecycle as the FIBs below) and
        # place the handler at its own ifindex.
        _interfaces = InterfaceTable(first_ifindex=_stack.STACK__DEFAULT_IFINDEX)
        _interfaces[mock__packet_handler.ifindex] = mock__packet_handler
        _stack.interfaces = _interfaces

    # Phase 4 commit A — the Address API. If the test harness
    # passes a packet_handler, also build a default Address API
    # over it (tests that need to mock the API itself can pass
    # 'mock__address' explicitly).
    if mock__address is not None:
        _stack.address = mock__address
    elif mock__packet_handler is not None:
        _stack.address = AddressApi(packet_handler=mock__packet_handler)

    # Link API Phase 0 — same pattern as 'address'. Tests get a
    # default 'LinkApi' bound to the mocked packet handler so
    # consumer code reading 'stack.link.mac_address' works in
    # isolation without bespoke harness wiring.
    if mock__link is not None:
        _stack.link = mock__link
    elif mock__packet_handler is not None:
        _stack.link = LinkApi(packet_handler=mock__packet_handler)

    # Neighbor API — same pattern as 'address' / 'link'. A default
    # 'NeighborApi' bound to the mocked handler lets consumer code
    # reading 'stack.neighbor.*' work in isolation without bespoke
    # harness wiring.
    if mock__packet_handler is not None:
        _stack.neighbor = NeighborApi(packet_handler=mock__packet_handler)

    # Membership API — same pattern as 'address' / 'link' /
    # 'neighbor'. A default 'MembershipApi' bound to the mocked
    # handler lets consumer code reading 'stack.membership.*' work in
    # isolation without bespoke harness wiring.
    if mock__packet_handler is not None:
        _stack.membership = MembershipApi(packet_handler=mock__packet_handler)

    # IPv6 Membership API — same pattern as 'membership'. A default
    # 'Membership6Api' bound to the mocked handler lets consumer code
    # reading 'stack.membership6.*' work in isolation.
    if mock__packet_handler is not None:
        _stack.membership6 = Membership6Api(packet_handler=mock__packet_handler)

    # Resolver API — DNS resolution control surface. Created
    # unconditionally (it needs no packet handler, only an upstream
    # server) and rebuilt every 'mock__init', so it needs no
    # snapshot/restore; tests exercising resolution inject a fake
    # resolver into 'stack.resolver'.
    _stack.resolver = ResolverApi(resolver=DnsResolver(server=_stack.STACK__DNS_SERVER))

    # Socket introspection API — stateless, reads the global socket table
    # at call time; rebuilt every 'mock__init'.
    _stack.ss = SocketIntrospectApi()
    _stack.activity = ActivityIntrospectApi()

    # Host-mode routing table — Phase 1. Rebuild the two FIBs
    # fresh every 'mock__init' (i.e. every harness 'setUp') so
    # route state cannot leak across the suite; same reconstruct-
    # per-test lifecycle as 'timer' / 'address' / 'link', which
    # is why the FIBs need no snapshot/restore entry. The
    # integration harness installs the fixture default routes
    # after this call; unit tests get clean empty FIBs.
    ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
    ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
    _stack.ip4_fib = ip4_fib
    _stack.ip6_fib = ip6_fib
    if mock__route is not None:
        _stack.route = mock__route
    else:
        _stack.route = RouteApi(ip4_fib=ip4_fib, ip6_fib=ip6_fib)

    # Inject the routing-control API into every registered interface the
    # same way 'init()' does, so the RX RA path drives the default route
    # through it. 'mock__init' rebuilds 'stack.route' on EVERY call (e.g.
    # 'IcmpTestCase' calls it a second time, timer-only), so re-inject
    # into whatever interfaces are currently registered — not just the
    # one passed this call — otherwise a handler keeps a stale RouteApi
    # wrapping the previous FIBs.
    for _registered_handler in _stack.interfaces.values():
        _registered_handler.attach_route_api(_stack.route)

    # Phase 4 commit B — DHCPv4 lifecycle. Default to None unless
    # the harness explicitly opts in; existing tests (NetworkTestCase
    # et al.) don't exercise the lifecycle and don't need a fake.
    _stack.dhcp4_client = mock__dhcp4_client
    # DHCPv6 lifecycle (RFC 8415). Default None — the harness opts in
    # via 'mock__dhcp6_client'; the RA-trigger integration tests inject
    # a client directly on the packet handler instead.
    _stack.dhcp6_client = mock__dhcp6_client

    # RFC 3927 Phase 1 — link-local autoconfig client slot. Default
    # None for unit tests; the link-local subsystem is exercised
    # through its own unit tests, not through the integration
    # harness in Phase 1.
    _stack.link_local = None

    # Opt-in loopback interface (off by default so the broad harness
    # suite is unaffected). Build a fresh registry first when no boot
    # handler was passed, so 'lo' is not appended to a stale table.
    if mock__loopback:
        if mock__packet_handler is None:
            _stack.interfaces = InterfaceTable(first_ifindex=_stack.STACK__DEFAULT_IFINDEX)
        _add_loopback()


def add_interface(
    *,
    fd: int,
    layer: InterfaceLayer,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    interface_name: str | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip4_dhcp: bool = False,
    ip4_link_local: bool = False,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    ip6_gua_autoconfig: bool = False,
    ip6_lla_autoconfig: bool = True,
) -> int:
    """
    Construct one network interface — its fd-bound RX / TX rings,
    its per-ifindex neighbor cache(s) and its packet handler —
    register it in 'stack.interfaces' under a freshly allocated
    ifindex, and return that ifindex.

    The handler instance IS the interface: it owns the injected
    rings and the ARP / ND caches (Linux keys neighbors per
    ifindex). The first interface added takes 'STACK__DEFAULT_IFINDEX'
    and also populates the N=1 back-compat singletons
    'stack.packet_handler' / 'rx_ring' / 'tx_ring' / 'arp_cache' /
    'nd_cache' (retired in a later phase); subsequent interfaces get
    the next free index and leave those shims on the boot interface.

    'init()' calls this once for the boot interface; the runtime
    multi-interface path calls it again once N>1 is enabled.
    """

    import pytcp.stack as _stack

    # Per-interface stats — each interface's rings + handler share
    # one set, so ring drop counters and per-protocol counters land
    # on a single dataclass per interface for unified-stats consumers.
    packet_stats_rx = PacketStatsRx()
    packet_stats_tx = PacketStatsTx()
    link_stats = LinkStatsCounters()

    tx_ring = TxRing(fd=fd, mtu=mtu, packet_stats=packet_stats_tx, link_stats=link_stats)
    rx_ring = RxRing(fd=fd, mtu=mtu, packet_stats=packet_stats_rx, link_stats=link_stats)
    nd_cache = NdCache()
    arp_cache: ArpCache | None = None

    packet_handler: PacketHandlerL2 | PacketHandlerL3
    match layer:
        case InterfaceLayer.L2:
            assert mac_address is not None, "MAC address must be provided for Layer 2 (TAP) interface."
            arp_cache = ArpCache()
            packet_handler = PacketHandlerL2(
                mac_address=mac_address,
                interface_mtu=mtu,
                interface_name=interface_name,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip4_dhcp=ip4_dhcp,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                ip6_gua_autoconfig=ip6_gua_autoconfig,
                ip6_lla_autoconfig=ip6_lla_autoconfig,
                rx_ring=rx_ring,
                tx_ring=tx_ring,
                packet_stats_rx=packet_stats_rx,
                packet_stats_tx=packet_stats_tx,
                link_stats=link_stats,
            )
            # Bind the per-interface neighbor caches to this handler and
            # the reverse owner back-reference so the caches' solicit /
            # flush callbacks route through this interface. ARP is
            # L2-only; ND is used by both layers. The interface name
            # plumbs into each cache's per-iface 'neighbor.<ifname>.*'
            # sysctl resolution path.
            packet_handler.attach_caches(arp_cache=arp_cache, nd_cache=nd_cache, iface_name=interface_name)
        case InterfaceLayer.L3:
            assert mac_address is None, "MAC address must NOT be provided for Layer 3 (TUN) interface."
            packet_handler = PacketHandlerL3(
                interface_mtu=mtu,
                interface_name=interface_name,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                rx_ring=rx_ring,
                tx_ring=tx_ring,
                packet_stats_rx=packet_stats_rx,
                packet_stats_tx=packet_stats_tx,
                link_stats=link_stats,
            )
            # L3 (TUN) has no ARP; bind only the ND cache + its owner.
            packet_handler.attach_caches(arp_cache=None, nd_cache=nd_cache, iface_name=interface_name)

    # Tag each per-interface subsystem's worker thread with the interface
    # name, so every message it logs while processing this NIC's traffic
    # carries the interface in the log's interface column.
    if interface_name is not None:
        rx_ring.set_log_interface(interface_name)
        tx_ring.set_log_interface(interface_name)
        nd_cache.set_log_interface(interface_name)
        packet_handler.set_log_interface(interface_name)
        if arp_cache is not None:
            arp_cache.set_log_interface(interface_name)

    # The table allocates the next ifindex (first_ifindex when empty,
    # else max+1) and stamps it onto the handler, atomically under its
    # lock so concurrent runtime adds cannot collide on an index.
    ifindex = _stack.interfaces.add(packet_handler)

    # Route state is global (shared across interfaces). Inject the
    # Route API if it already exists (a runtime add_interface call);
    # for the boot interface 'init()' builds the FIB after this
    # returns and injects the Route API itself.
    route = getattr(_stack, "route", None)
    if route is not None:
        packet_handler.attach_route_api(route)

    # Per-interface DHCPv4 / RFC 3927 link-local subsystems (L2-only;
    # both depend on Ethernet/ARP). Built HERE so the interface owns its
    # own client(s) — each binds to THIS interface via the control tools'
    # 'interface(ifindex)' view, never the bare singleton. The
    # 'stack.dhcp4_client' / 'stack.link_local' module slots are boot
    # shims (Phase 6: per-ifindex, parallel to 'stack.packet_handler').
    # The control tools ('stack.address' / 'stack.link' / 'stack.route')
    # are built by 'init()' before it delegates here, so the views
    # resolve.
    if layer is InterfaceLayer.L2 and ip4_dhcp:
        # MAC + address operations route through the public Link / Address
        # tools (bound to this interface), so DHCP construction has no
        # reach-through into packet-handler internals. The assertion
        # narrows 'MacAddress | None' → 'MacAddress' for mypy; on L2 the
        # MAC is always populated.
        address_view = _stack.address.interface(ifindex)
        dhcp_mac = _stack.link.interface(ifindex).mac_address
        assert dhcp_mac is not None, "L2 interface must expose a unicast MAC via the link tool."
        # RFC 5227 ACD runs in userspace over the AF_PACKET socket
        # (Phase 4) — the pre-lease Probe and the BOUND Announcement
        # delegate to the Ip4Acd engine, NOT the Address API. The
        # Address API stays only for the BOUND-transition address
        # install (RTM_NEWADDR).
        assert isinstance(packet_handler, PacketHandlerL2)
        dhcp4_client = Dhcp4Client(
            mac_address=dhcp_mac,
            acd=Ip4Acd(mac_address=dhcp_mac, ifindex=ifindex),
            address_api=address_view,
            route_api=_stack.route,
            interface_name=interface_name,
            ifindex=ifindex,
        )
        dhcp4_client.set_log_interface(interface_name)
        packet_handler.attach_dhcp4_client(dhcp4_client)
        # N=1 back-compat: 'stack.dhcp4_client' aliases the FIRST (boot)
        # DHCPv4 interface's client for single-interface consumers; real
        # ownership is per-interface on the handler so a multi-homed host
        # runs one DHCP lifecycle per NIC.
        if _stack.dhcp4_client is None:
            _stack.dhcp4_client = dhcp4_client

    # Per-interface DHCPv6 client (RFC 8415; L2-only — needs link-scoped
    # multicast). Unlike DHCPv4 there is no opt-in flag: DHCPv6 is
    # RA-driven, so the client is installed whenever IPv6 is enabled and
    # the RA RX handler triggers it on an inbound RA's Managed /
    # Other-config flags. The leased address installs through the public
    # Address tool (bound to this interface), never a packet-handler
    # reach-through.
    #
    # The 'isinstance(_stack.address, AddressApi)' guard makes the client
    # contingent on the Address control plane being up — always the case
    # in production ('init()' builds the control tools before delegating
    # here), and the signal that a narrow unit test exercising
    # 'add_interface' in isolation has not stood the tools up (in which
    # case there is nothing to bind the client to and it is skipped).
    # 'No isinstance(packet_handler, PacketHandlerL2)' narrowing is
    # needed (unlike the DHCPv4 block): '_dhcp6_client' is declared on
    # the base 'PacketHandler', so the assignment type-checks on the
    # 'PacketHandlerL2 | PacketHandlerL3' union directly.
    if layer is InterfaceLayer.L2 and ip6_support and isinstance(_stack.address, AddressApi):
        dhcp6_address_view = _stack.address.interface(ifindex)
        dhcp6_mac = _stack.link.interface(ifindex).mac_address
        assert dhcp6_mac is not None, "L2 interface must expose a unicast MAC via the link tool."
        dhcp6_client = Dhcp6Client(
            mac_address=dhcp6_mac,
            interface_name=interface_name,
            address_api=dhcp6_address_view,
        )
        dhcp6_client.set_log_interface(interface_name)
        packet_handler.attach_dhcp6_client(dhcp6_client)
        # N=1 back-compat alias, parallel to 'stack.dhcp4_client'.
        if _stack.dhcp6_client is None:
            _stack.dhcp6_client = dhcp6_client

    if layer is InterfaceLayer.L2 and ip4_link_local:
        assert isinstance(packet_handler, PacketHandlerL2)
        ll_handler = packet_handler
        ll_address_view = _stack.address.interface(ifindex)
        ll_mac = _stack.link.interface(ifindex).mac_address
        assert ll_mac is not None, "L2 interface must expose a unicast MAC via the link tool."
        from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4State

        def _is_dhcp_bound() -> bool:
            client = ll_handler.dhcp4_client
            return client is not None and client.state is Dhcp4State.BOUND

        from pytcp.protocols.ip4.link_local.link_local__client import Ip4LinkLocal as _Ip4LinkLocal

        _stack.link_local = _Ip4LinkLocal(
            mac_address=ll_mac,
            address_api=ll_address_view,
            acd=Ip4Acd(mac_address=ll_mac, ifindex=ifindex),
            is_dhcp_bound=_is_dhcp_bound,
        )

    # Daemon runtime path (RTM_NEWLINK): when the stack is already
    # running, bring the new interface's subsystem threads up on the
    # spot. At boot the stack is not yet running, so the pending
    # 'stack.start()' starts every registered interface instead.
    if _stack.stack_running:
        _start_interface(packet_handler)

    return ifindex


def _add_loopback() -> int:
    """
    Construct the loopback ('lo') interface and register it in
    'stack.interfaces', returning its allocated ifindex. Like Linux,
    'lo' is always present: 'init()' calls this so every stack — even
    the daemon's zero-physical-device resting state — has an interface
    for local delivery of 127.0.0.0/8 + ::1 (and own-IP) traffic.

    'lo' has no fd, no rings, no neighbour caches and no MAC; it owns
    its own in-process 'LoopbackRing' and delivers on its own subsystem
    thread. Registered AFTER any boot interface so a physical interface
    keeps 'STACK__DEFAULT_IFINDEX'; in the zero-device path 'lo' takes
    that index itself (Linux 'lo' == ifindex 1).
    """

    import pytcp.stack as _stack

    handler = PacketHandlerLoopback(
        interface_mtu=_stack.INTERFACE__LOOPBACK__MTU,
        interface_name="lo",
    )
    handler.set_log_interface("lo")
    return _stack.interfaces.add(handler)


def _purge_interface_state(iface: PacketHandlerL2 | PacketHandlerL3, /) -> None:
    """
    Run the 'RTM_DELLINK' teardown cascade for one interface's
    addresses, neighbour caches, routes and DHCP client — BEFORE it
    leaves the registry, so session-abort RSTs still egress the live
    interface and address-keyed lookups still resolve it:

      1. Remove every unicast address (one RTM_DELADDR per address) via
         the Address API. Each removal ABORTs the TCP sessions bound to
         that address (RFC 5227 §2.4) and drops it from the interface,
         so the connected routes synthesized from the address list
         vanish with the interface.
      2. Flush the interface's neighbour caches via the Neighbor API —
         ARP for an L2 interface, ND for every interface ('ip neighbor
         flush dev <ifX>').
      3. Purge explicitly-installed FIB routes that egress this
         interface ('oif' == ifindex) from both address families.
      4. Stop the per-interface DHCPv4 client — a Subsystem thread the
         per-interface thread-teardown does not own, so a leaked client
         would keep renewing a lease on a removed NIC.
    """

    import pytcp.stack as _stack

    address_api = AddressApi(packet_handler=iface)
    ifaddrs: list[Ip4IfAddr | Ip6IfAddr] = [*iface.ip4_ifaddr, *iface.ip6_ifaddr]
    for ifaddr in ifaddrs:
        address_api.remove(address=ifaddr.address)

    neighbor_api = NeighborApi(packet_handler=iface)
    if iface.arp_cache is not None:
        neighbor_api.flush(family=AddressFamily.INET4)
    neighbor_api.flush(family=AddressFamily.INET6)

    ip4_fib = getattr(_stack, "ip4_fib", None)
    if ip4_fib is not None:
        ip4_fib.remove_by_oif(oif=iface.ifindex)
    ip6_fib = getattr(_stack, "ip6_fib", None)
    if ip6_fib is not None:
        ip6_fib.remove_by_oif(oif=iface.ifindex)

    if isinstance(iface, PacketHandlerL2) and iface.dhcp4_client is not None:
        iface.dhcp4_client.stop()
    if isinstance(iface, PacketHandlerL2) and iface.dhcp6_client is not None:
        iface.dhcp6_client.stop()


def remove_interface(ifindex: int, /) -> PacketHandlerL2 | PacketHandlerL3 | None:
    """
    Remove the interface registered under 'ifindex' — the RTNETLINK
    'RTM_DELLINK' equivalent. On a running stack it first runs the
    teardown cascade ('_purge_interface_state': abort bound TCP
    sessions, drop addresses, flush neighbour caches, purge egress
    routes, stop the DHCPv4 client), then stops its subsystem threads
    (handler + rings + neighbor caches); finally it deregisters the
    interface from 'stack.interfaces'. Returns the removed handler, or
    None when no interface is registered under 'ifindex'.

    The cascade runs only on a running stack — a stopped stack has no
    live sessions or threads, and 'init()' rebuilds every interface
    from scratch, so a stopped-stack removal is a pure deregister.
    """

    import pytcp.stack as _stack

    iface = _stack.interfaces.get(ifindex)
    if iface is None:
        return None
    # Cascade + thread teardown BEFORE deregistering, so the abort RSTs
    # egress the still-registered interface and its address-derived
    # connected routes are still resolvable while sessions are torn down.
    if _stack.stack_running:
        _purge_interface_state(iface)
        _stop_interface(iface)
    _stack.interfaces.pop(ifindex)
    return iface


def init(
    *,
    fd: int | None = None,
    layer: InterfaceLayer | None = None,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    interface_name: str | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip4_dhcp: bool | None = None,
    ip4_link_local: bool = False,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    ip6_gua_autoconfig: bool | None = None,
    ip6_lla_autoconfig: bool = True,
    sysctls: dict[str, Any] | None = None,
) -> None:
    """
    Initialize stack components.

    With no 'fd' / 'layer' the stack comes up with ZERO interfaces —
    the daemon-shaped resting state (timer, empty interface registry,
    global FIBs + Route API, and the unbound control tools). Attach a
    device afterwards with 'add_interface(...)'. With 'fd' / 'layer'
    supplied (the interim back-compat convenience) 'init()' also builds
    that one boot interface by delegating to 'add_interface', and wires
    the per-interface DHCPv4 / link-local subsystems to it.
    """

    import pytcp.stack as _stack

    # The boot interface is optional: 'init(fd=..., layer=...)' brings
    # one up; bare 'init()' leaves the registry empty for a later
    # 'add_interface'. Narrows 'fd' / 'layer' to non-None below.
    has_interface = fd is not None and layer is not None

    # Resolve None-valued kwargs against the stack-level
    # config constants. The legacy form used these constants
    # as default-expression values, which evaluated at module
    # import — meaning a test changing 'stack.IP4_ADDRESS'
    # would not affect a later 'init()' call. Move the
    # resolution into the body so each invocation sees the
    # current values.
    if ip4_host is None and _stack.IP4_ADDRESS is not None:
        ip4_host = Ip4IfAddr(_stack.IP4_ADDRESS)
    if ip4_dhcp is None:
        ip4_dhcp = _stack.IP4_ADDRESS is None
    if ip6_host is None and _stack.IP6_ADDRESS is not None:
        ip6_host = Ip6IfAddr(_stack.IP6_ADDRESS)
    if ip6_gua_autoconfig is None:
        ip6_gua_autoconfig = _stack.IP6_ADDRESS is None

    # Apply any operator overrides for the registered sysctl
    # knobs before subsystems are constructed. The bag-form
    # 'sysctls={"arp.X": ..., "neighbor.X": ...}' is keyed by
    # the dotted-name canonical key. Per-knob validators run on
    # each set(); cross-knob constraints
    # ('finalize_validators') run after the bag is fully
    # applied. Importing 'arp__constants' / 'neighbor__constants'
    # triggers their module-level 'register' calls so the
    # registry is populated before we set anything.
    from pytcp.lib import neighbor__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.arp import arp__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.icmp import icmp__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.icmp6.nd import nd__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4 import ip4__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4.link_local import (  # noqa: F401  pylint: disable=unused-import
        link_local__constants,
    )
    from pytcp.protocols.ip6 import ip6__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.tcp import tcp__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.stack import sysctl as sysctl_module

    if sysctls is not None:
        for key, value in sysctls.items():
            sysctl_module.set(key, value)
    sysctl_module.finalize_validators()

    _stack.timer = Timer()
    _stack.interfaces = InterfaceTable(first_ifindex=_stack.STACK__DEFAULT_IFINDEX)

    # IPv4 address-control API + link-control surface — built as the
    # UNBOUND, device-independent "userspace tools" (the 'ip addr' /
    # 'ip link' model), NOT pinned to a boot interface. The unbound tool
    # has no default device: every per-interface op MUST select one via
    # '.interface(ifindex)' (Linux 'ip ... dev <ifX>'); a bare per-device
    # op raises. Built BEFORE 'add_interface' so the per-interface DHCP /
    # link-local subsystems it constructs can bind to their own
    # 'interface(ifindex)' view. See 'docs/refactor/link_api.md'.
    _stack.address = AddressApi()
    _stack.link = LinkApi()
    _stack.neighbor = NeighborApi()
    _stack.membership = MembershipApi()
    _stack.membership6 = Membership6Api()
    _stack.resolver = ResolverApi(resolver=DnsResolver(server=_stack.STACK__DNS_SERVER))
    _stack.ss = SocketIntrospectApi()
    _stack.activity = ActivityIntrospectApi()

    # Host-mode routing table — Phase 3 of
    # 'docs/refactor/routing_table_host_mode.md'. Build the two FIBs and
    # the Route API BEFORE 'add_interface' so the latter injects
    # '_route_api' into the new handler itself (no separate post-injection
    # needed). The static boot-config gateway is a boot-interface
    # convenience installed only when an interface is built; with zero
    # interfaces the FIBs come up empty (a daemon adds routes as
    # interfaces + addresses attach). The next hop is FIB state — DHCP /
    # RA / autoconfig install their learned gateway at runtime via
    # 'RouteApi.replace_default_ip{4,6}'.
    ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
    ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
    if has_interface:
        install_boot_default_routes(
            ip4_fib=ip4_fib,
            ip6_fib=ip6_fib,
            ip4_gateway=_stack.IP4_GATEWAY,
            ip6_gateway=_stack.IP6_GATEWAY,
        )
    _stack.ip4_fib = ip4_fib
    _stack.ip6_fib = ip6_fib
    _stack.route = RouteApi(ip4_fib=ip4_fib, ip6_fib=ip6_fib)

    # Per-interface subsystem slots default to None; 'add_interface'
    # populates them (boot shims) when it builds a DHCP / link-local
    # client for an L2 interface. With zero interfaces they stay None.
    _stack.dhcp4_client = None
    _stack.dhcp6_client = None
    _stack.link_local = None

    # Boot interface (interim back-compat convenience): when 'fd' /
    # 'layer' are supplied, delegate to 'add_interface', which builds the
    # rings + neighbor caches + handler, populates the N=1 back-compat
    # singletons, injects the Route API, and constructs this interface's
    # own DHCPv4 / link-local subsystems. With no 'fd' / 'layer' the
    # stack stays at zero interfaces (the daemon resting state).
    if has_interface:
        assert fd is not None and layer is not None  # narrowed by 'has_interface'
        add_interface(
            fd=fd,
            layer=layer,
            mtu=mtu,
            mac_address=mac_address,
            interface_name=interface_name,
            ip4_support=ip4_support,
            ip4_host=ip4_host,
            ip4_dhcp=bool(ip4_dhcp),
            ip4_link_local=ip4_link_local,
            ip6_support=ip6_support,
            ip6_host=ip6_host,
            ip6_gua_autoconfig=bool(ip6_gua_autoconfig),
            ip6_lla_autoconfig=ip6_lla_autoconfig,
        )

    # Loopback interface — always present (Linux 'lo'). Registered AFTER
    # the boot interface so a physical device keeps 'STACK__DEFAULT_IFINDEX';
    # in the zero-device daemon path 'lo' takes that index. Enables local
    # delivery of 127.0.0.0/8 + ::1 (and own-IP) traffic.
    _add_loopback()

    _stack.stack_initialized = True


def _start_interface(iface: PacketHandlerL2 | PacketHandlerL3, /) -> None:
    """
    Start one interface's own subsystem threads — its neighbor
    cache(s), TX / RX rings and packet handler (the handler owns its
    injected '_rx_ring' / '_tx_ring' / '_arp_cache' / '_nd_cache').
    Shared by 'stack.start()' (boot, every registered interface) and
    'add_interface' (runtime add to an already-running stack).
    """

    # The loopback interface has no fd-bound rings and no neighbour
    # caches — only its own consumer thread. Start the handler and stop.
    if iface.interface_layer is InterfaceLayer.LOOPBACK:
        iface.start()
        return

    if iface.arp_cache is not None:
        iface.arp_cache.start()
    assert iface.nd_cache is not None
    iface.nd_cache.start()
    assert iface.tx_ring is not None and iface.rx_ring is not None
    iface.tx_ring.start()
    iface.rx_ring.start()
    iface.start()


def _stop_interface(iface: PacketHandlerL2 | PacketHandlerL3, /) -> None:
    """
    Stop one interface's own subsystem threads — handler first (stop
    TX producers), then its rings, then its neighbor cache(s); the
    reverse of '_start_interface'. Used by 'remove_interface' to tear
    down a single interface on a running stack. ('stack.stop()' keeps
    its own global ordering — all handlers, then the shared timer, then
    all rings/caches — so it does not call this per-interface helper.)
    """

    # The loopback interface has no rings or neighbour caches to stop —
    # only its own consumer thread (which 'iface.stop()' winds down,
    # closing the LoopbackRing eventfd via its '_stop').
    if iface.interface_layer is InterfaceLayer.LOOPBACK:
        iface.stop()
        return

    iface.stop()
    assert iface.rx_ring is not None and iface.tx_ring is not None
    iface.rx_ring.stop()
    iface.tx_ring.stop()
    if iface.arp_cache is not None:
        iface.arp_cache.stop()
    assert iface.nd_cache is not None
    iface.nd_cache.stop()


def start(*, wait_for_dhcp_bind: bool = True) -> None:
    """
    Start stack components.

    'wait_for_dhcp_bind' (default True) preserves the in-process boot
    semantics: 'start()' blocks up to 'dhcp.boot_wait_ms' for the DHCPv4
    FSM to reach BOUND so a synchronous consumer has an IPv4 address in
    hand when it returns. A daemon passes False — the DHCPv4 lifecycle is
    started but not waited on, so the control plane comes up immediately
    and the lease lands in the background (clients poll the address state).
    """

    import pytcp.stack as _stack

    assert _stack.stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    _stack.stack_running = True

    _stack.timer.start()
    # Per-interface subsystems: start each registered interface's own
    # caches, rings and handler. At N=1 this is the single boot
    # interface; the loop is the N>1 path.
    for iface in _stack.interfaces.values():
        _start_interface(iface)

    # RFC 3927 link-local autoconfig subsystem. Start BEFORE the
    # DHCP wait so the two FSMs run in parallel — the link-local
    # subsystem's '_reconcile_with_dhcp' polls DHCP state and
    # naturally waits until 'dhcp_fallback_timeout_ms' has elapsed
    # of continuous DHCP-unbound time before claiming.
    if _stack.link_local is not None:
        _stack.link_local.start()

    # Phase 4 commit B — DHCPv4 lifecycle. Start AFTER the packet
    # handler so the TX/RX/socket plumbing is live. By default block up to
    # 'dhcp.boot_wait_ms' for the FSM to reach BOUND (on timeout the
    # lifecycle keeps trying in the background; boot proceeds without IPv4
    # for now). A daemon ('wait_for_dhcp_bind=False') starts the lifecycle
    # but does not block — its control plane must come up immediately.
    dhcp4_clients = [
        handler.dhcp4_client
        for handler in _stack.interfaces.values()
        if isinstance(handler, PacketHandlerL2) and handler.dhcp4_client is not None
    ]
    if dhcp4_clients and not wait_for_dhcp_bind:
        for dhcp4_client in dhcp4_clients:
            dhcp4_client.start()
        __debug__ and log("stack", "DHCPv4 lifecycle started; not blocking boot on the lease")
    elif dhcp4_clients:
        from pytcp.protocols.dhcp4 import dhcp4__constants

        boot_wait_s = dhcp4__constants.DHCP4__BOOT_WAIT_MS / 1000.0
        for dhcp4_client in dhcp4_clients:
            bound = dhcp4_client.start_and_wait_for_bind(timeout_s=boot_wait_s)
            if bound:
                __debug__ and log("stack", "DHCPv4 lifecycle reached BOUND during boot")
            else:
                __debug__ and log(
                    "stack",
                    f"<WARN>DHCPv4 lifecycle did not reach BOUND within "
                    f"{boot_wait_s:.1f}s; proceeding without IPv4 (lifecycle "
                    f"continues in background)</>",
                )

    # DHCPv6 lifecycle (RFC 8415). Start the worker threads AFTER the
    # packet handler so the TX/RX/socket plumbing is live. No boot wait —
    # DHCPv6 is RA-triggered (not boot-blocking); each worker idles until
    # the RA RX handler triggers it on an inbound RA's Managed /
    # Other-config flags.
    for handler in _stack.interfaces.values():
        if isinstance(handler, PacketHandlerL2) and handler.dhcp6_client is not None:
            handler.dhcp6_client.start()


def stop() -> None:
    """
    Stop stack components.
    """

    import pytcp.stack as _stack

    assert _stack.stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    # Graceful multicast Leave: while the TX path is still fully live
    # (before any subsystem teardown below), announce departure from
    # every joined IPv4 multicast group so routers prune the host's
    # memberships immediately instead of waiting for a query timeout
    # (RFC 3376 §5.1; Linux 'ip_mc_down').
    for iface in _stack.interfaces.values():
        iface.stop_igmp_querier()
        iface.stop_mld_querier()
        iface.send_igmp_leave_all()
        iface.send_mld_leave_all()

    _stack.stack_running = False

    # Teardown order:
    #   0. dhcp4_client    — stop the DHCPv4 lifecycle FIRST so any
    #                        in-flight RENEW/REBIND/RELEASE work
    #                        completes against still-live sockets.
    #   1. packet_handler  — stop application-side TX producers.
    #   2. timer           — stop periodic callbacks (TCP RTO,
    #                        persist, keep-alive, delayed-ACK) so
    #                        they cannot enqueue to a stopped tx_ring.
    #   3. rx_ring         — stop kernel reads.
    #   4. tx_ring         — drain anything still queued + stop.
    #   5. arp_cache / nd_cache — stop cache-refresh threads.
    for handler in _stack.interfaces.values():
        if isinstance(handler, PacketHandlerL2) and handler.dhcp4_client is not None:
            handler.dhcp4_client.stop()
        if isinstance(handler, PacketHandlerL2) and handler.dhcp6_client is not None:
            handler.dhcp6_client.stop()
    if _stack.link_local is not None:
        _stack.link_local.stop()
    # Per-interface handlers first (stop application-side TX
    # producers), then the shared timer (so periodic callbacks cannot
    # enqueue onto a stopped ring), then each interface's rings +
    # caches. At N=1 this is the single boot interface.
    for iface in _stack.interfaces.values():
        iface.stop()
    _stack.timer.stop()
    for iface in _stack.interfaces.values():
        # The loopback interface has no rings or neighbour caches — its
        # consumer thread and LoopbackRing eventfd were wound down by
        # 'iface.stop()' above.
        if iface.interface_layer is InterfaceLayer.LOOPBACK:
            continue
        assert iface.rx_ring is not None and iface.tx_ring is not None
        iface.rx_ring.stop()
        iface.tx_ring.stop()
        if iface.arp_cache is not None:
            iface.arp_cache.stop()
        assert iface.nd_cache is not None
        iface.nd_cache.stop()

    # Restore every registered sysctl to its compile-time default
    # so a follow-up 'stack.init()' (typical in long-running test
    # harnesses) starts from a clean baseline rather than
    # inheriting overrides from the prior run.
    from pytcp.stack import sysctl as sysctl_module

    sysctl_module.reset_to_defaults()
