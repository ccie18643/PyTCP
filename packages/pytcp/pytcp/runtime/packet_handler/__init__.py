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
This package contains packet handler class for inbound and outbound packets.

pytcp/runtime/packet_handler/__init__.py

ver 3.0.8
"""

import random
import secrets
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

from net_addr import (
    Buffer,
    Ip4Address,
    Ip4IfAddr,
    Ip6Address,
    Ip6IfAddr,
    Ip6Mask,
    Ip6Network,
    MacAddress,
)
from net_proto import (
    ETHERNET_802_3__PACKET__MAX_LEN,
    ArpOperation,
    Ethernet8023Payload,
    EthernetAssembler,
    EthernetPayload,
    EtherType,
    Icmp4Message,
    Icmp6Message,
    Icmp6NdRoutePreference,
    IgmpVersion,
    Ip4Payload,
    Ip6Assembler,
    Ip6Payload,
    IpProto,
    PacketRx,
    RawAssembler,
    Tracker,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    MldVersion,
)
from net_proto.protocols.ip4.options.ip4__options import Ip4Options
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import (
    LinkStatsCounters,
    PacketStatsRx,
    PacketStatsShards,
    PacketStatsTx,
)
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.dhcp6.dhcp6__client import Dhcp6Client
from pytcp.protocols.icmp6.nd import nd__constants
from pytcp.protocols.icmp6.nd.nd__router_state import (
    Icmp6DadState,
    Icmp6DefaultRouter,
    Icmp6RaParameters,
    Icmp6SlaacAddress,
    Icmp6SlaacAddressState,
    Icmp6TempAddress,
)
from pytcp.protocols.igmp import igmp__constants
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.protocols.ip.ip_frag_table import IpFragTable
from pytcp.runtime.fib import RouteProtocol
from pytcp.runtime.loopback_ring import LoopbackRing
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.subsystem import Subsystem
from pytcp.runtime.timer import TimerHandle
from pytcp.runtime.tx_ring import TxRing
from pytcp.stack import sysctl_iface
from pytcp.stack.membership import IP4__MULTICAST__ALL_SYSTEMS
from pytcp.stack.route import RouteApi

from .dispatch import DispatchRegistry
from .packet_handler__arp__rx import ArpRxHandler
from .packet_handler__arp__tx import ArpTxHandler
from .packet_handler__ethernet_802_3__rx import Ethernet8023RxHandler
from .packet_handler__ethernet_802_3__tx import Ethernet8023TxHandler
from .packet_handler__ethernet__rx import EthernetRxHandler
from .packet_handler__ethernet__tx import EthernetTxHandler
from .packet_handler__icmp4__rx import Icmp4RxHandler
from .packet_handler__icmp4__tx import Icmp4TxHandler
from .packet_handler__icmp6__rx import Icmp6RxHandler
from .packet_handler__icmp6__tx import Icmp6TxHandler
from .packet_handler__igmp__rx import IgmpGroupQueryPending, IgmpRxHandler
from .packet_handler__igmp__tx import IgmpTxHandler
from .packet_handler__ip4__rx import Ip4RxHandler
from .packet_handler__ip4__tx import Ip4TxHandler
from .packet_handler__ip6__rx import Ip6RxHandler
from .packet_handler__ip6__tx import Ip6TxHandler
from .packet_handler__ip6_frag__rx import Ip6FragRxHandler
from .packet_handler__ip6_frag__tx import Ip6FragTxHandler
from .packet_handler__tcp__rx import TcpRxHandler
from .packet_handler__tcp__tx import TcpTxHandler
from .packet_handler__udp__rx import UdpRxHandler
from .packet_handler__udp__tx import UdpTxHandler

if TYPE_CHECKING:
    from pytcp.protocols.arp.arp__cache import ArpCache
    from pytcp.protocols.icmp6.nd.nd__cache import NdCache


# The RFC 3376 §5.1 "non-existent" reception state — a filter mode of
# INCLUDE with an empty source list — used as the before/after state when
# a group's per-interface record is created (join) or deleted (leave).
_IP4_MULTICAST__NONMEMBER = Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE)


@dataclass(slots=True)
class _Ip4GroupMembership:
    """
    The per-socket source filters contributing to one IPv4 multicast
    group's reception on an interface — the operator hold ('ip maddr'-
    style, set-once, an EXCLUDE{} any-source contributor) and each
    socket's filter keyed by an opaque socket token (the BSD socket
    options 'IP_ADD_MEMBERSHIP' / 'IP_ADD_SOURCE_MEMBERSHIP' / …). The
    merged interface filter (RFC 3376 §3.2) is derived from
    'contributors()'; the group stays joined while that merge has
    reception state.
    """

    operator: bool = False
    # The current source filter each socket holds on this group, keyed
    # by the socket's opaque token (its 'id()'). 'IP_ADD_MEMBERSHIP'
    # registers an EXCLUDE{} any-source filter; the source options
    # register INCLUDE / EXCLUDE-with-sources filters. A socket's entry
    # is replaced on each of its own filter mutations and removed when
    # it leaves the group.
    socket_filters: dict[int, Ip4MulticastFilter] = field(default_factory=dict)

    def contributors(self) -> list[Ip4MulticastFilter]:
        """
        Return every per-socket filter feeding the §3.2 merge — the
        socket filters plus the operator hold's EXCLUDE{} contributor
        when the operator hold is set.
        """

        contributors = list(self.socket_filters.values())
        if self.operator:
            contributors.append(Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE))
        return contributors


class PacketHandler(Subsystem, ABC):
    """
    Base class for packet handlers.
    """

    _subsystem_name = "Packet Handler"

    # Composed per-protocol sub-handlers shared by both layers (see
    # docs/refactor/packet_handler_composition.md). Constructed in
    # this base '__init__' so both 'PacketHandlerL2' (via super())
    # and 'PacketHandlerL3' (which has no own '__init__') get them;
    # the handler keeps thin delegators below so the external +
    # cross-call surface is unchanged.
    _udp_rx: UdpRxHandler
    _udp_tx: UdpTxHandler
    _tcp_rx: TcpRxHandler
    _tcp_tx: TcpTxHandler
    _icmp4_rx: Icmp4RxHandler
    _icmp4_tx: Icmp4TxHandler
    _icmp6_rx: Icmp6RxHandler
    _icmp6_tx: Icmp6TxHandler
    _igmp_rx: IgmpRxHandler
    _igmp_tx: IgmpTxHandler
    _igmp_query__pending_response_at_ms: int | None
    _igmp_query__handle: TimerHandle | None
    _igmp_query__suppressed_groups: set[Ip4Address]
    # RFC 3376 §5.2 per-group Query response state (Group-Specific +
    # Group-and-Source-Specific): group -> deadline + handle + recorded
    # queried sources.
    _igmp_group_query__pending: dict[Ip4Address, IgmpGroupQueryPending]
    _igmp__v1_querier_present_until_ms: int | None
    _igmp__v2_querier_present_until_ms: int | None
    _ip6_frag_rx: Ip6FragRxHandler
    _ip6_frag_tx: Ip6FragTxHandler
    _ip4_rx: Ip4RxHandler
    _ip4_tx: Ip4TxHandler
    _ip6_rx: Ip6RxHandler
    _ip6_tx: Ip6TxHandler

    # Per-interface RX dispatch registries (see dispatch.py). Built at
    # construction so membership encodes this interface's layer +
    # protocol-support policy; the demux sites consult them instead of
    # a hard-coded 'match'. The link-layer registry is keyed by
    # 'EtherType' (consulted by the Ethernet RX demux on L2 and the
    # TUN-PI demux on L3); the two transport registries are keyed by
    # 'IpProto' (the IPv4 transport demux and the IPv6
    # transport-terminator demux).
    _ethertype_registry: DispatchRegistry[EtherType]
    _ip4_proto_registry: DispatchRegistry[IpProto]
    _ip6_proto_registry: DispatchRegistry[IpProto]

    # Per-interface DHCPv6 client (RFC 8415), triggered by the RA RX
    # handler when an inbound Router Advertisement carries the Managed /
    # Other-config flags. Declared on the base (default 'None') so the
    # shared ICMPv6 RX handler can reach it through 'self._if:
    # PacketHandler'; the lifecycle installs a real client only on an
    # L2 interface. 'None' = the RA M/O flags are parsed but not acted on.
    _dhcp6_client: Dhcp6Client | None = None

    if TYPE_CHECKING:
        # '_phtx_ethernet' is provided by the L2-only
        # 'PacketHandlerEthernetTx' mixin. The shared IPv4 / IPv6 TX
        # sub-handlers reach it through their 'self._if:
        # PacketHandlerL2 | PacketHandlerL3' union, but only ever on
        # the 'InterfaceLayer.L2' branch — an L3 (TUN) interface emits
        # via the TX ring directly and never calls this. The
        # declaration here is the typing fiction that lets the union
        # see the method; it is 'TYPE_CHECKING'-only so the running
        # 'PacketHandlerL3' is not given a non-functional Ethernet
        # emitter. Drops out once L2/L3 are themselves restructured.
        # Args unused: this is a signature-only typing stub ('...' body).
        def _phtx_ethernet(  # pylint: disable=unused-argument
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload = RawAssembler(),
        ) -> TxStatus: ...

    _event__stop_subsystem: threading.Event

    _stats_rx: PacketStatsShards[PacketStatsRx]
    _stats_tx: PacketStatsShards[PacketStatsTx]
    _link_stats: LinkStatsCounters
    # Per-interface RX ring. Injected at construction by
    # 'stack.init()' (the ring is fd-bound, hence per-interface).
    # The subsystem loop dequeues from this — never from the
    # global 'stack.rx_ring' shim. 'None' only for standalone
    # unit-test handlers that never run the subsystem loop. The
    # class-level 'None' default (rather than an annotation alone)
    # keeps the attribute visible to 'create_autospec' so test
    # fixtures can install a mock ring on a spec'd handler.
    _rx_ring: RxRing | None = None
    # Per-interface TX ring (fd-bound). Injected at construction;
    # the TX-mixin send-out paths enqueue onto this — never onto
    # the global 'stack.tx_ring' shim. 'None' only for standalone
    # unit-test handlers that never enqueue.
    _tx_ring: TxRing | None = None
    # Per-interface neighbor caches (Linux keys ARP / ND per
    # ifindex). Injected after construction by 'stack.init()'.
    # ARP is L2-only, so '_arp_cache' stays None on an L3 (TUN)
    # handler; '_nd_cache' is used by both layers. 'None' for
    # standalone unit-test handlers that never resolve a neighbor.
    _arp_cache: ArpCache | None = None
    _nd_cache: NdCache | None = None
    # Routing-control API (the host-mode FIB mutation surface).
    # Global state shared across interfaces, but injected as an
    # explicit dependency rather than reached via 'stack.route'.
    # The RX RA path drives the default route through this. 'None'
    # until injected (early-RX / test contexts without a Route API).
    _route_api: RouteApi | None = None
    # Per-interface index (Linux ifindex). The handler IS the
    # interface object; 'stack.interfaces' maps this index to the
    # handler. Class-level default 1 (the sole interface today /
    # standalone unit-test handlers); 'stack.init()' assigns the
    # real index per registered interface.
    _ifindex: int = 1
    _interface_mtu: int
    _interface_name: str | None
    # Concrete value set on each subclass ('PacketHandlerL2' /
    # 'PacketHandlerL3'); declared here so the composed TX sub-handlers
    # can branch on it through their 'PacketHandler' back-reference.
    _interface_layer: InterfaceLayer
    _ip6_support: bool
    _ip4_support: bool
    _ip6_ifaddr_candidate: list[Ip6IfAddr]
    _ip4_ifaddr_candidate: list[Ip4IfAddr]
    _ip6_ifaddr: list[Ip6IfAddr]
    _ip4_ifaddr: list[Ip4IfAddr]
    _ip6_multicast: list[Ip6Address]
    # The materialized per-interface IPv4 multicast reception state —
    # one merged source filter (RFC 3376 §3.2) per group the interface
    # listens on, including the permanent all-systems group 224.0.0.1.
    # The flat '_ip4_multicast' joined-group list is a derived view over
    # this map's keys. In Phase 1 every entry is EXCLUDE{} (any-source).
    _ip4_multicast_filters: dict[Ip4Address, Ip4MulticastFilter]
    _ip4_multicast_refs: dict[Ip4Address, _Ip4GroupMembership]
    # IPv4 Identification counter + the lock guarding its masked
    # read-modify-write. Per-interface (the counter is interface
    # state); the tiny lock makes '_next_ip4_id' atomic under the
    # current app-thread TX model and stays cheap (uncontended)
    # once Phase 4 makes TX single-writer. IPv6 has no counterpart:
    # its Fragment Identification is a fresh random per datagram
    # (a loop-local in '_phtx_ip6_frag'), not stored on the handler.
    _ip4_id: int
    _lock__ip4_id: threading.Lock
    _lock__multicast: threading.RLock
    _lock__addr_config: threading.RLock
    _ip6_frag_table: IpFragTable
    _ip4_frag_table: IpFragTable
    _ip_configuration_in_progress: threading.Semaphore
    _mac_unicast: MacAddress
    _icmp6_default_routers: list[Icmp6DefaultRouter]
    _icmp6_slaac_addresses: list[Icmp6SlaacAddress]
    _icmp6_temp_addresses: list[Icmp6TempAddress]
    _icmp6_slaac__secret_key: bytes
    _icmp6_ra_parameters: Icmp6RaParameters
    _icmp6_dad__states: dict[Ip6Address, Icmp6DadState]
    _ip6_addressing_complete: bool
    # ICMPv6 ND / RA / MLD link-layer state. Annotated on the base
    # so the shared 'Icmp6RxHandler' (typed over PacketHandlerL2 |
    # PacketHandlerL3) can read it; initialised only in
    # 'PacketHandlerL2.__init__' since the link-layer paths that use
    # it are L2-only (TUN has no DAD / RA-solicit / MLD) — same
    # annotate-on-base, init-on-L2 split the '_icmp6_*' state above
    # already uses.
    _icmp6_nd_dad__registry: DadSlotRegistry[Ip6Address]
    _icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]]
    _icmp6_ra__event: threading.Semaphore
    _mld2_query__pending_response_at_ms: int | None
    _mld2_query__handle: TimerHandle | None
    _mld__v1_querier_present_until_ms: int | None

    @override
    def __init__(
        self,
        *,
        interface_mtu: int,
        ip6_support: bool,
        ip4_support: bool,
        interface_name: str | None = None,
        ip6_host: Ip6IfAddr | None = None,
        ip4_host: Ip4IfAddr | None = None,
        rx_ring: RxRing | None = None,
        tx_ring: TxRing | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__()

        # Per-interface RX / TX rings (fd-bound). Injected by
        # 'stack.init()'; standalone unit-test handlers leave them
        # None and never run '_subsystem_loop' / enqueue.
        self._rx_ring = rx_ring
        self._tx_ring = tx_ring

        # Per-interface neighbor caches. Injected after construction
        # by 'stack.init()' (the cache <-> handler relationship is
        # bidirectional, so they cannot both be ctor args). Default
        # None so standalone unit-test handlers have the attributes
        # present without a cache wired.
        self._arp_cache = None
        self._nd_cache = None

        # Initialize data stores for packet statistics. When the
        # caller supplies pre-constructed stats objects (the
        # 'stack.init()' path does this so the rings can share
        # them), reuse — otherwise default to fresh instances for
        # standalone unit-test callers.
        # Per-thread sharded counters (no-GIL N1/P1): the constructing
        # thread's shard is seeded with the injected (or fresh)
        # instance, so the synchronous single-thread test harness reads
        # its exact counts back; RX / TX / Timer threads each accumulate
        # into their own shard with no lock, summed only on read.
        self._stats_rx = PacketStatsShards(
            factory=PacketStatsRx,
            seed=packet_stats_rx if packet_stats_rx is not None else PacketStatsRx(),
        )
        self._stats_tx = PacketStatsShards(
            factory=PacketStatsTx,
            seed=packet_stats_tx if packet_stats_tx is not None else PacketStatsTx(),
        )
        # Link-level aggregate counters (bytes / multicast) bumped
        # by the rings at frame receive / send time. Sharing the
        # same instance across PacketHandler + RxRing + TxRing
        # mirrors the 'packet_stats_*' pattern; consumers read via
        # 'stack.link.stats'.
        self._link_stats = link_stats if link_stats is not None else LinkStatsCounters()

        # Initialize the interface mtu.
        self._interface_mtu = interface_mtu

        # Record the interface name as plumbed through by
        # 'stack.init()' (None when the harness skips this).
        # Read by the Link API's 'name' property; not used by
        # the packet-handling paths.
        self._interface_name = interface_name

        # Initialize support for IPv6 and IPv4 protocols.
        self._ip6_support = ip6_support
        self._ip4_support = ip4_support

        # Used to assign IP addresses to the stack.
        self._ip6_ifaddr_candidate = []
        self._ip4_ifaddr_candidate = []

        # Used to keep track of IPv6 and IPv4 unicast addresses.
        self._ip6_ifaddr = []
        self._ip4_ifaddr = []

        # Used to keep track of IPv6 multicast addresses.
        self._ip6_multicast = []

        # The materialized per-interface IPv4 multicast reception state
        # (RFC 3376 §3.2 merged filter per group). The '_ip4_multicast'
        # joined-group list is a derived read-only view over its keys.
        self._ip4_multicast_filters = {}

        # Per-group source-filter contributors deciding when an IPv4
        # multicast group crosses the join / leave edge (R3 — operator
        # hold + per-socket filters; the §3.2 merge over these derives
        # the materialized filter above). The permanent all-systems
        # group 224.0.0.1 is assigned directly at boot and is never
        # ref-managed.
        self._ip4_multicast_refs = {}

        # Guards every read / write of the two IPv4 multicast reception-
        # state structures above against concurrent application-thread
        # membership changes and the RX/timer read paths. Reentrant
        # because the mutators nest ('mc_ref_acquire' -> '_mc_recompute'
        # -> '_assign_ip4_multicast' -> '_ip4_multicast_filter_for').
        # GIL atomicity is not relied upon — PyTCP targets free-threaded
        # CPython, where a bare dict RMW racing another thread corrupts.
        self._lock__multicast = threading.RLock()

        # Serializes writers to the per-interface address-configuration
        # cluster — '_ip4_ifaddr' / '_ip6_ifaddr', '_ip6_multicast',
        # the RA-derived SLAAC / temporary / default-router lists and
        # the DAD-state map. Writers publish a fresh list/dict object
        # under this lock (copy-on-write); the per-packet RX / TX
        # readers stay lock-free, iterating the immutable snapshot they
        # load. Reentrant because the RA / sweep / DAD-claim paths nest
        # ('_icmp6_sweep_* -> _remove_ip6_multicast', '_assign_ip6_host
        # -> _assign_ip6_multicast'). NEVER held across a blocking DAD
        # wait — the DAD loop locks only at its individual mutation
        # points. Ordering: this lock is taken before 'tx_ring' on the
        # emit paths and never under '_lock__multicast'.
        self._lock__addr_config = threading.RLock()

        # IPv4 Identification counter (last value) + its lock. The
        # IPv6 Fragment Identification is generated fresh per
        # datagram as a loop-local in '_phtx_ip6_frag', so there is
        # no IPv6 counter to store here.
        self._ip4_id: int = 0
        self._lock__ip4_id = threading.Lock()

        # Used to defragment IPv4 and IPv6 packets.
        self._ip4_frag_table = IpFragTable(timeout=stack.IP4__FRAG_FLOW_TIMEOUT__S)
        self._ip6_frag_table = IpFragTable(timeout=stack.IP6__FRAG_FLOW_TIMEOUT__S)

        # Used for IPv4 and IPv6 address configuration.
        self._ip_configuration_in_progress: threading.Semaphore = threading.Semaphore(0)

        # RFC 4429 §3.1 Optimistic DAD per-address state map.
        # Populated by the DAD-claim path; consulted by the NA
        # emit path to clear the Override flag on outbound NAs
        # whose source is in OPTIMISTIC state per §3.3.
        self._icmp6_dad__states: dict[Ip6Address, Icmp6DadState] = {}

        # Flips True at the end of '_create_stack_ip6_addressing'.
        # Gates runtime stable-SLAAC claim in the RX path: a
        # PI for a new prefix that arrives DURING the boot
        # window updates the SLAAC tracking table only (the
        # boot loop owns the claim ordering); a PI that
        # arrives AFTER the boot window also spawns a fresh
        # 'claim_ip6_address_async' worker.
        self._ip6_addressing_complete: bool = False

        # Assign IP addresses statically.
        if ip6_host is not None:
            self._ip6_ifaddr_candidate.append(ip6_host)

        if ip4_host is not None:
            self._ip4_ifaddr_candidate.append(ip4_host)

        # Construct the shared per-protocol sub-handlers. Each holds a
        # typed '_if: PacketHandler' back-reference and reaches all its
        # shared state + cross-call delegators through this base, so
        # 'self' is passed directly — every protocol is a composed
        # sub-handler now, so the old union cast is gone.
        self._udp_rx = UdpRxHandler(interface=self)
        self._udp_tx = UdpTxHandler(interface=self)
        self._tcp_rx = TcpRxHandler(interface=self)
        self._tcp_tx = TcpTxHandler(interface=self)
        self._icmp4_rx = Icmp4RxHandler(interface=self)
        self._icmp4_tx = Icmp4TxHandler(interface=self)
        self._icmp6_rx = Icmp6RxHandler(interface=self)
        self._icmp6_tx = Icmp6TxHandler(interface=self)
        self._igmp_rx = IgmpRxHandler(interface=self)
        self._igmp_tx = IgmpTxHandler(interface=self)
        self._ip6_frag_rx = Ip6FragRxHandler(interface=self)
        self._ip6_frag_tx = Ip6FragTxHandler(interface=self)
        self._ip4_rx = Ip4RxHandler(interface=self)
        self._ip4_tx = Ip4TxHandler(interface=self)
        self._ip6_rx = Ip6RxHandler(interface=self)
        self._ip6_tx = Ip6TxHandler(interface=self)

        # Build the per-interface RX dispatch registries. The
        # link-layer registry is built by '_build_ethertype_registry'
        # (overridden on 'PacketHandlerL2' to add the L2-only ARP
        # entry) so its membership tracks the protocol-support flags
        # and can be rebuilt if those flags change. The transport
        # registries are layer-independent — both reached only after a
        # datagram of the matching IP version has parsed, so the
        # entries are unconditional (matching the prior unguarded
        # 'match').
        self._build_ethertype_registry()

        self._ip4_proto_registry = DispatchRegistry()
        self._ip4_proto_registry.register(IpProto.ICMP4, self._phrx_icmp4)
        self._ip4_proto_registry.register(IpProto.IGMP, self._phrx_igmp)
        self._ip4_proto_registry.register(IpProto.UDP, self._phrx_udp)
        self._ip4_proto_registry.register(IpProto.TCP, self._phrx_tcp)

        # RFC 3376 §5.2 deferred query-response state, shared with the
        # IGMP RX handler. Tracks the absolute 'stack.timer.now_ms' at
        # which the scheduled IGMPv3 Report fires on Query receipt
        # (None = no Report pending), coalescing multiple inbound
        # Queries the same way the MLDv2 sibling does.
        self._igmp_query__pending_response_at_ms: int | None = None
        self._igmp_query__handle: TimerHandle | None = None
        # RFC 2236 §3 v1/v2 report suppression: groups whose pending
        # Query response has been suppressed by another host's Report
        # within the current response window.
        self._igmp_query__suppressed_groups: set[Ip4Address] = set()
        # RFC 3376 §5.2 per-group response state (Group-Specific +
        # Group-and-Source-Specific Query).
        self._igmp_group_query__pending: dict[Ip4Address, IgmpGroupQueryPending] = {}
        # RFC 3376 §7.2.1 Older Version Querier Present deadlines (ms);
        # None = no v1/v2 querier seen within the timeout (IGMPv3 mode).
        self._igmp__v1_querier_present_until_ms: int | None = None
        self._igmp__v2_querier_present_until_ms: int | None = None

        self._ip6_proto_registry = DispatchRegistry()
        self._ip6_proto_registry.register(IpProto.ICMP6, self._phrx_icmp6)
        self._ip6_proto_registry.register(IpProto.UDP, self._phrx_udp)
        self._ip6_proto_registry.register(IpProto.TCP, self._phrx_tcp)

    def _build_ethertype_registry(self) -> None:
        """
        (Re)build the link-layer EtherType dispatch registry from the
        current IPv4 / IPv6 protocol-support flags. 'PacketHandlerL2'
        overrides this to add the L2-only ARP entry. Re-callable so a
        support-flag change can be reflected in the registry.
        """

        self._ethertype_registry = DispatchRegistry()
        if self._ip4_support:
            self._ethertype_registry.register(EtherType.IP4, self._phrx_ip4)
        if self._ip6_support:
            self._ethertype_registry.register(EtherType.IP6, self._phrx_ip6)

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        """
        Marshal a '_phtx_*' pipeline call onto this interface's TX
        worker thread (ring-handoff single-writer) and return its
        'TxStatus'. Every stack-originated or stack-generated TX
        operation — socket sends, RX-thread replies, timer-thread
        retransmits, neighbor solicitations / advertisements —
        funnels through here so the per-interface TX state
        ('_ip4_id', stat counters, the ifaddr lists read during
        assembly) is written by one thread only. 'TxRing.dispatch'
        runs the call inline when there is no live worker (unit-test
        / boot path) or when the caller is already the worker (a
        re-entrant solicitation emitted mid-pipeline), so wrapping
        every entry point is safe even when they nest.
        """

        assert self._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        return self._tx_ring.dispatch(run)

    def _marshal_tx_async(self, run: Callable[[], TxStatus], /) -> None:
        """
        Fire-and-forget variant of '_marshal_tx' (Phase 4b async
        send): hand a '_phtx_*' call to this interface's TX worker
        and return immediately without waiting for the 'TxStatus'.
        The UDP / raw socket send paths use this so the application
        thread is not blocked on the worker; the datagram is
        "accepted into the stack" the moment it is queued, matching
        Linux's queued-on-send UDP semantics. Delivery failures
        (no route, ARP timeout, ICMP error) surface asynchronously,
        not through the send() return value.
        """

        assert self._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._tx_ring.dispatch_async(run)

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return [ip6_host.address for ip6_host in self._ip6_ifaddr]

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self._ip4_ifaddr]

    @property
    def _ip4_multicast(self) -> list[Ip4Address]:
        """
        Get the list of IPv4 multicast groups the interface listens on —
        a derived read-only view over the materialized per-group filter
        map (the groups with reception state). RFC 3376 §3.2 reception
        state is the source of truth; this flat list is the join-set
        view the RX accept / TX source / IGMP report paths consume.
        """

        with self._lock__multicast:
            return list(self._ip4_multicast_filters)

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        ip4_broadcast = [ip4_host.network.broadcast for ip4_host in self._ip4_ifaddr]
        ip4_broadcast.append(Ip4Address(0xFFFFFFFF))

        return ip4_broadcast

    def _accepts_local_dst_ip4(self, dst: Ip4Address, /) -> bool:
        """
        Return whether an inbound IPv4 datagram destined to 'dst' is for
        this interface to deliver locally — the RFC 1812 §5.2.1
        host-deliver test. True when no unicast is configured yet (the
        DHCP-client accept-all bootstrap) or 'dst' is one of this
        interface's unicast / joined-multicast / broadcast addresses.
        The loopback interface overrides this to also accept the whole
        127.0.0.0/8 range and any of the host's own unicast addresses.
        """

        return (not self._ip4_unicast) or dst in {
            *self._ip4_unicast,
            *self._ip4_multicast,
            *self._ip4_broadcast,
        }

    def _accepts_local_dst_ip6(self, dst: Ip6Address, /) -> bool:
        """
        Return whether an inbound IPv6 datagram destined to 'dst' is for
        this interface to deliver locally — the host-deliver test. True
        when 'dst' is one of this interface's unicast or joined-multicast
        addresses (the latter covers link-local, solicited-node, and the
        all-nodes group). The loopback interface overrides this to also
        accept ::1 and any of the host's own unicast addresses.
        """

        return dst in {*self._ip6_unicast, *self._ip6_multicast}

    @override
    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem thread.
        """

        self._acquire_ip4_addresses()
        self._acquire_ip6_addresses()

        self._log_stack_address_info()

    def _thread__packet_handler__acquire_ip6_addresses(self) -> None:
        """
        Thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Started the IPv6 address acquire thread")

        self._create_stack_ip6_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv6 address acquire thread")

    def _thread__packet_handler__acquire_ip4_addresses(self) -> None:
        """
        Thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Started the IPv4 address acquire thread")

        self._create_stack_ip4_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv4 address acquire thread")

    @abstractmethod
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.
        """

        raise NotImplementedError

    @abstractmethod
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        raise NotImplementedError

    def _acquire_ip6_addresses(self) -> None:
        """
        Start thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Starting the IPv6 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip6_addresses,
            daemon=True,
        ).start()

    def _acquire_ip4_addresses(self) -> None:
        """
        Start thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Starting the IPv4 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip4_addresses,
            daemon=True,
        ).start()

    def _assign_ip6_host(self, /, ip6_host: Ip6IfAddr) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_ifaddr = [*self._ip6_ifaddr, ip6_host]

        __debug__ and log("stack", f"Assigned IPv6 unicast address {ip6_host}")

        self.assign_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _remove_ip6_host(self, /, ip6_host: Ip6IfAddr) -> None:
        """
        Remove IPv6 host unicast address from the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_ifaddr = [host for host in self._ip6_ifaddr if host != ip6_host]

        __debug__ and log("stack", f"Removed IPv6 unicast address {ip6_host}")

        self.remove_ip6_multicast(ip6_host.address.solicited_node_multicast)

    @abstractmethod
    def claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
        on_conflict: Callable[[Ip6Address], None] | None = None,
    ) -> threading.Thread:
        """
        Claim 'ip6_host' on a daemon worker thread (DAD on L2,
        direct assign on L3). Returns the worker so callers
        that need to wait can '.join()'.

        When 'regenerate' is supplied, on DAD failure the
        worker calls it up to 'icmp6.idgen_retries' times to
        get a fresh candidate (RFC 7217 §6 / RFC 8981 §3.3.3).
        Each retry runs a full DAD cycle; the worker installs
        the first candidate that passes.

        When 'on_conflict' is supplied, it is invoked with the
        conflicting address if DAD ultimately fails (after any
        'regenerate' retries) — the hook the DHCPv6 client uses
        to DECLINE a leased duplicate (RFC 8415 §18.2.8).
        """

        raise NotImplementedError

    @abstractmethod
    def assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        raise NotImplementedError

    @abstractmethod
    def remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        raise NotImplementedError

    @abstractmethod
    def _assign_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Assign IPv4 multicast group to the list stack listens on.
        """

        raise NotImplementedError

    @abstractmethod
    def _remove_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Remove IPv4 multicast group from the list stack listens on.
        """

        raise NotImplementedError

    def mc_is_joined(self, group: Ip4Address, /) -> bool:
        """
        Return whether the interface currently listens on IPv4 multicast
        'group'. The materialized filter map is the source of truth and
        also covers the permanent all-systems group 224.0.0.1.
        """

        with self._lock__multicast:
            return group in self._ip4_multicast_filters

    def _mc_recompute(self, group: Ip4Address, /) -> None:
        """
        Re-derive the merged interface filter for 'group' from its
        per-socket + operator contributors (RFC 3376 §3.2) and reconcile
        the materialized reception state. Crossing into reception joins
        the group (MAC filter + state-change Report via
        '_assign_ip4_multicast'); losing reception leaves it (via
        '_remove_ip4_multicast'); a filter change while still joined
        updates the materialized filter. The permanent all-systems group
        224.0.0.1 is assigned directly and never recomputed here.
        """

        with self._lock__multicast:
            membership = self._ip4_multicast_refs.get(group)
            merged = Ip4MulticastFilter.merge(membership.contributors() if membership is not None else [])
            joined = self.mc_is_joined(group)

            if merged.has_reception:
                if not joined:
                    # Reception edge: '_assign_ip4_multicast' materializes
                    # the merged filter, programs the MAC, and emits the
                    # §5.1 join difference record(s).
                    self._assign_ip4_multicast(group)
                elif merged != self._ip4_multicast_filters[group]:
                    # Still joined, filter changed: emit the §5.1 source
                    # delta (ALLOW / BLOCK / CHANGE_TO_*) and re-materialize.
                    old = self._ip4_multicast_filters[group]
                    self._ip4_multicast_filters[group] = merged
                    self._send_igmp_state_change(group, old=old, new=merged)
            elif joined:
                self._remove_ip4_multicast(group)

    def mc_ref_acquire(self, group: Ip4Address, /) -> None:
        """
        Acquire the operator hold on IPv4 multicast 'group' (the
        set-once 'ip maddr'-style EXCLUDE{} any-source contributor) and
        recompute the merged interface filter. The permanent all-systems
        group 224.0.0.1 is never ref-managed (RFC 3376 §5.1 join edge).
        """

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            return

        with self._lock__multicast:
            self._ip4_multicast_refs.setdefault(group, _Ip4GroupMembership()).operator = True
            self._mc_recompute(group)

    def mc_ref_release(self, group: Ip4Address, /) -> None:
        """
        Release the operator hold on IPv4 multicast 'group' and recompute
        the merged interface filter; the group leaves only when no
        contributor (operator or socket) remains. Idempotent. The
        permanent all-systems group 224.0.0.1 is never dropped here
        (RFC 1112 §4; RFC 3376 §5.1 leave edge).
        """

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            return

        with self._lock__multicast:
            membership = self._ip4_multicast_refs.get(group)
            if membership is None:
                return

            membership.operator = False
            if not membership.operator and not membership.socket_filters:
                del self._ip4_multicast_refs[group]
            self._mc_recompute(group)

    def mc_set_socket_filter(self, group: Ip4Address, /, *, token: int, source_filter: Ip4MulticastFilter) -> None:
        """
        Register / replace the source filter socket 'token' holds on IPv4
        multicast 'group' (RFC 3376 §3.1 per-socket state) and recompute
        the merged interface filter (§3.2). A socket joining the
        all-systems group 224.0.0.1 is a no-op — it is permanent and
        never IGMP-managed.
        """

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            return

        with self._lock__multicast:
            self._ip4_multicast_refs.setdefault(group, _Ip4GroupMembership()).socket_filters[token] = source_filter
            self._mc_recompute(group)

    def mc_clear_socket_filter(self, group: Ip4Address, /, *, token: int) -> None:
        """
        Drop the source filter socket 'token' held on IPv4 multicast
        'group' (the socket left, per RFC 3376 §3.1 INCLUDE{} delete) and
        recompute the merged interface filter (§3.2); the group leaves
        only when no contributor remains. Idempotent. The all-systems
        group 224.0.0.1 is never managed here.
        """

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            return

        with self._lock__multicast:
            membership = self._ip4_multicast_refs.get(group)
            if membership is None:
                return

            membership.socket_filters.pop(token, None)
            if not membership.operator and not membership.socket_filters:
                del self._ip4_multicast_refs[group]
            self._mc_recompute(group)

    def _assign_ip4_host(self, /, ip4_host: Ip4IfAddr) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip4_ifaddr = [*self._ip4_ifaddr, ip4_host]

        __debug__ and log("stack", f"Assigned IPv4 unicast address {ip4_host}")

    def _remove_ip4_host(self, /, ip4_host: Ip4IfAddr) -> None:
        """
        Remove IPv4 host unicast address from the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip4_ifaddr = [host for host in self._ip4_ifaddr if host != ip4_host]

        __debug__ and log("stack", f"Removed IPv4 unicast address {ip4_host}")

    def assign_ip4_ifaddr(self, ifaddr: Ip4IfAddr, /) -> None:
        """
        Install 'ifaddr' on this interface's IPv4 address list — the
        Address API's 'add' mutator. Publishes a fresh list reference
        under '_lock__addr_config' (copy-on-write): the TX worker reads
        the address list during source-address selection on a different
        thread, so the writer swaps a whole new list (the reader sees the
        old or new list whole, never a mid-append state) while the lock
        serialises this writer against the RX / SLAAC / DAD writers.
        Targets free-threaded CPython — GIL atomicity is not relied upon.
        """

        with self._lock__addr_config:
            self._ip4_ifaddr = [*self._ip4_ifaddr, ifaddr]

    def remove_ip4_ifaddr(self, address: Ip4Address, /) -> int:
        """
        Remove every IPv4 host whose '.address' equals 'address' from
        this interface's address list — the Address API's 'remove'
        mutator — and return the number of hosts removed. Copy-on-write
        under '_lock__addr_config' (see 'assign_ip4_ifaddr').
        """

        with self._lock__addr_config:
            before = len(self._ip4_ifaddr)
            self._ip4_ifaddr = [host for host in self._ip4_ifaddr if host.address != address]
            return before - len(self._ip4_ifaddr)

    def assign_ip6_ifaddr(self, ifaddr: Ip6IfAddr, /) -> None:
        """
        Install 'ifaddr' on this interface's IPv6 address list (the
        non-DAD direct path) and join its solicited-node multicast group
        (RFC 4291 §2.7.1) — the Address API's 'add' mutator for an IPv6
        host that has already been DAD-vetted (or opted out of DAD).
        Copy-on-write under '_lock__addr_config' (see 'assign_ip4_ifaddr');
        the solicited-node multicast assignment runs outside the address-
        config lock, mirroring '_assign_ip6_host'.
        """

        with self._lock__addr_config:
            self._ip6_ifaddr = [*self._ip6_ifaddr, ifaddr]
        self.assign_ip6_multicast(ifaddr.address.solicited_node_multicast)

    def remove_ip6_ifaddr(self, address: Ip6Address, /) -> list[Ip6IfAddr]:
        """
        Remove every IPv6 host whose '.address' equals 'address' from
        this interface's address list — the Address API's 'remove'
        mutator — leave each removed host's solicited-node multicast
        group, and return the removed hosts (for the caller's log line).
        Copy-on-write under '_lock__addr_config' (see 'assign_ip4_ifaddr').
        """

        with self._lock__addr_config:
            removed_hosts = [host for host in self._ip6_ifaddr if host.address == address]
            self._ip6_ifaddr = [host for host in self._ip6_ifaddr if host.address != address]
        for host in removed_hosts:
            self.remove_ip6_multicast(host.address.solicited_node_multicast)
        return removed_hosts

    def set_interface_mtu(self, mtu: int, /) -> None:
        """
        Set this interface's MTU in bytes — the Link API's 'set_mtu'
        mutator. '_interface_mtu' is the canonical source of truth the TX
        paths read for MSS / fragmentation decisions; the per-interface
        RX / TX rings cache it as the read / writev size bound, so both
        are updated here. Range validation is the Link API's
        responsibility.

        The 'getattr' / 'AttributeError' tolerance covers the test
        fixtures: 'mock__init' handlers that skip ring construction (the
        ring is None → skipped) and 'create_autospec(TxRing,
        spec_set=True)' ring mocks (whose proxy does not expose the
        '_mtu' slot the real 'set_mtu' writes).
        """

        self._interface_mtu = mtu
        for ring in (self._tx_ring, self._rx_ring):
            if ring is None:
                continue
            try:
                ring.set_mtu(mtu)
            except AttributeError:
                pass

    def set_mac_address(self, mac_address: MacAddress, /) -> None:
        """
        Set this interface's unicast MAC address — the Link API's
        'set_mac_address' mutator. Valid only on an L2 (TAP) interface
        with the stack stopped; the Link API enforces those preconditions
        and the unicast / non-zero validity of 'mac_address' before
        calling.
        """

        self._mac_unicast = mac_address

    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (self._ip6_support, self._ip4_support):
            self._ip_configuration_in_progress.acquire(timeout=15)

        if __debug__:
            if self._ip6_support:
                log(
                    "stack",
                    f"<INFO>Interface {self._interface_name} listening on unicast IPv6 addresses: "
                    f"{', '.join([str(ip6_unicast) for ip6_unicast in self.ip6_unicast])}</>",
                )
                log(
                    "stack",
                    f"<INFO>Interface {self._interface_name} listening on multicast IPv6 addresses: "
                    f"{', '.join([str(ip6_multicast) for ip6_multicast in set(self._ip6_multicast)])}</>",
                )

            if self._ip4_support:
                log(
                    "stack",
                    f"<INFO>Interface {self._interface_name} listening on unicast IPv4 addresses: "
                    f"{', '.join([str(ip4_unicast) for ip4_unicast in self._ip4_unicast])}</>",
                )
                log(
                    "stack",
                    f"<INFO>Interface {self._interface_name} listening on multicast IPv4 addresses: "
                    f"{', '.join([str(ip4_multicast) for ip4_multicast in self._ip4_multicast])}</>",
                )
                log(
                    "stack",
                    f"<INFO>Interface {self._interface_name} listening on broadcast IPv4 addresses: "
                    f"{', '.join([str(ip4_broadcast) for ip4_broadcast in self._ip4_broadcast])}</>",
                )

    ###
    # Public interface.
    ###

    @property
    def _packet_stats_rx(self) -> PacketStatsRx:
        """
        Get the calling thread's RX statistics shard (the lock-free
        per-thread increment target).
        """

        return self._stats_rx.current()

    @property
    def _packet_stats_tx(self) -> PacketStatsTx:
        """
        Get the calling thread's TX statistics shard (the lock-free
        per-thread increment target).
        """

        return self._stats_tx.current()

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        """
        Get the packet statistics for received packets.
        """

        return self._stats_rx.snapshot()

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        """
        Get the packet statistics for transmitted packets.
        """

        return self._stats_tx.snapshot()

    @property
    def ip6_host(self) -> list[Ip6IfAddr]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip6_ifaddr

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return self._ip6_unicast

    @property
    def ip6_multicast(self) -> list[Ip6Address]:
        """
        Get the list of IPv6 multicast groups the interface listens on.
        Read surface for the socket factory's 'IPV6_JOIN_GROUP' /
        'IPV6_LEAVE_GROUP' idempotence check; the '_ip6_multicast' list
        stays the storage.
        """

        return self._ip6_multicast

    @property
    def ip4_host(self) -> list[Ip4IfAddr]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip4_ifaddr

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast

    @property
    def ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        return self._ip4_broadcast

    @property
    def interface_name(self) -> str | None:
        """
        Get the interface name this handler serves. Read surface for the
        socket factory's SO_BINDTODEVICE name match; the
        '_interface_name' attribute stays the storage.
        """

        return self._interface_name

    @property
    def interface_mtu(self) -> int:
        """
        Get the interface MTU in bytes. Read surface for the Link API's
        'mtu' property and the per-destination 'egress_interface_mtu'
        helper; the '_interface_mtu' attribute stays the storage.
        """

        return self._interface_mtu

    @property
    def interface_layer(self) -> InterfaceLayer:
        """
        Get the interface layer (L2 = TAP, L3 = TUN). Read surface for
        the Link API's 'interface_layer' / 'flags' / stat-aggregation
        paths; the '_interface_layer' attribute stays the storage.
        """

        return self._interface_layer

    @property
    def ifindex(self) -> int:
        """
        Get the per-interface index (Linux ifindex). Read surface for the
        FIB teardown / introspection paths; the '_ifindex' attribute
        stays the storage.
        """

        return self._ifindex

    def set_ifindex(self, ifindex: int, /) -> None:
        """
        Stamp the allocated per-interface index onto this handler — the
        'InterfaceTable.add' construction-time wiring (the table owns
        monotonic ifindex allocation under its lock and stamps the result
        here).
        """

        self._ifindex = ifindex

    @property
    def mac_unicast(self) -> MacAddress | None:
        """
        Get the interface unicast MAC address, or 'None' on an L3 (TUN)
        interface that has no Ethernet layer. Read surface for the Link
        API's 'mac_address' property; the '_mac_unicast' attribute (set
        only on 'PacketHandlerL2') stays the storage.
        """

        return getattr(self, "_mac_unicast", None)

    @property
    def link_stats(self) -> LinkStatsCounters:
        """
        Get the live per-interface link-level aggregate counters (bytes /
        multicast) shared with the RX / TX rings. Read surface for the
        Link API's 'stats' aggregation; the '_link_stats' attribute stays
        the storage.
        """

        return self._link_stats

    @property
    def ip4_multicast(self) -> list[Ip4Address]:
        """
        Get the list of IPv4 multicast groups the interface listens on.
        Read surface for the Membership API; the derived '_ip4_multicast'
        view stays the storage.
        """

        return self._ip4_multicast

    @property
    def ip4_ifaddr(self) -> tuple[Ip4IfAddr, ...]:
        """
        Get a read-only, copy-by-value snapshot of the stack's IPv4
        interface addresses (the Phase-3 "introspection is read-only"
        contract). Read surface for the Route / Address APIs; the
        '_ip4_ifaddr' list stays the storage.
        """

        return tuple(self._ip4_ifaddr)

    @property
    def ip6_ifaddr(self) -> tuple[Ip6IfAddr, ...]:
        """
        Get a read-only, copy-by-value snapshot of the stack's IPv6
        interface addresses (the Phase-3 "introspection is read-only"
        contract). Read surface for the Route / Address APIs; the
        '_ip6_ifaddr' list stays the storage.
        """

        return tuple(self._ip6_ifaddr)

    @property
    def arp_cache(self) -> ArpCache | None:
        """
        Get the per-interface ARP cache, or 'None' on an L3 (TUN)
        interface that has no ARP. Read surface for the Neighbor API; the
        '_arp_cache' attribute stays the storage.
        """

        return self._arp_cache

    @property
    def nd_cache(self) -> NdCache | None:
        """
        Get the per-interface ND cache, or 'None' for a standalone
        unit-test handler with no cache wired. Read surface for the
        Neighbor API; the '_nd_cache' attribute stays the storage.
        """

        return self._nd_cache

    @property
    def dhcp4_client(self) -> Dhcp4Client | None:
        """
        Get the per-interface DHCPv4 client, or 'None' when the interface
        runs no DHCPv4 client. Read surface for the activity-introspection
        API; the '_dhcp4_client' attribute (set only on 'PacketHandlerL2')
        stays the storage.
        """

        return getattr(self, "_dhcp4_client", None)

    @property
    def dhcp6_client(self) -> Dhcp6Client | None:
        """
        Get the per-interface DHCPv6 client, or 'None' when no client is
        installed. Read surface for the stack-lifecycle start / stop
        paths; the '_dhcp6_client' attribute stays the storage.
        """

        return self._dhcp6_client

    @property
    def rx_ring(self) -> RxRing | None:
        """
        Get the per-interface RX ring, or 'None' for a standalone
        unit-test handler with no ring wired. Read surface for the
        stack-lifecycle start / stop paths; the '_rx_ring' attribute
        stays the storage.
        """

        return self._rx_ring

    @property
    def tx_ring(self) -> TxRing | None:
        """
        Get the per-interface TX ring, or 'None' for a standalone
        unit-test handler with no ring wired. Read surface for the
        stack-lifecycle start / stop paths; the '_tx_ring' attribute
        stays the storage.
        """

        return self._tx_ring

    @property
    def route_api(self) -> RouteApi | None:
        """
        Get the injected routing-control API, or 'None' until injected.
        Read surface for the stack lifecycle; the '_route_api' attribute
        stays the storage.
        """

        return self._route_api

    def attach_rings(self, *, rx_ring: RxRing | None = None, tx_ring: TxRing | None = None) -> None:
        """
        Bind this interface's fd-bound RX / TX rings post-construction —
        the 'stack.mock__init' test affordance uses this to install mock
        rings independently (the real 'add_interface' path passes them as
        constructor arguments). Only the supplied ring(s) are replaced; a
        'None' argument leaves the existing binding untouched.
        """

        if rx_ring is not None:
            self._rx_ring = rx_ring
        if tx_ring is not None:
            self._tx_ring = tx_ring

    def attach_caches(self, *, arp_cache: "ArpCache | None", nd_cache: "NdCache", iface_name: str | None) -> None:
        """
        Bind this interface's neighbor caches and the reverse owner
        back-reference (the bidirectional cache <-> handler link) — the
        stack lifecycle's construction-time wiring. ARP is L2-only, so
        'arp_cache' is 'None' on an L3 (TUN) handler; ND is used by both
        layers. The 'iface_name' plumbs the interface name into each
        cache's per-interface 'neighbor.<ifname>.*' sysctl resolution.
        """

        # 'self' is always a concrete L2 / L3 handler at runtime (the
        # base 'PacketHandler' is abstract); the narrowing satisfies the
        # caches' 'attach_owner' owner type.
        assert isinstance(self, (PacketHandlerL2, PacketHandlerL3)), "Caches bind only to a concrete interface."
        self._arp_cache = arp_cache
        self._nd_cache = nd_cache
        if arp_cache is not None:
            # ARP is L2-only — a non-None ARP cache is only ever attached
            # to an L2 (TAP) handler.
            assert isinstance(self, PacketHandlerL2), "ARP cache may only bind to an L2 interface."
            arp_cache.attach_owner(self, iface_name=iface_name)
        nd_cache.attach_owner(self, iface_name=iface_name)

    def attach_arp_cache(self, arp_cache: "ArpCache", /) -> None:
        """
        Bind this interface's ARP cache on its own (the 'stack.mock__init'
        test affordance's narrow ARP-only path) and the reverse owner
        back-reference. The production path uses 'attach_caches', which
        binds both neighbor caches together. ARP is L2-only.
        """

        assert isinstance(self, PacketHandlerL2), "ARP cache may only bind to an L2 interface."
        self._arp_cache = arp_cache
        arp_cache.attach_owner(self, iface_name=None)

    def attach_route_api(self, route_api: RouteApi, /) -> None:
        """
        Inject the routing-control API (global state shared across
        interfaces) — the stack lifecycle's construction-time wiring. The
        RX RA path drives the default route through this.
        """

        self._route_api = route_api

    def attach_dhcp6_client(self, client: Dhcp6Client, /) -> None:
        """
        Bind this interface's DHCPv6 client (RFC 8415) — the stack
        lifecycle's construction-time wiring. RA-driven: the RA RX
        handler triggers it on an inbound RA's Managed / Other-config
        flags.
        """

        self._dhcp6_client = client

    @property
    def dad_states(self) -> dict[Ip6Address, Icmp6DadState]:
        """
        Get a copy-by-value snapshot of the RFC 4429 §3.1 Optimistic DAD
        per-address state map (the Phase-3 "introspection is read-only"
        contract). Read surface for the activity-introspection API's
        tentative-address view; the '_icmp6_dad__states' map stays the
        storage.
        """

        return dict(self._icmp6_dad__states)

    def select_ip6_source(self, destination: Ip6Address, /) -> Ip6Address | None:
        """
        Run RFC 6724 default source-address selection over this
        interface's IPv6 addresses for a packet bound to 'destination',
        returning the winner or 'None' when no acceptable source is
        found. Read surface for 'stack.select_local_ip6_source'; the
        per-interface IPv6 TX sub-handler does the work.
        """

        return self._ip6_tx._select_ip6_source(ip6__dst=destination)

    def select_ip4_source(self, destination: Ip4Address, /) -> Ip4Address | None:
        """
        Select the IPv4 source address over this interface's IPv4
        addresses for a packet bound to 'destination', returning the
        winner or 'None' when no acceptable source is found. Read surface
        for 'stack.select_local_ip4_source'; the per-interface IPv4 TX
        sub-handler does the work.
        """

        return self._ip4_tx._select_ip4_source(ip4__dst=destination)

    def _update_icmp6_default_router(
        self,
        *,
        address: Ip6Address,
        router_lifetime: int,
        prf: Icmp6NdRoutePreference = Icmp6NdRoutePreference.MEDIUM,
    ) -> None:
        """
        Apply an inbound RA's Router Lifetime to the default-
        router list per RFC 4861 §6.3.4. A non-zero lifetime
        installs / refreshes the entry; a zero lifetime removes
        it. The RFC 4191 Default Router Preference is captured
        on the entry; RFC 4191 §2.2 mandates that a RESERVED
        (binary 10) advertisement be normalised to MEDIUM at the
        receiver. Bumps 'update_router' or 'remove_router'
        counters only when the list actually changes.
        """

        existing = next(
            (r for r in self._icmp6_default_routers if r.address == address),
            None,
        )

        # Phase 3 of docs/refactor/routing_table_host_mode.md:
        # the RA's router lifetime drives the host-mode FIB
        # default route. This is the single chokepoint where RA
        # router info is consumed — the per-IfAddr
        # 'ip6_host.gateway = ...' writes the SLAAC / RFC 8981 /
        # RFC 7217 paths used are gone (the FIB owns the next
        # hop). The injected '_route_api' may be None in reduced
        # test contexts that drive this without a Route API bound.
        route_api = self._route_api

        if router_lifetime > 0:
            normalised_prf = Icmp6NdRoutePreference.MEDIUM if prf is Icmp6NdRoutePreference.RESERVED else prf
            new_router = Icmp6DefaultRouter(
                address=address,
                lifetime=router_lifetime,
                expires_at=time.monotonic() + router_lifetime,
                prf=normalised_prf,
            )
            with self._lock__addr_config:
                self._icmp6_default_routers = [r for r in self._icmp6_default_routers if r.address != address] + [
                    new_router
                ]
            self._packet_stats_rx.icmp6__nd_router_advertisement__update_router += 1
            if route_api is not None:
                route_api.replace_default(gateway=address, protocol=RouteProtocol.RA, oif=self._ifindex)
            return

        if existing is not None:
            with self._lock__addr_config:
                self._icmp6_default_routers = [r for r in self._icmp6_default_routers if r.address != address]
            self._packet_stats_rx.icmp6__nd_router_advertisement__remove_router += 1
            if route_api is not None:
                route_api.remove_default(family=AddressFamily.INET6)

    def get_icmp6_default_routers(self) -> list[Icmp6DefaultRouter]:
        """
        Get the list of currently-active default-router entries
        per RFC 4861 §6.3.4 sorted by RFC 4191 preference
        (HIGH > MEDIUM > LOW) so a TX-side consumer that picks
        the first valid entry naturally selects the most-
        preferred router. Lazy-aged: entries whose 'expires_at'
        deadline has passed are filtered out at access time
        instead of removed by a background sweep.
        """

        now = time.monotonic()
        prf_rank = {
            Icmp6NdRoutePreference.HIGH: 0,
            Icmp6NdRoutePreference.MEDIUM: 1,
            Icmp6NdRoutePreference.LOW: 2,
        }
        active = [r for r in self._icmp6_default_routers if r.expires_at > now]
        # 'RESERVED' was normalised to MEDIUM at install time; the
        # rank dict has no entry for it, so a defensive fallback
        # places any stray RESERVED at MEDIUM rank.
        active.sort(key=lambda r: prf_rank.get(r.prf, prf_rank[Icmp6NdRoutePreference.MEDIUM]))
        return active

    def _update_icmp6_slaac_address(
        self,
        *,
        prefix: Ip6Network,
        valid_lifetime: int,
        preferred_lifetime: int,
        router_address: Ip6Address,
    ) -> None:
        """
        Apply an inbound Prefix-Information option to the SLAAC
        address table per RFC 4862 §5.5.3. A non-zero
        'valid_lifetime' installs / refreshes the entry; zero
        'valid_lifetime' removes a matching entry (the §5.5.3
        (e)(6)(a) "advertised lifetime overwrites address valid
        lifetime" rule collapses to removal at value 0). The
        2-hour rule (e)(6)(b)/(c) clamps refresh on existing
        entries: an unauthenticated router cannot shorten an
        address's remaining lifetime below 2 hours unless the
        existing remaining is already ≤ 2 hours. Bumps
        'pi__update_address' / 'pi__remove_address' /
        'pi__2hour_rule_ignored__drop' counters per the path
        actually taken.
        """

        existing = next(
            (a for a in self._icmp6_slaac_addresses if a.prefix == prefix),
            None,
        )

        if valid_lifetime == 0:
            if existing is not None:
                with self._lock__addr_config:
                    self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.prefix != prefix]
                self._packet_stats_rx.icmp6__nd_router_advertisement__pi__remove_address += 1
            return

        now = time.monotonic()

        # RFC 4862 §5.5.3 (e)(6) 2-hour rule. Only applies on
        # refresh (existing is not None); first-install bypasses
        # the safeguard entirely. PyTCP has no SEND support so
        # case (b) is unconditional.
        new_valid_lifetime = valid_lifetime
        if existing is not None:
            remaining = existing.valid_until - now
            two_hour_s = nd__constants.ICMP6__SLAAC__TWO_HOUR_RULE_S
            if valid_lifetime > two_hour_s or valid_lifetime > remaining:
                new_valid_lifetime = valid_lifetime
            elif remaining <= two_hour_s:
                self._packet_stats_rx.icmp6__nd_router_advertisement__pi__2hour_rule_ignored__drop += 1
                return
            else:
                new_valid_lifetime = two_hour_s

        address = self._derive_ip6_host(ip6_network=prefix).address

        new_slaac = Icmp6SlaacAddress(
            address=address,
            prefix=prefix,
            preferred_until=now + preferred_lifetime,
            valid_until=now + new_valid_lifetime,
            router_address=router_address,
        )
        with self._lock__addr_config:
            self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.prefix != prefix] + [new_slaac]
        self._packet_stats_rx.icmp6__nd_router_advertisement__pi__update_address += 1

        # Runtime stable-address claim: a brand-new prefix
        # admitted AFTER boot-time addressing completed needs
        # a DAD claim — boot loop only handles prefixes that
        # arrived during the boot window. The
        # '_ip6_addressing_complete' flag gates this so the
        # boot loop's own claim path doesn't double up. On
        # refresh ('existing is not None') no claim is needed
        # — the stable address is already in '_ip6_ifaddr'.
        if existing is None and self._ip6_addressing_complete:
            ip6_host = Ip6IfAddr((address, Ip6Mask("/64")))
            self.claim_ip6_address_async(
                ip6_host=ip6_host,
                regenerate=self._make_rfc7217_regenerator(ip6_network=prefix),
            )

    def get_icmp6_slaac_addresses(self) -> list[Icmp6SlaacAddress]:
        """
        Get the list of currently-active SLAAC address entries
        per RFC 4862 §5.5.3. Lazy-aged: entries whose
        'valid_until' deadline has passed are filtered out at
        access time instead of removed by a background sweep.
        """

        now = time.monotonic()
        return [a for a in self._icmp6_slaac_addresses if a.valid_until > now]

    def _update_icmp6_temp_address(
        self,
        *,
        prefix: Ip6Network,
        valid_lifetime: int,
        preferred_lifetime: int,
        router_address: Ip6Address,
    ) -> None:
        """
        Apply an inbound Prefix-Information option to the
        RFC 8981 §3 temporary-address table. No-op when
        'icmp6.use_tempaddr=0'. Otherwise:

        - 'valid_lifetime=0' removes any existing entry for
          the prefix (RFC 4862 §5.5.3 (e)(4) interaction
          applied to the temp table).
        - Existing entry: refresh the 'preferred_until' /
          'valid_until' deadlines but preserve the address
          (regeneration is §18c, not §18b).
        - New entry: generate a random IID via
          'Ip6IfAddr.from_rfc8981_temp', spawn an async DAD
          claim via 'claim_ip6_address_async', and append
          to '_icmp6_temp_addresses'.

        Lifetimes are clamped to TEMP_VALID_LIFETIME /
        TEMP_PREFERRED_LIFETIME (RFC 8981 §3.4 / §3.8). The
        preferred deadline is further offset by a random
        DESYNC_FACTOR to prevent fleet-wide synchronised
        regeneration; the §18c regeneration subsystem will
        consume the offset to schedule rotation.
        """

        if sysctl_iface.get_for_iface("icmp6.use_tempaddr", self._interface_name) == 0:
            return

        existing = next(
            (t for t in self._icmp6_temp_addresses if t.prefix == prefix),
            None,
        )

        if valid_lifetime == 0:
            if existing is not None:
                with self._lock__addr_config:
                    self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.prefix != prefix]
            return

        # RFC 8981 §3.4 lifetime clamps. The preferred lifetime
        # is reduced by a random DESYNC_FACTOR offset so a fleet
        # of hosts created together don't all rotate at the same
        # instant.
        now = time.monotonic()
        desync = random.uniform(0, sysctl_iface.get_for_iface("icmp6.max_desync_factor_s", self._interface_name))
        clamped_valid = min(
            valid_lifetime, sysctl_iface.get_for_iface("icmp6.temp_valid_lifetime_s", self._interface_name)
        )
        clamped_preferred_base = min(
            preferred_lifetime, sysctl_iface.get_for_iface("icmp6.temp_preferred_lifetime_s", self._interface_name)
        )
        clamped_preferred = max(0.0, clamped_preferred_base - desync)

        if existing is not None:
            # Refresh deadlines, preserve address. Drop the old
            # entry and append a new one with the same address.
            refreshed = Icmp6TempAddress(
                address=existing.address,
                prefix=prefix,
                preferred_until=now + clamped_preferred,
                valid_until=now + clamped_valid,
                created_at=existing.created_at,
                router_address=router_address,
            )
            with self._lock__addr_config:
                self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.prefix != prefix] + [refreshed]
            return

        # New entry — generate random IID, spawn DAD claim.
        try:
            temp_host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)
        except RuntimeError:
            # Reserved-IID retry exhaustion (broken random
            # source). Skip the temp address; the stable SLAAC
            # entry still carries the prefix.
            return

        new_temp = Icmp6TempAddress(
            address=temp_host.address,
            prefix=prefix,
            preferred_until=now + clamped_preferred,
            valid_until=now + clamped_valid,
            created_at=now,
            router_address=router_address,
        )
        with self._lock__addr_config:
            self._icmp6_temp_addresses = [*self._icmp6_temp_addresses, new_temp]

        # RFC 8981 §3.3.3 — on DAD failure, retry with a fresh
        # random IID up to 'icmp6.idgen_retries' times. Each
        # call to 'from_rfc8981_temp' yields a different IID
        # (no 'dad_counter' is needed; the random generator is
        # stateless).
        def _regenerate() -> Ip6IfAddr:
            return Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)

        # Spawn async DAD claim. The worker will assign the
        # address into '_ip6_ifaddr' on success or fall through
        # to the failure path on collision (where retries
        # exhaust before the temp-table entry is left
        # orphaned).
        self.claim_ip6_address_async(ip6_host=temp_host, regenerate=_regenerate)

    def get_icmp6_temp_addresses(self) -> list[Icmp6TempAddress]:
        """
        Get the list of currently-active RFC 8981 temporary
        addresses. Lazy-aged: entries whose 'valid_until'
        deadline has passed are filtered out at access time
        instead of removed by a background sweep.
        """

        now = time.monotonic()
        return [t for t in self._icmp6_temp_addresses if t.valid_until > now]

    def _icmp6_sweep_temp_addresses(self) -> None:
        """
        Remove temporary addresses whose 'valid_until'
        deadline has passed from BOTH '_icmp6_temp_addresses'
        AND '_ip6_ifaddr'. The lazy accessor
        ('get_icmp6_temp_addresses') already filters out
        expired entries at read time, but '_ip6_ifaddr' is the
        hot list that the RX dispatch and TX source-address
        selection both walk directly — leaving expired
        entries there would mean the host kept receiving on
        and sourcing from addresses whose valid lifetime has
        elapsed.

        Invoked periodically from the subsystem loop, rate-
        limited by 'icmp6.temp_addr_sweep_interval_s'.

        Reference: RFC 8981 §3.4 (expired temp address must
                                  not be used for new traffic).
        """

        now = time.monotonic()
        expired = [t for t in self._icmp6_temp_addresses if t.valid_until <= now]
        if not expired:
            return

        # Hold the address-config lock across the cluster mutation so
        # '_ip6_ifaddr', '_ip6_multicast' and '_icmp6_temp_addresses'
        # are republished (copy-on-write) as a consistent set. No
        # blocking call runs inside the lock.
        with self._lock__addr_config:
            for entry in expired:
                __debug__ and log(
                    "stack",
                    f"<INFO>RFC 8981 sweep: temp address {entry.address} "
                    f"(prefix {entry.prefix}) past valid_until — removing</>",
                )
                # Drop from '_ip6_ifaddr'. The address may already
                # be absent (e.g. if a manual operator action
                # removed it). The solicited-node multicast may
                # already be absent too (manual cleanup, never
                # joined). Both are tolerated — best-effort.
                for ip6_host in self._ip6_ifaddr:
                    if ip6_host.address == entry.address:
                        self._ip6_ifaddr = [host for host in self._ip6_ifaddr if host != ip6_host]
                        snm = ip6_host.address.solicited_node_multicast
                        if snm in self._ip6_multicast:
                            self.remove_ip6_multicast(snm)
                        break

            # Drop from the temp-address table.
            self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.valid_until > now]

    def _icmp6_regen_temp_addresses(self) -> None:
        """
        For each prefix represented in '_icmp6_temp_addresses',
        check whether the newest entry is approaching its
        REGEN_ADVANCE threshold (preferred_until - REGEN_ADVANCE
        <= now). If so, mint a fresh random IID for the same
        prefix and append it to the table — both the old and
        new entries coexist during the rotation-overlap window
        per RFC 8981 §3.4. Skip prefixes where a sibling entry
        is already past the regen threshold (the regen has
        already happened).

        No-op when 'icmp6.use_tempaddr=0'.

        Reference: RFC 8981 §3.4 (regenerate REGEN_ADVANCE
                                  before preferred lifetime
                                  expires).
        """

        if sysctl_iface.get_for_iface("icmp6.use_tempaddr", self._interface_name) == 0:
            return
        if not self._icmp6_temp_addresses:
            return

        now = time.monotonic()
        regen_advance_s = sysctl_iface.get_for_iface("icmp6.regen_advance_s", self._interface_name)

        # Group entries by prefix; for each prefix, find the
        # newest 'preferred_until'. If that newest entry is at
        # or past its regen-advance threshold, regenerate.
        prefixes_seen: set[Ip6Network] = set()
        for entry in list(self._icmp6_temp_addresses):
            prefix = entry.prefix
            if prefix in prefixes_seen:
                continue
            prefixes_seen.add(prefix)

            siblings = [t for t in self._icmp6_temp_addresses if t.prefix == prefix]
            newest = max(siblings, key=lambda t: t.preferred_until)

            # If the newest is far from the regen threshold,
            # nothing to do for this prefix.
            if newest.preferred_until - regen_advance_s > now:
                continue

            # Mint a fresh random IID for the same prefix.
            try:
                temp_host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)
            except RuntimeError:
                continue

            # Append a NEW entry alongside (not replacing) the
            # existing one. Lifetimes derived from the same
            # TEMP_*_LIFETIME ceilings as §18b.
            desync = random.uniform(0, sysctl_iface.get_for_iface("icmp6.max_desync_factor_s", self._interface_name))
            clamped_valid = sysctl_iface.get_for_iface("icmp6.temp_valid_lifetime_s", self._interface_name)
            clamped_preferred = max(
                0.0, sysctl_iface.get_for_iface("icmp6.temp_preferred_lifetime_s", self._interface_name) - desync
            )

            regen_temp = Icmp6TempAddress(
                address=temp_host.address,
                prefix=prefix,
                preferred_until=now + clamped_preferred,
                valid_until=now + clamped_valid,
                created_at=now,
                router_address=newest.router_address,
            )
            with self._lock__addr_config:
                self._icmp6_temp_addresses = [*self._icmp6_temp_addresses, regen_temp]

            # RFC 8981 §3.3.3 regen via §20.3 retry: each retry
            # mints a fresh random IID.
            def _regenerate(p: Ip6Network = prefix) -> Ip6IfAddr:
                return Ip6IfAddr.from_rfc8981_temp(ip6_network=p)

            __debug__ and log(
                "stack",
                f"<INFO>RFC 8981 regen: minting new temp address {temp_host} "
                f"for prefix {prefix} (existing {newest.address} approaching "
                "preferred-lifetime expiry)</>",
            )
            self.claim_ip6_address_async(ip6_host=temp_host, regenerate=_regenerate)

    def _icmp6_sweep_slaac_addresses(self) -> None:
        """
        Remove stable SLAAC entries past 'valid_until' from
        BOTH '_icmp6_slaac_addresses' AND '_ip6_ifaddr'. The
        lazy accessor 'get_icmp6_slaac_addresses()' already
        filters expired entries at read time, but '_ip6_ifaddr'
        is the hot list TX and RX walk directly — the stable
        address must be pruned there too once its valid
        lifetime has elapsed.

        Invoked periodically from '_maybe_run_periodic_tasks'
        alongside the §18c.1 temp-address sweep.

        Reference: RFC 4862 §5.5.3 (e)(7) (expired stable
                                           address must not
                                           be used).
        """

        now = time.monotonic()
        expired = [a for a in self._icmp6_slaac_addresses if a.valid_until <= now]
        if not expired:
            return

        # Hold the address-config lock across the cluster mutation so
        # '_ip6_ifaddr', '_ip6_multicast' and '_icmp6_slaac_addresses'
        # are republished (copy-on-write) as a consistent set. No
        # blocking call runs inside the lock.
        with self._lock__addr_config:
            for entry in expired:
                __debug__ and log(
                    "stack",
                    f"<INFO>SLAAC sweep: stable address {entry.address} "
                    f"(prefix {entry.prefix}) past valid_until — removing</>",
                )
                for ip6_host in self._ip6_ifaddr:
                    if ip6_host.address == entry.address:
                        self._ip6_ifaddr = [host for host in self._ip6_ifaddr if host != ip6_host]
                        snm = ip6_host.address.solicited_node_multicast
                        if snm in self._ip6_multicast:
                            self.remove_ip6_multicast(snm)
                        break

            self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.valid_until > now]

    def get_icmp6_default_router_for_destination(
        self,
        *,
        destination: Ip6Address,
    ) -> Icmp6DefaultRouter | None:
        """
        Pick a default router for outbound traffic to
        'destination' using deterministic per-destination
        distribution across the highest-preference equivalence
        class per RFC 4311 §3 host-to-router load sharing.

        The same destination always selects the same router so
        TCP flows aren't reordered, but distinct destinations
        spread across all highest-preference routers (preserving
        the §14 RFC 4191 preference rule — a LOW router never
        gets traffic when a HIGH router is available). The
        index is computed as
        'int(destination) % len(highest_preference_set)'.

        Returns None when no default routers are tracked.

        Reference: RFC 4311 §3 (per-destination load sharing).
        Reference: RFC 4191 §2.1 (preference precedence).
        """

        active_routers = self.get_icmp6_default_routers()
        if not active_routers:
            return None

        # 'get_icmp6_default_routers()' returns the active list
        # sorted by §14 preference (HIGH > MEDIUM > LOW). The
        # highest-preference equivalence class is the prefix of
        # entries sharing the head's prf value.
        head_prf = active_routers[0].prf
        candidates = [r for r in active_routers if r.prf == head_prf]

        index = int(destination) % len(candidates)
        return candidates[index]

    def get_icmp6_default_router_for_source(
        self,
        *,
        source: Ip6Address,
    ) -> Icmp6DefaultRouter | None:
        """
        Pick the default router whose RA-advertised prefix
        covers 'source', falling back to the highest-preference
        default router when no source-matching entry exists per
        RFC 8028 §3 first-hop selection in multi-prefix
        networks. Returns None when no default routers are
        tracked.

        The host MUST emit a packet whose source is in ISP A's
        prefix via ISP A's router (not via a randomly-picked
        default), otherwise the upstream anti-spoofing filter
        drops it.

        Reference: RFC 8028 §3 (first-hop selection by source).
        """

        active_routers = self.get_icmp6_default_routers()
        if not active_routers:
            return None

        # Find the SLAAC entry whose address equals 'source';
        # its 'router_address' names the announcing router.
        slaac_entry = next(
            (a for a in self._icmp6_slaac_addresses if a.address == source),
            None,
        )
        if slaac_entry is not None:
            for router in active_routers:
                if router.address == slaac_entry.router_address:
                    return router

        # No SLAAC binding — fall back to the highest-preference
        # router (the accessor returns the list pre-sorted).
        return active_routers[0]

    def get_icmp6_dad_state(self, *, address: Ip6Address) -> Icmp6DadState | None:
        """
        Get the per-address Duplicate Address Detection state
        (RFC 4862 §5.4 + RFC 4429 §3.1). Returns None when no
        DAD activity has been recorded for 'address' — either
        the host never started DAD on it or DAD failed and the
        entry was cleaned up. The NA emit path consults this
        accessor to clear the Override flag for OPTIMISTIC
        sources per RFC 4429 §3.3.
        """

        return self._icmp6_dad__states.get(address)

    def get_icmp6_slaac_address_state(
        self,
        *,
        prefix: Ip6Network,
    ) -> Icmp6SlaacAddressState | None:
        """
        Get the lifecycle state of the SLAAC address derived
        from the given prefix per RFC 4862 §5.5.4. Returns
        None when no entry exists or when the entry has been
        REMOVED (valid_until passed).
        """

        now = time.monotonic()
        entry = next(
            (a for a in self._icmp6_slaac_addresses if a.prefix == prefix),
            None,
        )
        if entry is None:
            return None
        return entry.state(now)

    def _update_icmp6_ra_parameters(
        self,
        *,
        cur_hop_limit: int,
        reachable_time_ms: int,
        retrans_timer_ms: int,
    ) -> None:
        """
        Apply the three RA-header host-parameter fields to
        '_icmp6_ra_parameters' per RFC 4861 §6.3.4. Each field
        with value 0 is "unspecified by this router" per §4.2
        and MUST NOT overwrite the existing host value. The
        Cur-Hop-Limit advertisement is additionally floored by
        'icmp6.accept_ra_min_hop_limit' (Linux parity).
        """

        prior = self._icmp6_ra_parameters
        new_hop = prior.cur_hop_limit
        new_reach = prior.reachable_time_ms
        new_retrans = prior.retrans_timer_ms

        if cur_hop_limit > 0:
            if cur_hop_limit >= sysctl_iface.get_for_iface("icmp6.accept_ra_min_hop_limit", self._interface_name):
                new_hop = cur_hop_limit
                self._packet_stats_rx.icmp6__nd_router_advertisement__cur_hop_limit__update += 1
            else:
                self._packet_stats_rx.icmp6__nd_router_advertisement__cur_hop_limit__floor__drop += 1

        if reachable_time_ms > 0:
            new_reach = reachable_time_ms
            self._packet_stats_rx.icmp6__nd_router_advertisement__reachable_time__update += 1
            # RFC 4861 §6.3.4 wires the captured value through
            # to this interface's IPv6 NUD cache as a per-cache
            # override; ARP is unaffected. Guarded for the early-RX
            # path where the ND cache has not yet been injected
            # (test fixtures, mock__init).
            if self._nd_cache is not None:
                self._nd_cache.set_reachable_time_override_ms(reachable_time_ms)

        if retrans_timer_ms > 0:
            new_retrans = retrans_timer_ms
            self._packet_stats_rx.icmp6__nd_router_advertisement__retrans_timer__update += 1

        self._icmp6_ra_parameters = Icmp6RaParameters(
            cur_hop_limit=new_hop,
            reachable_time_ms=new_reach,
            retrans_timer_ms=new_retrans,
        )

    def get_icmp6_ra_parameters(self) -> Icmp6RaParameters:
        """
        Get the most recent RA-header parameter snapshot per
        RFC 4861 §6.3.4. Each field is None until the host has
        observed at least one RA carrying a non-zero (and floor-
        passing) advertisement of that field.
        """

        return self._icmp6_ra_parameters

    def _derive_ip6_host(self, *, ip6_network: Ip6Network) -> Ip6IfAddr:
        """
        Derive the host's IPv6 address for 'ip6_network' using
        either RFC 7217 stable opaque IIDs (default; modern
        Linux equivalent of 'addr_gen_mode = 2') or legacy
        EUI-64. Selection is gated by the 'icmp6.use_rfc7217'
        sysctl.

        Reference: RFC 7217 §5 (algorithm specification).
        Reference: RFC 4291 §2.5.1 (legacy EUI-64 fallback).
        """

        if sysctl_iface.get_for_iface("icmp6.use_rfc7217", self._interface_name):
            return Ip6IfAddr.from_rfc7217(
                ip6_network=ip6_network,
                mac_address=self._mac_unicast,
                secret_key=self._icmp6_slaac__secret_key,
            )
        return Ip6IfAddr.from_eui64(
            mac_address=self._mac_unicast,
            ip6_network=ip6_network,
        )

    def _make_rfc7217_regenerator(
        self,
        *,
        ip6_network: Ip6Network,
    ) -> Callable[[], Ip6IfAddr] | None:
        """
        Build a DAD-failure regenerator for an RFC 7217 stable
        opaque IID address (RFC 7217 §6 retry on collision).
        Each invocation re-derives with an incremented
        'dad_counter'. Returns None when EUI-64 derivation is
        active ('icmp6.use_rfc7217 = 0') because EUI-64 is
        deterministic from the MAC and re-derivation would
        produce the same address.
        """

        if not sysctl_iface.get_for_iface("icmp6.use_rfc7217", self._interface_name):
            return None

        counter = [0]

        def _regenerate() -> Ip6IfAddr:
            counter[0] += 1
            return Ip6IfAddr.from_rfc7217(
                ip6_network=ip6_network,
                mac_address=self._mac_unicast,
                secret_key=self._icmp6_slaac__secret_key,
                dad_counter=counter[0],
            )

        return _regenerate

    def _effective_ip6_hop_limit(self) -> int:
        """
        Get the effective default Hop Limit for outbound IPv6
        traffic per RFC 4861 §6.3.4: the most recent RA-
        advertised Cur-Hop-Limit if observed, otherwise the
        protocol default (RFC 8200 §3 — 64). Callers that
        protocol-mandate a specific value (e.g. ND with 255,
        MLD with 1) bypass this helper.
        """

        from net_proto import IP6__DEFAULT_HOP_LIMIT

        return self._icmp6_ra_parameters.cur_hop_limit or IP6__DEFAULT_HOP_LIMIT

    ###
    # UDP delegators — logic lives in the composed 'UdpRxHandler' /
    # 'UdpTxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound UDP packet (delegates to the UDP RX sub-handler).
        """

        self._udp_rx._phrx_udp(packet_rx)

    def _phtx_udp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        udp__sport: int,
        udp__dport: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle an outbound UDP packet (delegates to the UDP TX sub-handler).
        """

        return self._udp_tx._phtx_udp(
            ip__src=ip__src,
            ip__dst=ip__dst,
            udp__sport=udp__sport,
            udp__dport=udp__dport,
            udp__payload=udp__payload,
            udp__no_cksum=udp__no_cksum,
            ip__ttl=ip__ttl,
            ip__ecn=ip__ecn,
            ip__dscp=ip__dscp,
            ip4__options=ip4__options,
            echo_tracker=echo_tracker,
        )

    def send_udp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
    ) -> None:
        """
        Enqueue an outbound UDP datagram (delegates to the UDP TX sub-handler).
        """

        self._udp_tx.send_udp_packet(
            ip__local_address=ip__local_address,
            ip__remote_address=ip__remote_address,
            udp__local_port=udp__local_port,
            udp__remote_port=udp__remote_port,
            udp__payload=udp__payload,
            udp__no_cksum=udp__no_cksum,
            ip__ttl=ip__ttl,
            ip__ecn=ip__ecn,
            ip__dscp=ip__dscp,
            ip4__options=ip4__options,
        )

    ###
    # TCP delegators — logic lives in the composed 'TcpRxHandler' /
    # 'TcpTxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_tcp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound TCP packet (delegates to the TCP RX sub-handler).
        """

        self._tcp_rx._phrx_tcp(packet_rx)

    def _phtx_tcp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        tcp__sport: int,
        tcp__dport: int,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__flag_ns: bool = False,
        tcp__flag_cwr: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_urg: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_syn: bool = False,
        tcp__flag_fin: bool = False,
        tcp__mss: int | None = None,
        tcp__wscale: int | None = None,
        tcp__sackperm: bool = False,
        tcp__sack_blocks: list[tuple[int, int]] | None = None,
        tcp__tsval: int | None = None,
        tcp__tsecr: int | None = None,
        tcp__fastopen_cookie: bytes | None = None,
        tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__accecn1_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__win: int = 0,
        tcp__urg: int = 0,
        tcp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle an outbound TCP packet (delegates to the TCP TX sub-handler).
        """

        return self._tcp_tx._phtx_tcp(
            ip__src=ip__src,
            ip__dst=ip__dst,
            ip__ecn=ip__ecn,
            ip__dscp=ip__dscp,
            tcp__sport=tcp__sport,
            tcp__dport=tcp__dport,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__flag_ns=tcp__flag_ns,
            tcp__flag_cwr=tcp__flag_cwr,
            tcp__flag_ece=tcp__flag_ece,
            tcp__flag_urg=tcp__flag_urg,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_psh=tcp__flag_psh,
            tcp__flag_rst=tcp__flag_rst,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_fin=tcp__flag_fin,
            tcp__mss=tcp__mss,
            tcp__wscale=tcp__wscale,
            tcp__sackperm=tcp__sackperm,
            tcp__sack_blocks=tcp__sack_blocks,
            tcp__tsval=tcp__tsval,
            tcp__tsecr=tcp__tsecr,
            tcp__fastopen_cookie=tcp__fastopen_cookie,
            tcp__accecn0_counters=tcp__accecn0_counters,
            tcp__accecn1_counters=tcp__accecn1_counters,
            tcp__win=tcp__win,
            tcp__urg=tcp__urg,
            tcp__payload=tcp__payload,
            echo_tracker=echo_tracker,
        )

    def send_tcp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        tcp__local_port: int,
        tcp__remote_port: int,
        tcp__flag_syn: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_fin: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_cwr: bool = False,
        tcp__flag_ns: bool = False,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__win: int = 0,
        tcp__wscale: int | None = None,
        tcp__mss: int | None = None,
        tcp__sackperm: bool = False,
        tcp__sack_blocks: list[tuple[int, int]] | None = None,
        tcp__tsval: int | None = None,
        tcp__tsecr: int | None = None,
        tcp__fastopen_cookie: bytes | None = None,
        tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__accecn1_counters: tuple[int | None, int | None, int | None] | None = None,
        tcp__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Enqueue an outbound TCP segment (delegates to the TCP TX sub-handler).
        """

        return self._tcp_tx.send_tcp_packet(
            ip__local_address=ip__local_address,
            ip__remote_address=ip__remote_address,
            ip__ttl=ip__ttl,
            ip__ecn=ip__ecn,
            ip__dscp=ip__dscp,
            tcp__local_port=tcp__local_port,
            tcp__remote_port=tcp__remote_port,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_fin=tcp__flag_fin,
            tcp__flag_rst=tcp__flag_rst,
            tcp__flag_psh=tcp__flag_psh,
            tcp__flag_ece=tcp__flag_ece,
            tcp__flag_cwr=tcp__flag_cwr,
            tcp__flag_ns=tcp__flag_ns,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__win=tcp__win,
            tcp__wscale=tcp__wscale,
            tcp__mss=tcp__mss,
            tcp__sackperm=tcp__sackperm,
            tcp__sack_blocks=tcp__sack_blocks,
            tcp__tsval=tcp__tsval,
            tcp__tsecr=tcp__tsecr,
            tcp__fastopen_cookie=tcp__fastopen_cookie,
            tcp__accecn0_counters=tcp__accecn0_counters,
            tcp__accecn1_counters=tcp__accecn1_counters,
            tcp__payload=tcp__payload,
        )

    ###
    # ICMPv4 delegators — logic lives in the composed 'Icmp4RxHandler'
    # / 'Icmp4TxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound ICMPv4 packet (delegates to the ICMPv4 RX sub-handler).
        """

        self._icmp4_rx._phrx_icmp4(packet_rx)

    def _phrx_igmp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IGMP packet (delegates to the IGMP RX sub-handler).
        """

        self._igmp_rx._phrx_igmp(packet_rx)

    def _phtx_icmp4(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        ip4__options: Ip4Options = Ip4Options(),
        icmp4__message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle an outbound ICMPv4 packet (delegates to the ICMPv4 TX sub-handler).
        """

        return self._icmp4_tx._phtx_icmp4(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__options=ip4__options,
            icmp4__message=icmp4__message,
            echo_tracker=echo_tracker,
        )

    def send_icmp4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        icmp4__message: Icmp4Message,
    ) -> TxStatus:
        """
        Enqueue an outbound ICMPv4 packet (delegates to the ICMPv4 TX sub-handler).
        """

        return self._icmp4_tx.send_icmp4_packet(
            ip4__local_address=ip4__local_address,
            ip4__remote_address=ip4__remote_address,
            icmp4__message=icmp4__message,
        )

    ###
    # ICMPv6 delegators — logic lives in the composed 'Icmp6RxHandler'
    # / 'Icmp6TxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound ICMPv6 packet (delegates to the ICMPv6 RX sub-handler).
        """

        self._icmp6_rx._phrx_icmp6(packet_rx)

    def _phtx_icmp6(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle an outbound ICMPv6 packet (delegates to the ICMPv6 TX sub-handler).
        """

        return self._icmp6_tx._phtx_icmp6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            icmp6__message=icmp6__message,
            echo_tracker=echo_tracker,
        )

    def _send_icmp6_nd_dad_message(
        self,
        *,
        ip6_unicast_candidate: Ip6Address,
        nonce: bytes | None = None,
    ) -> None:
        """
        Send an ICMPv6 ND DAD message (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx._send_icmp6_nd_dad_message(
            ip6_unicast_candidate=ip6_unicast_candidate,
            nonce=nonce,
        )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send an ICMPv6 MLDv2 Report (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx._send_icmp6_multicast_listener_report()

    def _send_igmp_v3_report(self) -> None:
        """
        Send an IGMPv3 current-state Membership Report (delegates to the
        IGMP TX sub-handler).
        """

        self._igmp_tx._send_igmp_v3_report()

    def _send_igmp_state_change(
        self,
        group: Ip4Address,
        /,
        *,
        old: Ip4MulticastFilter,
        new: Ip4MulticastFilter,
    ) -> None:
        """
        Emit an IGMP state-change report for the 'old'→'new' filter
        transition in the interface's Host Compatibility Mode form
        (delegates to the IGMP TX sub-handler).
        """

        self._igmp_tx._send_igmp_state_change(group, old=old, new=new)

    def _ip4_multicast_filter_for(self, group: Ip4Address, /) -> Ip4MulticastFilter:
        """
        Return the merged RFC 3376 §3.2 interface filter for 'group' from
        its current contributors, or the any-source EXCLUDE{} default
        when the group has no contributor registry entry (a directly
        assigned group such as the permanent all-systems group, or a
        test-driven direct assign).
        """

        with self._lock__multicast:
            membership = self._ip4_multicast_refs.get(group)
            if membership is None:
                return Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE)
            return Ip4MulticastFilter.merge(membership.contributors())

    def send_igmp_leave_all(self) -> None:
        """
        Emit a graceful IGMP Leave for every joined IPv4 multicast group
        on shutdown (delegates to the IGMP TX sub-handler). Public surface
        for the stack-shutdown lifecycle path.
        """

        self._igmp_tx._send_igmp_leave_all()

    def _igmp_host_compatibility_mode(self) -> IgmpVersion:
        """
        Return the RFC 3376 §7.2.1 Host Compatibility Mode for this
        interface: a forced 'igmp.version' (1/2/3) overrides; otherwise
        IGMPv1 while the v1 Older-Version-Querier-Present timer runs,
        else IGMPv2 while the v2 timer runs, else IGMPv3. Reading
        'igmp.version' via qualified module access so an operator
        override resolves live.
        """

        forced = igmp__constants.IGMP__FORCE_VERSION
        if forced != 0:
            return IgmpVersion(forced)

        now_ms = stack.timer.now_ms
        if self._igmp__v1_querier_present_until_ms is not None and now_ms < self._igmp__v1_querier_present_until_ms:
            return IgmpVersion.V1
        if self._igmp__v2_querier_present_until_ms is not None and now_ms < self._igmp__v2_querier_present_until_ms:
            return IgmpVersion.V2
        return IgmpVersion.V3

    def _mld_host_compatibility_mode(self) -> MldVersion:
        """
        Return the RFC 3810 §8.2.1 MLD Host Compatibility Mode for this
        interface: MLDv1 while the Older Version Querier Present timer
        runs (an MLDv1 Query was heard within the timeout), else MLDv2.
        The scalar is written under '_lock__multicast' by the RX Query
        handler; this read is lock-free (a benign-stale read at worst
        picks the previous mode), mirroring '_igmp_host_compatibility_mode'.
        """

        now_ms = stack.timer.now_ms
        if self._mld__v1_querier_present_until_ms is not None and now_ms < self._mld__v1_querier_present_until_ms:
            return MldVersion.V1
        return MldVersion.V2

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send an ICMPv6 ND Router Solicitation (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx._send_icmp6_nd_router_solicitation()

    def send_icmp6_neighbor_solicitation(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Send a multicast ICMPv6 ND NS (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx.send_icmp6_neighbor_solicitation(icmp6_ns_target_address=icmp6_ns_target_address)

    def send_icmp6_neighbor_solicitation_unicast(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Send a unicast ICMPv6 ND NS (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx.send_icmp6_neighbor_solicitation_unicast(icmp6_ns_target_address=icmp6_ns_target_address)

    def send_icmp6_neighbor_advertisement(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        target_address: Ip6Address,
        flag_r: bool = False,
        flag_s: bool = False,
        flag_o: bool = False,
        include_tlla: bool = True,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Send an ICMPv6 ND Neighbor Advertisement (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx.send_icmp6_neighbor_advertisement(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            target_address=target_address,
            flag_r=flag_r,
            flag_s=flag_s,
            flag_o=flag_o,
            include_tlla=include_tlla,
            echo_tracker=echo_tracker,
        )

    def send_icmp6_neighbor_advertisement_gratuitous(self, *, ip6_unicast: Ip6Address) -> None:
        """
        Send gratuitous ICMPv6 ND NAs (delegates to the ICMPv6 TX sub-handler).
        """

        self._icmp6_tx.send_icmp6_neighbor_advertisement_gratuitous(ip6_unicast=ip6_unicast)

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Enqueue an outbound ICMPv6 packet (delegates to the ICMPv6 TX sub-handler).
        """

        return self._icmp6_tx.send_icmp6_packet(
            ip6__local_address=ip6__local_address,
            ip6__remote_address=ip6__remote_address,
            ip6__hop=ip6__hop,
            icmp6__message=icmp6__message,
        )

    ###
    # IPv4 delegators — logic lives in the composed 'Ip4RxHandler' /
    # 'Ip4TxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IPv4 packet (delegates to the IPv4 RX sub-handler).
        """

        self._ip4_rx._phrx_ip4(packet_rx)

    def _phtx_ip4(
        self,
        *,
        ip4__dst: Ip4Address,
        ip4__src: Ip4Address,
        ip4__ttl: int | None = None,
        ip4__ecn: int = 0,
        ip4__dscp: int = 0,
        ip4__flag_df: bool = False,
        ip4__options: Ip4Options = Ip4Options(),
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle an outbound IPv4 packet (delegates to the IPv4 TX sub-handler).
        """

        return self._ip4_tx._phtx_ip4(
            ip4__dst=ip4__dst,
            ip4__src=ip4__src,
            ip4__ttl=ip4__ttl,
            ip4__ecn=ip4__ecn,
            ip4__dscp=ip4__dscp,
            ip4__flag_df=ip4__flag_df,
            ip4__options=ip4__options,
            ip4__payload=ip4__payload,
        )

    def send_ip4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        ip4__proto: IpProto,
        ip4__payload: bytes = bytes(),
        ip4__ttl: int | None = None,
        ip4__ecn: int = 0,
        ip4__dscp: int = 0,
    ) -> None:
        """
        Enqueue an outbound IPv4 RAW datagram (delegates to the IPv4 TX sub-handler).
        """

        self._ip4_tx.send_ip4_packet(
            ip4__local_address=ip4__local_address,
            ip4__remote_address=ip4__remote_address,
            ip4__proto=ip4__proto,
            ip4__payload=ip4__payload,
            ip4__ttl=ip4__ttl,
            ip4__ecn=ip4__ecn,
            ip4__dscp=ip4__dscp,
        )

    ###
    # IPv6 fragment delegators — logic lives in the composed
    # 'Ip6FragRxHandler' / 'Ip6FragTxHandler'. Shared by both layers,
    # so they sit on the base.
    ###

    def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IPv6 fragment (delegates to the IPv6 fragment RX sub-handler).
        """

        self._ip6_frag_rx._phrx_ip6_frag(packet_rx)

    def _phtx_ip6_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus:
        """
        Handle an outbound IPv6 fragment (delegates to the IPv6 fragment TX sub-handler).
        """

        return self._ip6_frag_tx._phtx_ip6_frag(ip6_packet_tx=ip6_packet_tx)

    ###
    # IPv6 delegators — logic lives in the composed 'Ip6RxHandler' /
    # 'Ip6TxHandler'. Shared by both layers, so they sit on the base.
    ###

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IPv6 packet (delegates to the IPv6 RX sub-handler).
        """

        self._ip6_rx._phrx_ip6(packet_rx)

    def _phtx_ip6(
        self,
        *,
        ip6__dst: Ip6Address,
        ip6__src: Ip6Address,
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
        ip6__dscp: int = 0,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle an outbound IPv6 packet (delegates to the IPv6 TX sub-handler).
        """

        return self._ip6_tx._phtx_ip6(
            ip6__dst=ip6__dst,
            ip6__src=ip6__src,
            ip6__hop=ip6__hop,
            ip6__ecn=ip6__ecn,
            ip6__dscp=ip6__dscp,
            ip6__payload=ip6__payload,
        )

    def send_ip6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__next: IpProto,
        ip6__payload: bytes = bytes(),
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
        ip6__dscp: int = 0,
    ) -> None:
        """
        Enqueue an outbound IPv6 RAW datagram (delegates to the IPv6 TX sub-handler).
        """

        self._ip6_tx.send_ip6_packet(
            ip6__local_address=ip6__local_address,
            ip6__remote_address=ip6__remote_address,
            ip6__next=ip6__next,
            ip6__payload=ip6__payload,
            ip6__hop=ip6__hop,
            ip6__ecn=ip6__ecn,
            ip6__dscp=ip6__dscp,
        )

    def deliver_tx_to_packet_sockets(self, ethernet_packet_tx: EthernetAssembler, /) -> None:
        """
        AF_PACKET egress-tap surface required by the ARP / ND cache flush
        callbacks (the 'ArpCacheOwner' / 'NdCacheOwner' seams). The base
        implementation is a no-op: a Layer 3 (TUN) interface has no
        link-layer tap, and ND on such an interface never queues an
        Ethernet frame, so this is never reached there. 'PacketHandlerL2'
        overrides it to fan the frame to bound packet sockets.
        """


class PacketHandlerL2(
    PacketHandler,
):
    """
    Pick up and respond to incoming packets on Layer 2 (TAP) interface.
    """

    _interface_layer = InterfaceLayer.L2

    # Composed per-protocol sub-handlers (see
    # docs/refactor/packet_handler_composition.md). Each holds a
    # typed back-reference to this interface and reaches shared
    # state through it; the handler keeps thin '_phrx_*' / 'send_*'
    # delegators below so the external + cross-call surface is
    # unchanged. ARP is L2-only — no counterpart on L3.
    _arp_rx: ArpRxHandler
    _arp_tx: ArpTxHandler
    # IEEE 802.3 / LLC / SNAP framing is L2-only.
    _ethernet_802_3_rx: Ethernet8023RxHandler
    _ethernet_802_3_tx: Ethernet8023TxHandler
    # Ethernet II framing + the link-layer RX demux hub are L2-only.
    _ethernet_rx: EthernetRxHandler
    _ethernet_tx: EthernetTxHandler

    _ip4_dhcp: bool
    _ip6_lla_autoconfig: bool
    _ip6_gua_autoconfig: bool
    # Per-interface DHCPv4 client (RFC 2131), installed by
    # 'stack.add_interface' when 'ip4_dhcp' is set. 'None' on interfaces
    # without DHCPv4 (static / TUN / IPv6-only). Each interface owns its
    # own client so a multi-homed host runs one DHCP lifecycle per NIC.
    _dhcp4_client: Dhcp4Client | None = None
    _mac_unicast: MacAddress
    _mac_multicast: list[MacAddress]
    _mac_broadcast: MacAddress

    @override
    def __init__(
        self,
        *,
        mac_address: MacAddress,
        interface_mtu: int,
        interface_name: str | None = None,
        ip4_support: bool = True,
        ip4_host: Ip4IfAddr | None = None,
        ip4_dhcp: bool = True,
        ip6_support: bool = True,
        ip6_host: Ip6IfAddr | None = None,
        ip6_lla_autoconfig: bool = True,
        ip6_gua_autoconfig: bool = True,
        rx_ring: RxRing | None = None,
        tx_ring: TxRing | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__(
            interface_mtu=interface_mtu,
            interface_name=interface_name,
            ip6_support=ip6_support,
            ip4_support=ip4_support,
            ip6_host=ip6_host,
            ip4_host=ip4_host,
            rx_ring=rx_ring,
            tx_ring=tx_ring,
            packet_stats_rx=packet_stats_rx,
            packet_stats_tx=packet_stats_tx,
            link_stats=link_stats,
        )

        # Composed per-protocol sub-handlers. Each stores a typed
        # back-reference to this interface and resolves shared state
        # lazily through it, so constructing them here (before the
        # rest of the L2 state is set) is safe.
        self._arp_rx = ArpRxHandler(interface=self)
        self._arp_tx = ArpTxHandler(interface=self)
        self._ethernet_802_3_rx = Ethernet8023RxHandler(interface=self)
        self._ethernet_802_3_tx = Ethernet8023TxHandler(interface=self)
        self._ethernet_rx = EthernetRxHandler(interface=self)
        self._ethernet_tx = EthernetTxHandler(interface=self)

        self._ip4_dhcp = ip4_dhcp
        self._ip6_lla_autoconfig = ip6_lla_autoconfig
        self._ip6_gua_autoconfig = ip6_gua_autoconfig

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This
        # is to accommodate IPv6 Solicited Node Multicast mechanism where
        # multiple IPv6 unicast addresses can be tied to the same SNM address
        # (and the same multicast MAC). This is important when removing one of
        # the unicast addresses, so the other ones keep it's SNM entry in the
        # multicast list. Its the simplest solution and imho perfectly valid
        # one in this case.
        self._mac_unicast = mac_address
        self._mac_multicast = []
        self._mac_broadcast = MacAddress(0xFFFFFFFFFFFF)

        # Used for the ICMPv6 ND DAD process. Per-address state
        # (events, peer TLLA capture, RFC 7527 Enhanced DAD
        # nonce trackers) lives in 'DadSlotRegistry[Ip6Address]'
        # so multiple addresses can DAD concurrently. The RX
        # path signals the right slot by inbound NS / NA
        # 'target_address'; an entry's presence means a worker
        # is in DAD for that address. The registry's internal
        # lock makes worker install / nonce-add / tear-down
        # atomic against the RX 'try_signal_conflict' call.
        self._icmp6_nd_dad__registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()

        # RFC 7217 §5 secret_key — generated once per process
        # at handler init. PyTCP doesn't persist this to disk;
        # an OS-style "stable_secret" file is out of scope. The
        # 128-bit minimum is per RFC 7217 §5.
        self._icmp6_slaac__secret_key = secrets.token_bytes(16)

        # Used for the ICMPv6 ND RA address auto configuration.
        self._icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self._icmp6_ra__event: threading.Semaphore = threading.Semaphore(0)

        # RFC 3810 §5.1.10 deferred-Report state. Tracks the
        # absolute 'stack.timer.now_ms' at which the next
        # scheduled MLDv2 Report will fire on Query receipt;
        # None means no Report is pending. Coalesces multiple
        # inbound Queries: a Query whose computed response
        # time is later than the existing pending entry is
        # absorbed without rescheduling.
        self._mld2_query__pending_response_at_ms: int | None = None
        self._mld2_query__handle: TimerHandle | None = None

        # RFC 3810 §8.2.1 MLDv1 Older Version Querier Present timer.
        # Armed (under '_lock__multicast') when an MLDv1 Query is
        # heard; while it runs the interface is in MLDv1 Host
        # Compatibility Mode and emits MLDv1 Reports instead of the
        # MLDv2 Report. 'None' = no MLDv1 querier seen (MLDv2 mode).
        self._mld__v1_querier_present_until_ms: int | None = None

        # RFC 4861 §6.3.4 default-router list — entries learned
        # from inbound RAs, indexed implicitly by RA source link-
        # local. Lazy-aged: 'get_icmp6_default_routers()' filters
        # out entries whose 'expires_at' is in the past instead of
        # a background sweep, mirroring how Linux's
        # 'rt6_check_expired' is invoked on demand.
        self._icmp6_default_routers: list[Icmp6DefaultRouter] = []

        # RFC 4862 §5.5.3 SLAAC address table — per-address
        # preferred / valid lifetime state harvested from RA
        # Prefix-Information options, plus the per-address
        # lifecycle state (PREFERRED / DEPRECATED) computed
        # lazily from the deadlines per §5.5.4. Same lazy-ageing
        # pattern as the default-router list above.
        self._icmp6_slaac_addresses: list[Icmp6SlaacAddress] = []

        # RFC 8981 SLAAC temporary-address table — populated
        # alongside '_icmp6_slaac_addresses' when
        # 'icmp6.use_tempaddr' is non-zero. Each entry mints a
        # random-IID address via 'Ip6IfAddr.from_rfc8981_temp' and
        # claims it via the §20.1 async DAD worker. Lifetimes
        # are clamped to TEMP_*_LIFETIME at creation. Lazy-aged
        # like '_icmp6_slaac_addresses'.
        self._icmp6_temp_addresses: list[Icmp6TempAddress] = []

        # RFC 8981 §3.4 sweep timestamp — '_subsystem_loop'
        # rate-limits sweep invocations via this monotonic
        # timestamp. Initialised to 0.0 so the first iteration
        # of the loop runs the sweep immediately (which is
        # cheap on an empty table).
        self._last_temp_addr_sweep_at: float = 0.0

        # RFC 4861 §6.3.4 RA-header parameter mirror —
        # Cur-Hop-Limit, Reachable Time, Retrans Timer values
        # observed from the most recent RA carrying a non-zero
        # advertisement of each field. Phase 2: TX / NUD / DAD
        # consumers will fall back to these when set, otherwise
        # to operator-configured sysctl defaults.
        self._icmp6_ra_parameters: Icmp6RaParameters = Icmp6RaParameters(
            cur_hop_limit=None,
            reachable_time_ms=None,
            retrans_timer_ms=None,
        )

    @override
    def _build_ethertype_registry(self) -> None:
        """
        Extend the base link-layer dispatch registry with the L2-only
        ARP entry (ARP is the link-layer half of IPv4 on a broadcast
        link; a TUN / L3 interface has none). Gated by IPv4 support,
        matching the prior 'case EtherType.ARP if self._ip4_support'
        guard.
        """

        super()._build_ethertype_registry()
        if self._ip4_support:
            self._ethertype_registry.register(EtherType.ARP, self._phrx_arp)

    ###
    # ARP delegators — the stable RX / TX surface; the logic lives
    # in the composed 'ArpRxHandler' / 'ArpTxHandler' sub-handlers.
    ###

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound ARP packet (delegates to the ARP RX sub-handler).
        """

        self._arp_rx._phrx_arp(packet_rx)

    def _phtx_arp(
        self,
        *,
        ethernet__src: MacAddress,
        ethernet__dst: MacAddress,
        arp__oper: ArpOperation,
        arp__sha: MacAddress,
        arp__spa: Ip4Address,
        arp__tha: MacAddress,
        arp__tpa: Ip4Address,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle an outbound ARP packet (delegates to the ARP TX sub-handler).
        """

        return self._arp_tx._phtx_arp(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            arp__oper=arp__oper,
            arp__sha=arp__sha,
            arp__spa=arp__spa,
            arp__tha=arp__tha,
            arp__tpa=arp__tpa,
            echo_tracker=echo_tracker,
        )

    def _send_arp_reply(
        self,
        *,
        arp__spa: Ip4Address,
        arp__tha: MacAddress,
        arp__tpa: Ip4Address,
        tracker: Tracker | None = None,
    ) -> None:
        """
        Send an ARP Reply (delegates to the ARP TX sub-handler).
        """

        self._arp_tx._send_arp_reply(
            arp__spa=arp__spa,
            arp__tha=arp__tha,
            arp__tpa=arp__tpa,
            tracker=tracker,
        )

    def send_arp_request(self, *, arp__tpa: Ip4Address) -> None:
        """
        Send a broadcast ARP Request (delegates to the ARP TX sub-handler).
        """

        self._arp_tx.send_arp_request(arp__tpa=arp__tpa)

    def send_arp_unicast_request(
        self,
        *,
        arp__tpa: Ip4Address,
        ethernet__dst: MacAddress,
        arp__spa: Ip4Address | None = None,
    ) -> None:
        """
        Send a unicast ARP Request (delegates to the ARP TX sub-handler).
        """

        self._arp_tx.send_arp_unicast_request(
            arp__tpa=arp__tpa,
            ethernet__dst=ethernet__dst,
            arp__spa=arp__spa,
        )

    ###
    # IEEE 802.3 delegators — logic lives in the composed
    # 'Ethernet8023RxHandler' / 'Ethernet8023TxHandler'.
    ###

    def _phrx_ethernet_802_3(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound 802.3 frame (delegates to the 802.3 RX sub-handler).
        """

        self._ethernet_802_3_rx._phrx_ethernet_802_3(packet_rx)

    def _phtx_ethernet_802_3(
        self,
        *,
        ethernet_802_3__src: MacAddress = MacAddress(),
        ethernet_802_3__dst: MacAddress = MacAddress(),
        ethernet_802_3__payload: Ethernet8023Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle an outbound 802.3 frame (delegates to the 802.3 TX sub-handler).
        """

        return self._ethernet_802_3_tx._phtx_ethernet_802_3(
            ethernet_802_3__src=ethernet_802_3__src,
            ethernet_802_3__dst=ethernet_802_3__dst,
            ethernet_802_3__payload=ethernet_802_3__payload,
        )

    ###
    # Ethernet II delegators — the link-layer RX demux hub + outbound
    # framing. Logic lives in the composed 'EthernetRxHandler' /
    # 'EthernetTxHandler'. L2-only ('PacketHandlerL3' has no Ethernet
    # layer). '_phtx_ethernet' carries '@override' because the base
    # 'PacketHandler' declares it (TYPE_CHECKING-only) so the shared
    # IPv4 / IPv6 TX sub-handlers can reach it through their union.
    ###

    def _phrx_ethernet(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound Ethernet packet (delegates to the Ethernet RX sub-handler).
        """

        self._ethernet_rx._phrx_ethernet(packet_rx)

    @override
    def _phtx_ethernet(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(),
        ethernet__dst: MacAddress = MacAddress(),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle an outbound Ethernet packet (delegates to the Ethernet TX sub-handler).
        """

        return self._ethernet_tx._phtx_ethernet(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=ethernet__payload,
        )

    def send_link_frame(self, frame: Buffer, /) -> None:
        """
        Enqueue a pre-built link-layer frame for verbatim transmission
        (delegates to the Ethernet TX sub-handler).
        """

        self._ethernet_tx.send_link_frame(frame)

    @override
    def deliver_tx_to_packet_sockets(self, ethernet_packet_tx: EthernetAssembler, /) -> None:
        """
        Fan a queued-then-flushed outbound frame to every bound AF_PACKET
        socket (delegates to the Ethernet TX sub-handler's egress tap).
        Called by the ARP / ND cache flush callbacks so a frame queued
        pending neighbor resolution is still observed on egress.
        """

        self._ethernet_tx.deliver_tx_to_packet_sockets(ethernet_packet_tx)

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        Also runs periodic housekeeping (RFC 8981 temp-address
        sweep) rate-limited by 'icmp6.temp_addr_sweep_interval_s'.
        """

        assert self._rx_ring is not None, "Started PacketHandler must have an injected RX ring."

        if (packet_rx := self._rx_ring.dequeue()) is not None:
            if int.from_bytes(packet_rx.frame[12:14]) <= ETHERNET_802_3__PACKET__MAX_LEN:
                self._phrx_ethernet_802_3(packet_rx)
            else:
                self._phrx_ethernet(packet_rx)

        self._maybe_run_periodic_tasks()

    def _maybe_run_periodic_tasks(self) -> None:
        """
        Run periodic housekeeping tasks at most once per
        'icmp6.temp_addr_sweep_interval_s' seconds. Both the
        RFC 8981 §3.4 cleanup sweep (§18c.1) and the
        regen-before-expiry mint (§18c.2) run here.
        """

        now = time.monotonic()
        interval = sysctl_iface.get_for_iface("icmp6.temp_addr_sweep_interval_s", self._interface_name)
        if now - self._last_temp_addr_sweep_at < interval:
            return
        self._last_temp_addr_sweep_at = now
        # Regen first so freshly-minted entries don't get
        # sweep-removed by an unlikely valid_until=now race
        # in the same tick (the cleanup sweep filters strictly
        # on valid_until <= now).
        self._icmp6_regen_temp_addresses()
        self._icmp6_sweep_temp_addresses()
        # Stable-SLAAC sweep — symmetric to the temp sweep,
        # for §12a.runtime lifecycle close-out.
        self._icmp6_sweep_slaac_addresses()

    def _send_icmp6_nd_router_solicitations_with_backoff(self) -> None:
        """
        Send up to 'icmp6.max_rtr_solicitations' Router
        Solicitations spaced by RFC 7559 §2 truncated binary
        exponential backoff with ±10% randomisation. Each
        inter-message wait is at least
        'icmp6.rtr_solicitation_interval_ms', doubles each
        round, and is capped at 'icmp6.rtr_solicitation_max_rt_ms'.
        Returns early on the first RA receipt (the RX handler
        releases '_icmp6_ra__event'). 'max_rtr_solicitations = 0'
        is the kill switch — no RS is emitted.
        """

        max_attempts = sysctl_iface.get_for_iface("icmp6.max_rtr_solicitations", self._interface_name)
        if max_attempts <= 0:
            return

        rt_ms = sysctl_iface.get_for_iface("icmp6.rtr_solicitation_interval_ms", self._interface_name)
        mrt_ms = sysctl_iface.get_for_iface("icmp6.rtr_solicitation_max_rt_ms", self._interface_name)

        for _ in range(max_attempts):
            self._send_icmp6_nd_router_solicitation()
            wait_s = (rt_ms + random.uniform(-0.1, 0.1) * rt_ms) / 1000.0
            if self._icmp6_ra__event.acquire(timeout=wait_s):
                return
            rt_ms = min(2 * rt_ms, mrt_ms)

    def _perform_ip6_nd_dad(self, *, ip6_unicast_candidate: Ip6Address) -> bool:
        """
        Perform IPv6 ND Duplicate Address Detection, return True if passed.

        Per RFC 4862 §5.1 the host emits 'icmp6.dad_transmits'
        probes spaced by 'icmp6.retrans_timer_ms' milliseconds
        before declaring the address verified. A conflict event
        released at any point during the loop short-circuits
        further probing — the host MUST NOT continue once a
        duplicate has been signaled. 'dad_transmits = 0'
        disables DAD entirely (Linux parity).

        Per-address DAD state lives in '_icmp6_nd_dad__registry'
        ('DadSlotRegistry[Ip6Address]') keyed by the candidate
        address, so multiple addresses can DAD concurrently in
        separate worker threads. Each call installs its own
        slot on entry and tears it down on exit — the RX path
        looks up the slot by inbound NS / NA 'target_address'
        and signals the right Event. The candidate's lifecycle
        state is also recorded in '_icmp6_dad__states':
        TENTATIVE while probes are in flight, VALID on success,
        removed on conflict. The Optimistic-DAD helper
        '_claim_ip6_address_optimistic' overrides the TENTATIVE
        entry with OPTIMISTIC before invoking us so the NA emit
        path sees the relaxed Override-flag rule per RFC 4429
        §3.3.
        """

        __debug__ and log(
            "stack",
            f"ICMPv6 ND DAD - Starting process for {ip6_unicast_candidate}",
        )

        # 'icmp6.accept_dad=0' short-circuits DAD entirely:
        # candidate goes straight to VALID with no probes
        # emitted, no initial delay taken, and no per-address
        # DAD-state slot. Linux 'accept_dad=0' parity.
        if sysctl_iface.get_for_iface("icmp6.accept_dad", self._interface_name) == 0:
            with self._lock__addr_config:
                self._icmp6_dad__states = {**self._icmp6_dad__states, ip6_unicast_candidate: Icmp6DadState.VALID}
            return True

        # Per-address DAD slot. Populated BEFORE the first probe
        # TX so the RX dispatch can find this candidate's slot
        # when peer NS / NA arrives. The registry's internal
        # lock guarantees the RX path cannot observe a partial
        # install.
        dad_event = self._icmp6_nd_dad__registry.install(ip6_unicast_candidate)
        # Default to TENTATIVE; the Optimistic-DAD wrapper
        # promotes this to OPTIMISTIC before invoking us.
        with self._lock__addr_config:
            if ip6_unicast_candidate not in self._icmp6_dad__states:
                self._icmp6_dad__states = {
                    **self._icmp6_dad__states,
                    ip6_unicast_candidate: Icmp6DadState.TENTATIVE,
                }

        # RFC 4862 §5.4.2 — random initial delay before the
        # first DAD probe to alleviate fleet-wide
        # synchronisation when many hosts boot at the same
        # instant. Ceiling is 'icmp6.max_rtr_solicitation_delay_ms'
        # (default 1000 ms = RFC 4861 §10). Setting the sysctl
        # to 0 disables.
        max_initial_delay_ms = sysctl_iface.get_for_iface("icmp6.max_rtr_solicitation_delay_ms", self._interface_name)
        if max_initial_delay_ms > 0:
            time.sleep(random.uniform(0, max_initial_delay_ms / 1000.0))

        # The optimistic wrapper has already joined the
        # solicited-node multicast group via '_assign_ip6_host';
        # in the strict path the multicast must be joined here
        # so DAD probes can be received back from peers.
        solicited_node = ip6_unicast_candidate.solicited_node_multicast
        joined_for_dad = solicited_node not in self._ip6_multicast
        if joined_for_dad:
            self.assign_ip6_multicast(ip6_multicast=solicited_node)

        # RFC 4861 §6.3.4: an RA-advertised Retrans Timer
        # supersedes the operator-configured sysctl default. The
        # mirror is captured by §13a; consumer wiring is §13b.
        effective_retrans_timer_ms = self._icmp6_ra_parameters.retrans_timer_ms or sysctl_iface.get_for_iface(
            "icmp6.retrans_timer_ms", self._interface_name
        )
        retrans_timer_s = effective_retrans_timer_ms / 1000.0
        conflict = False
        for _probe_index in range(sysctl_iface.get_for_iface("icmp6.dad_transmits", self._interface_name)):
            # RFC 7527 §4.1: every NS(DAD) carries a fresh
            # random nonce when Enhanced DAD is enabled. The
            # nonce is registered with the slot under the
            # registry's lock so the RX nonce-membership read
            # in 'registry.try_signal_conflict' cannot observe
            # a partially-mutated set.
            nonce: bytes | None = None
            if sysctl_iface.get_for_iface("icmp6.enhanced_dad", self._interface_name):
                nonce = secrets.token_bytes(6)
                self._icmp6_nd_dad__registry.register_nonce(ip6_unicast_candidate, nonce)
            self._send_icmp6_nd_dad_message(
                ip6_unicast_candidate=ip6_unicast_candidate,
                nonce=nonce,
            )
            if dad_event.wait(timeout=retrans_timer_s):
                conflict = True
                break

        if conflict:
            # The RX path captured the peer's TLLA into the
            # slot under the registry's lock; we read it back
            # the same way.
            conflict_tlla = self._icmp6_nd_dad__registry.peer_info(ip6_unicast_candidate)
            __debug__ and log(
                "stack",
                "<WARN>ICMPv6 ND DAD - Duplicate IPv6 address detected, "
                f"{ip6_unicast_candidate} advertised by "
                f"{conflict_tlla}</>",
            )
            # Conflict — drop the per-address state entry; the
            # caller is responsible for reverting any pre-claim
            # (Optimistic-DAD wrapper removes the address from
            # '_ip6_ifaddr'; the strict path never assigned it).
            with self._lock__addr_config:
                self._icmp6_dad__states = {
                    addr: state for addr, state in self._icmp6_dad__states.items() if addr != ip6_unicast_candidate
                }
        else:
            __debug__ and log(
                "stack",
                "ICMPv6 ND DAD - No duplicate address detected for " f"{ip6_unicast_candidate}",
            )
            # Promote the per-address state to VALID before the
            # gratuitous NA goes out so the NA emit path's
            # OPTIMISTIC-source Override-flag suppression no
            # longer applies (RFC 9131 §3 announcement carries
            # Override=1 by design, RFC 4429 §3.3 step 5).
            with self._lock__addr_config:
                self._icmp6_dad__states = {**self._icmp6_dad__states, ip6_unicast_candidate: Icmp6DadState.VALID}
            # RFC 9131 §3 — gratuitous Neighbor Advertisement(s)
            # on host attachment so peers preemptively populate
            # their neighbour cache for our newly-claimed
            # address. Operator-tunable count via
            # 'icmp6.gratuitous_na_count' (default 1; 0 disables).
            self.send_icmp6_neighbor_advertisement_gratuitous(ip6_unicast=ip6_unicast_candidate)

        # Tear down the per-address DAD slot. Order: clear the
        # slot AFTER the state-transition above so the RX
        # dispatch cannot signal a slot that's about to be
        # popped. The registry tear-down runs under its
        # internal lock so an in-flight RX
        # 'try_signal_conflict' call cannot observe a
        # half-popped slot.
        self._icmp6_nd_dad__registry.teardown(ip6_unicast_candidate)
        if joined_for_dad:
            self.remove_ip6_multicast(ip6_unicast_candidate.solicited_node_multicast)
        return not conflict

    def _claim_ip6_address_optimistic(self, *, ip6_host: Ip6IfAddr) -> bool:
        """
        Claim 'ip6_host' using RFC 4429 §3 Optimistic DAD: the
        address is installed into '_ip6_ifaddr' as OPTIMISTIC
        before the DAD probes are emitted, then the DAD probe
        loop runs as in the strict path. On success the state
        is promoted to VALID; on collision the address is
        removed and the per-address state cleared.

        Returns True on DAD success, False on collision.
        """

        with self._lock__addr_config:
            self._icmp6_dad__states = {**self._icmp6_dad__states, ip6_host.address: Icmp6DadState.OPTIMISTIC}
        self._assign_ip6_host(ip6_host=ip6_host)
        if self._perform_ip6_nd_dad(ip6_unicast_candidate=ip6_host.address):
            return True
        # Collision: roll back the optimistic assignment. The
        # per-address state was already cleared inside
        # '_perform_ip6_nd_dad'.
        self._remove_ip6_host(ip6_host=ip6_host)
        return False

    def attach_dhcp4_client(self, client: Dhcp4Client, /) -> None:
        """
        Bind this L2 interface's DHCPv4 client (RFC 2131) — the stack
        lifecycle's construction-time wiring. L2-only: DHCPv4 depends on
        Ethernet / ARP, so '_dhcp4_client' lives on this subclass.
        """

        self._dhcp4_client = client

    @override
    def claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
        on_conflict: Callable[[Ip6Address], None] | None = None,
    ) -> threading.Thread:
        """
        Spawn a daemon worker thread that runs the DAD claim for
        'ip6_host' (synchronous '_perform_ip6_nd_dad' or
        '_claim_ip6_address_optimistic' depending on
        'icmp6.optimistic_dad'). Returns the worker thread so
        callers that need to wait for completion can '.join()'
        it; callers that fire-and-forget simply discard the
        returned handle.

        Multiple addresses can be claimed concurrently — each
        worker owns its own slot in '_icmp6_nd_dad__registry'
        and the RX dispatch keys on inbound NS / NA
        'target_address' to signal the right slot. This is what
        unblocks RFC 8981 temp-address regen (§18b/c) and
        runtime PI-arrival claims, neither of which can block
        the RX subsystem thread.

        When 'regenerate' is supplied (RFC 7217 §6 / RFC 8981
        §3.3.3), on DAD failure the worker calls it up to
        'icmp6.idgen_retries' times to mint a fresh candidate
        for the same prefix. The first candidate that DAD
        passes is installed; if all retries fail the
        accept_dad=2 fail-hard hook (§20.4) fires.
        """

        def _attempt_claim(candidate: Ip6IfAddr) -> bool:
            if sysctl_iface.get_for_iface("icmp6.optimistic_dad", self._interface_name) == 1:
                return self._claim_ip6_address_optimistic(ip6_host=candidate)
            ok = self._perform_ip6_nd_dad(ip6_unicast_candidate=candidate.address)
            if ok:
                self._assign_ip6_host(ip6_host=candidate)
            return ok

        def _worker() -> None:
            max_retries = (
                sysctl_iface.get_for_iface("icmp6.idgen_retries", self._interface_name) if regenerate is not None else 0
            )
            current = ip6_host
            for attempt in range(max_retries + 1):
                ok = _attempt_claim(current)
                if ok:
                    __debug__ and log("stack", f"Successfully claimed IPv6 address {current}")
                    return
                if attempt < max_retries:
                    # RFC 7217 §6 / RFC 8981 §3.3.3 — re-derive
                    # the IID and retry. The closure owns the
                    # 'dad_counter' / random-IID logic.
                    assert regenerate is not None
                    __debug__ and log(
                        "stack",
                        f"<WARN>DAD failure on {current}; regenerating " f"(attempt {attempt + 1}/{max_retries})</>",
                    )
                    current = regenerate()

            __debug__ and log(
                "stack",
                f"<WARN>Unable to claim IPv6 address {current}; gave up " f"after {max_retries} retries</>",
            )
            # Notify the per-protocol engine that requested this claim
            # (the DHCPv6 client) that the address is a duplicate, so it
            # can DECLINE it (RFC 8415 §18.2.8). Fired before the
            # accept_dad=2 fail-hard so the engine learns of the conflict
            # even when that policy then disables IPv6 stack-wide.
            if on_conflict is not None:
                on_conflict(current.address)
            # 'icmp6.accept_dad=2' fail-hard: any DAD failure
            # (after retries are exhausted) disables IPv6 on
            # the interface entirely. Linux 'accept_dad=2'
            # parity.
            if sysctl_iface.get_for_iface("icmp6.accept_dad", self._interface_name) == 2:
                __debug__ and log(
                    "stack",
                    f"<CRIT>icmp6.accept_dad=2 — DAD failure on {current} " "disables IPv6 on this interface</>",
                )
                self._ip6_support = False

        thread = threading.Thread(
            target=_worker,
            daemon=True,
            name=f"DAD-{ip6_host.address}",
        )
        thread.start()
        return thread

    @override
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.

        Each address claim spawns a daemon DAD worker thread via
        'claim_ip6_address_async'. With 'icmp6.optimistic_dad=0'
        the boot path '.join()'s every worker (preserving today's
        "address available only after DAD passes" semantic but
        permitting parallel DAD across candidates); with =1 the
        boot path fires-and-forgets so the workers transition
        OPTIMISTIC → VALID after boot has returned.

        For auto-configured addresses (link-local autoconfig,
        RA-driven SLAAC) the boot path passes an RFC 7217
        regenerator so DAD failures retry up to
        'icmp6.idgen_retries' times with an incremented
        'dad_counter' before giving up. Statically-configured
        candidates pass no regenerator — the operator picked
        the exact address; we cannot substitute a different
        one.
        """

        def _claim_ip6_address(
            ip6_host: Ip6IfAddr,
            *,
            regenerate: Callable[[], Ip6IfAddr] | None = None,
        ) -> None:
            thread = self.claim_ip6_address_async(ip6_host=ip6_host, regenerate=regenerate)
            if sysctl_iface.get_for_iface("icmp6.optimistic_dad", self._interface_name) == 0:
                thread.join()

        # Assign IPv6 All Nodes multicast address.
        self.assign_ip6_multicast(Ip6Address("ff02::1"))

        # Configure Link Local address(es) staticaly.
        for ip6_host in list(self._ip6_ifaddr_candidate):
            if ip6_host.address.is_link_local:
                self._ip6_ifaddr_candidate.remove(ip6_host)
                _claim_ip6_address(ip6_host)

        # Configure Link Local address automatically.
        if self._ip6_lla_autoconfig:
            lla_network = Ip6Network("fe80::/64")
            ip6_host = self._derive_ip6_host(ip6_network=lla_network)
            _claim_ip6_address(
                ip6_host,
                regenerate=self._make_rfc7217_regenerator(ip6_network=lla_network),
            )

        # If we don't have any link local address then disable
        # IPv6 protocol operations.
        if not self._ip6_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 link local address, " "disabling IPv6 protocol</>",
            )
            self._ip6_support = False
            return

        # Check if there are any statically configures GUA addresses.
        for ip6_host in list(self._ip6_ifaddr_candidate):
            self._ip6_ifaddr_candidate.remove(ip6_host)
            _claim_ip6_address(ip6_host)

        # Send out IPv6 Router Solicitation messages with
        # RFC 7559 §2 exponential backoff and wait for an RA
        # so SLAAC can pick up the advertised prefix.
        if self._ip6_gua_autoconfig:
            self._send_icmp6_nd_router_solicitations_with_backoff()
            # The RA source (tuple's 2nd element) no longer feeds
            # a per-IfAddr gateway: the default route was already
            # installed in the FIB by '_update_icmp6_default_router'
            # when the boot-window RA was received. Phase 4 may
            # simplify '_icmp6_ra__prefixes' to a prefix list.
            for prefix, _ in list(self._icmp6_ra__prefixes):
                __debug__ and log(
                    "stack",
                    f"Attempting IPv6 address auto configuration for RA " f"prefix {prefix}",
                )
                ip6_address = self._derive_ip6_host(ip6_network=prefix)
                _claim_ip6_address(
                    ip6_address,
                    regenerate=self._make_rfc7217_regenerator(ip6_network=prefix),
                )

        # Open the runtime-claim gate. From here on, any PI
        # arriving at the RX path for a brand-new prefix
        # (existing SLAAC entry is None) triggers an
        # immediate 'claim_ip6_address_async' for the
        # stable address. Boot-window PIs only updated the
        # tracking table and relied on the loop above for
        # their claim ordering.
        self._ip6_addressing_complete = True

    @override
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.

        Handles statically configured candidates only. As of Phase 4
        commit B, the DHCPv4 path is owned by 'stack.dhcp4_client'
        (a 'Subsystem' that 'stack.start()' brings up after the
        packet handler) — the lifecycle calls
        'stack.address.add(...)' on its BOUND transition; this
        method is not the integration point for that.
        """

        # RFC 1112 §4 — every IPv4 host joins the all-systems group
        # 224.0.0.1 permanently on every interface (programs the
        # 01:00:5e:00:00:01 multicast MAC on L2). It is never
        # IGMP-reported (RFC 3376 §6).
        self._assign_ip4_multicast(Ip4Address("224.0.0.1"))

        # Probe each candidate sequentially over its own 'Ip4Acd'
        # engine (the Linux 'sd-ipv4acd' model — RFC 5227 §2.1.1
        # Probe then §2.3 Announce on a clean probe). A statically
        # configured host gets probe + announce only, with NO
        # ongoing defender: this mirrors a bare Linux 'ip addr add',
        # where §2.4 ongoing defense is a managing-daemon job (DHCP
        # client / link-local autoconfig), not part of static
        # assignment. The engine opens its own AF_PACKET socket and
        # reads ARP off it for conflicts, so the stack's ARP RX path
        # is uninvolved.
        for ip4_host in list(self._ip4_ifaddr_candidate):
            self._ip4_ifaddr_candidate.remove(ip4_host)
            acd = Ip4Acd(mac_address=self._mac_unicast, ifindex=self._ifindex)
            if acd.probe(address=ip4_host.address).success:
                acd.announce(address=ip4_host.address)
                self._assign_ip4_host(ip4_host=ip4_host)
                __debug__ and log(
                    "stack",
                    f"Successfully claimed IPv4 address {ip4_host.address}",
                )
            else:
                __debug__ and log(
                    "stack",
                    f"<WARN>Unable to claim IPv4 address {ip4_host.address}</>",
                )

        # If we have no statically configured IPv4 host AND DHCP is
        # not running, disable IPv4 outright. When DHCP IS running,
        # 'stack.start()' blocks on
        # 'dhcp4_client.start_and_wait_for_bind(...)' AFTER this
        # method returns, so '_ip4_ifaddr' may still populate via the
        # Address API before any IPv4 application traffic flows.
        if not self._ip4_ifaddr and not self._ip4_dhcp:
            __debug__ and log(
                "stack",
                "<WARN>No statically configured IPv4 address and DHCP " "disabled; disabling IPv4 protocol</>",
            )
            self._ip4_support = False

    @override
    def assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_multicast = [*self._ip6_multicast, ip6_multicast]

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._assign_mac_multicast(ip6_multicast.multicast_mac)

        self._send_icmp6_multicast_listener_report()

    @override
    def remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_multicast = [group for group in self._ip6_multicast if group != ip6_multicast]

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")

        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    @override
    def _assign_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Assign IPv4 multicast group to the list stack listens on.
        """

        with self._lock__multicast:
            # Materialize the merged §3.2 reception filter (EXCLUDE{} for a
            # directly-assigned / any-source group, the merged contributors'
            # filter for a source-specific join).
            new = self._ip4_multicast_filter_for(ip4_multicast)
            self._ip4_multicast_filters[ip4_multicast] = new

            __debug__ and log("stack", f"Assigned IPv4 multicast {ip4_multicast}")

            # RFC 1112 §6.4 — the IPv4 multicast group maps to the Ethernet
            # multicast MAC 01:00:5e + low 23 bits of the group address.
            self._assign_mac_multicast(ip4_multicast.multicast_mac)

            # RFC 3376 §5.1 — announce the new membership with an unsolicited
            # state-change Report describing the INCLUDE{}→'new' transition
            # (the all-systems group is exempt, handled inside the TX method
            # per RFC 3376 §6).
            self._send_igmp_state_change(ip4_multicast, old=_IP4_MULTICAST__NONMEMBER, new=new)

    @override
    def _remove_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Remove IPv4 multicast group from the list stack listens on.
        """

        with self._lock__multicast:
            old = self._ip4_multicast_filters[ip4_multicast]
            del self._ip4_multicast_filters[ip4_multicast]

            __debug__ and log("stack", f"Removed IPv4 multicast {ip4_multicast}")

            self._remove_mac_multicast(ip4_multicast.multicast_mac)

            # RFC 3376 §5.1 — announce the departure with a state-change
            # Report describing the 'old'→INCLUDE{} transition (no longer a
            # member).
            self._send_igmp_state_change(ip4_multicast, old=old, new=_IP4_MULTICAST__NONMEMBER)

    def _assign_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Assign MAC multicast address to the list stack listens on.
        """

        self._mac_multicast.append(mac_multicast)

        __debug__ and log("stack", f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Remove MAC multicast address from the list stack listens on.
        """

        self._mac_multicast.remove(mac_multicast)

        __debug__ and log("stack", f"Removed MAC multicast {mac_multicast}")

    @override
    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (self._ip6_support, self._ip4_support):
            self._ip_configuration_in_progress.acquire(timeout=15)

        if __debug__:
            log(
                "stack",
                f"<INFO>Interface {self._interface_name} listening on unicast MAC address: " f"{self._mac_unicast}</>",
            )
            log(
                "stack",
                f"<INFO>Interface {self._interface_name} listening on multicast MAC addresses: "
                f"{', '.join([str(mac_multicast) for mac_multicast in set(self._mac_multicast)])}</>",
            )
            log(
                "stack",
                f"<INFO>Interface {self._interface_name} listening on broadcast MAC address: "
                f"{self._mac_broadcast}</>",
            )

        self._ip_configuration_in_progress.release(2)
        super()._log_stack_address_info()


class PacketHandlerL3(
    PacketHandler,
):
    """
    Pick up and respond to incoming packets on Layer 3 (TUN) interface.
    """

    _interface_layer = InterfaceLayer.L3

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        """

        assert self._rx_ring is not None, "Started PacketHandler must have an injected RX ring."

        if (packet_rx := self._rx_ring.dequeue()) is not None:
            # TUN PI-header EtherType -> handler demux via the
            # per-interface dispatch registry. The L3 registry holds
            # only the support-gated IPv4 / IPv6 entries (no ARP), so a
            # miss is an unhandled EtherType. The 4-byte TUN PI header
            # is stripped before the IP handler sees the frame.
            ethertype = EtherType.from_bytes(packet_rx.frame[2:4])
            handler = self._ethertype_registry.get(ethertype)
            if handler is None:
                __debug__ and log(
                    "stack",
                    f"<WARN>Unknown EtherType 0x{packet_rx.frame[2:4].hex()} " "received, dropping packet</>",
                )
            else:
                packet_rx.frame = packet_rx.frame[4:]
                handler(packet_rx)

    @override
    def claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
        on_conflict: Callable[[Ip6Address], None] | None = None,
    ) -> threading.Thread:
        """
        L3 has no DAD — claims complete synchronously via
        '_assign_ip6_host'. The 'regenerate' and 'on_conflict'
        callbacks are accepted for signature parity with L2 but
        never invoked (no DAD, so no failure to retry or report).
        The returned Thread is a no-op helper that has already
        finished, so callers '.join()'ing it return immediately.
        """

        del regenerate, on_conflict  # unused on L3 — no DAD, no retry, no conflict
        self._assign_ip6_host(ip6_host=ip6_host)
        thread = threading.Thread(target=lambda: None, daemon=True, name=f"DAD-{ip6_host.address}")
        thread.start()
        return thread

    @override
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.
        """

        self.assign_ip6_multicast(Ip6Address("ff02::1"))

        for ip6_host in list(self._ip6_ifaddr_candidate):
            self._ip6_ifaddr_candidate.remove(ip6_host)
            self._assign_ip6_host(ip6_host=ip6_host)

        if not self._ip6_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 address, disabling IPv6 " "protocol</>",
            )
            self._ip6_support = False

    @override
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        # RFC 1112 §4 — every IPv4 host joins the all-systems group
        # 224.0.0.1 permanently on every interface. It is never
        # IGMP-reported (RFC 3376 §6).
        self._assign_ip4_multicast(Ip4Address("224.0.0.1"))

        for ip4_host in list(self._ip4_ifaddr_candidate):
            self._ip4_ifaddr_candidate.remove(ip4_host)
            self._assign_ip4_host(ip4_host=ip4_host)

        if not self._ip4_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv4 address, disabling IPv4 " "protocol</>",
            )
            self._ip4_support = False

    @override
    def assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_multicast = [*self._ip6_multicast, ip6_multicast]

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._send_icmp6_multicast_listener_report()

    @override
    def remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        with self._lock__addr_config:
            self._ip6_multicast = [group for group in self._ip6_multicast if group != ip6_multicast]

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")

    @override
    def _assign_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Assign IPv4 multicast group to the list stack listens on. An L3
        (TUN) interface has no Ethernet layer, so no multicast MAC is
        programmed.
        """

        with self._lock__multicast:
            # Materialize the merged §3.2 reception filter (EXCLUDE{} for an
            # any-source group, the merged contributors' filter otherwise).
            new = self._ip4_multicast_filter_for(ip4_multicast)
            self._ip4_multicast_filters[ip4_multicast] = new

            __debug__ and log("stack", f"Assigned IPv4 multicast {ip4_multicast}")

            # RFC 3376 §5.1 — announce the new membership with an unsolicited
            # state-change Report describing the INCLUDE{}→'new' transition
            # (the all-systems group is exempt per RFC 3376 §6, handled inside
            # the TX method).
            self._send_igmp_state_change(ip4_multicast, old=_IP4_MULTICAST__NONMEMBER, new=new)

    @override
    def _remove_ip4_multicast(self, /, ip4_multicast: Ip4Address) -> None:
        """
        Remove IPv4 multicast group from the list stack listens on.
        """

        with self._lock__multicast:
            old = self._ip4_multicast_filters[ip4_multicast]
            del self._ip4_multicast_filters[ip4_multicast]

            __debug__ and log("stack", f"Removed IPv4 multicast {ip4_multicast}")

            # RFC 3376 §5.1 — announce the departure with a state-change
            # Report describing the 'old'→INCLUDE{} transition.
            self._send_igmp_state_change(ip4_multicast, old=old, new=_IP4_MULTICAST__NONMEMBER)


class PacketHandlerLoopback(
    PacketHandlerL3,
):
    """
    The loopback ('lo') interface handler — delivers locally-destined
    IP traffic internally instead of on the wire, the PyTCP analogue of
    the Linux 'lo' device. Owns 127.0.0.1/8 + ::1/128 and reports the
    LOOPBACK interface layer.

    Subclasses 'PacketHandlerL3' to reuse the no-Ethernet / no-DAD /
    synchronous-address-assignment plumbing (a loopback device has no
    L2, no neighbors, and its addresses need no acquisition). The
    behavioural discriminator is '_interface_layer = InterfaceLayer.
    LOOPBACK', not the class: the TX 'match self._interface_layer' arms
    are never reached because the IP-TX layer diverts locally-destined
    traffic onto the loopback ring BEFORE the L2/L3 split (see the
    loopback diversion in 'packet_handler__ip4__tx' / '…ip6__tx'), and
    the Link API surfaces the LOOPBACK flag from the layer. Reusing the
    L3 base keeps loopback inside the existing 'PacketHandlerL2 |
    PacketHandlerL3' interface union with no type-churn.

    Delivery is queue-based (never inline TX->RX->TX): the TX diversion
    'enqueue_loopback's the assembled IP packet onto '_lo_ring'; this
    handler's own subsystem thread drains it in '_subsystem_loop' and
    dispatches into the IP RX path. Two threads ping-pong via the queue
    so a whole handshake / transfer never nests in one call stack.
    """

    _interface_layer = InterfaceLayer.LOOPBACK
    _lo_ring: LoopbackRing

    @override
    def __init__(
        self,
        *,
        interface_mtu: int,
        interface_name: str = "lo",
        ip4_support: bool = True,
        ip6_support: bool = True,
    ) -> None:
        """
        Construct the loopback interface: build the delivery ring and
        self-assign the fixed loopback addresses.
        """

        super().__init__(
            interface_mtu=interface_mtu,
            interface_name=interface_name,
            ip4_support=ip4_support,
            ip6_support=ip6_support,
        )

        # In-process delivery queue; the consumer is this handler's own
        # subsystem thread ('_subsystem_loop' -> 'LoopbackRing.dequeue').
        self._lo_ring = LoopbackRing()

        # The loopback addresses are fixed constants with no acquisition
        # (no DHCP / SLAAC / DAD), so assign them directly at construction
        # rather than through the '_create_stack_ip*_addressing' acquire
        # threads. Assign IPv6 ::1 directly, NOT via '_assign_ip6_host'
        # (which would join a solicited-node multicast group and emit an
        # MLD report — 'lo' has no multicast plane).
        if ip4_support:
            self._assign_ip4_host(Ip4IfAddr("127.0.0.1/8"))
        if ip6_support:
            with self._lock__addr_config:
                self._ip6_ifaddr = [*self._ip6_ifaddr, Ip6IfAddr("::1/128")]

    @override
    def _subsystem_loop(self) -> None:
        """
        Drain one locally-destined packet from the loopback ring and
        deliver it to the IP RX path. Blocks up to
        'SUBSYSTEM_SLEEP_TIME__SEC' inside 'dequeue' so the loop stays
        stop-responsive.
        """

        if (packet_rx := self._lo_ring.dequeue()) is not None:
            self._deliver_loopback(packet_rx)

    def enqueue_loopback(self, packet_rx: PacketRx, /) -> None:
        """
        Enqueue a locally-destined IP packet for internal delivery on the
        loopback interface — the public producer surface the IP-TX
        layer's loopback diversion calls. Keeps the '_lo_ring' queue
        private to this handler (Phase-3 boundary).
        """

        self._lo_ring.enqueue(packet_rx)

    def _deliver_loopback(self, packet_rx: PacketRx, /) -> None:
        """
        Deliver a queued loopback packet into the IPv4 or IPv6 RX path by
        its IP version nibble. Unlike the TUN path there is no PI /
        EtherType prefix — the enqueued frame is a bare IP packet.

        Marks the packet 'from_loopback' so the IP parser skips the
        loopback-source martian check (a wire-ingress policy that must
        not apply to internally-looped traffic).
        """

        packet_rx.from_loopback = True

        match packet_rx.frame[0] >> 4:
            case 4:
                self._phrx_ip4(packet_rx)
            case 6:
                self._phrx_ip6(packet_rx)
            case version:
                __debug__ and log(
                    "stack",
                    f"<WARN>Loopback received unknown IP version {version}, dropping packet</>",
                )

    @override
    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        """
        Run a '_phtx_*' pipeline inline. 'lo' has no TX ring — every
        packet its '_phtx_ip4/6' assembles is diverted onto the loopback
        delivery ring (a thread-safe, lock-guarded enqueue), so there is
        no wire single-writer to marshal onto. Per-interface TX state
        ('_ip4_id', the sharded stat counters, the copy-on-write ifaddr
        lists) stays safe under concurrent callers without the ring.
        """

        return run()

    @override
    def _marshal_tx_async(self, run: Callable[[], TxStatus], /) -> None:
        """
        Fire-and-forget variant of '_marshal_tx' for the loopback
        interface — run the pipeline inline (see '_marshal_tx').
        """

        run()

    @override
    def _accepts_local_dst_ip4(self, dst: Ip4Address, /) -> bool:
        """
        Accept local delivery for the whole 127.0.0.0/8 loopback range
        and for any address the host owns (own-IP loops), on top of the
        base membership test. 'lo' owns only 127.0.0.1 as an interface
        address, so 'is_loopback' is what covers the rest of 127/8, and
        'stack.local_ip4_unicast()' covers a packet looped to one of the
        host's routable addresses.
        """

        return dst.is_loopback or dst in stack.local_ip4_unicast() or super()._accepts_local_dst_ip4(dst)

    @override
    def _accepts_local_dst_ip6(self, dst: Ip6Address, /) -> bool:
        """
        Accept local delivery for ::1 and for any address the host owns
        (own-IP loops), on top of the base membership test.
        """

        return dst.is_loopback or dst in stack.local_ip6_unicast() or super()._accepts_local_dst_ip6(dst)

    @override
    def _effective_ip6_hop_limit(self) -> int:
        """
        Return the default IPv6 hop limit for internally-delivered
        loopback traffic. 'lo' has no Router-Advertisement state (the
        L2-only '_icmp6_ra_parameters' the base reads is never set on the
        loopback handler), and a loopback packet is never forwarded, so
        the hop limit is a formality — the default is correct.
        """

        from net_proto import IP6__DEFAULT_HOP_LIMIT

        return IP6__DEFAULT_HOP_LIMIT

    @override
    def _create_stack_ip4_addressing(self) -> None:
        """
        No-op: the loopback IPv4 address (127.0.0.1/8) is assigned
        directly at construction (deterministic, nothing to acquire).
        """

    @override
    def _create_stack_ip6_addressing(self) -> None:
        """
        No-op: the loopback IPv6 address (::1/128) is assigned directly
        at construction (deterministic, nothing to acquire).
        """

    @override
    def _stop(self) -> None:
        """
        Release the loopback ring's eventfd back to the kernel on stack
        teardown.
        """

        super()._stop()
        self._lo_ring.close()
