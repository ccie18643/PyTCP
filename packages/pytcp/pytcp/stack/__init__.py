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
This package contains the stack components and global structures.

pytcp/stack/__init__.py

ver 3.0.8
"""

from __future__ import annotations

import fcntl
import os
import secrets
import struct
import sys
import threading
from enum import IntFlag
from typing import TYPE_CHECKING, Any

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.dhcp6.dhcp6__client import Dhcp6Client
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.protocols.tcp.tcp__stack import TcpStack
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.runtime.socket.packet__socket_table import PacketSocketTable
from pytcp.runtime.socket.socket_table import SocketTable
from pytcp.runtime.timer import Timer
from pytcp.stack.activity_introspect import ActivityIntrospectApi
from pytcp.stack.address import AddressApi
from pytcp.stack.link import LinkApi
from pytcp.stack.membership import MembershipApi
from pytcp.stack.neighbor import NeighborApi
from pytcp.stack.resolver import ResolverApi
from pytcp.stack.route import RouteApi
from pytcp.stack.socket_introspect import SocketIntrospectApi

if TYPE_CHECKING:
    from net_addr import Ip4IfAddr, Ip4Network, Ip6IfAddr, Ip6Network
    from pytcp.lib.plpmtud import PmtuSearch
    from pytcp.protocols.ip4.link_local.link_local__client import Ip4LinkLocal
    from pytcp.runtime.fib import RouteTable
    from pytcp.runtime.socket import AddressFamily
    from pytcp.runtime.socket.ping__socket import PingSocket


assert sys.version_info >= (
    3,
    12,
), "PyTCP stack requires Python version 3.12 or higher to run."


# TUN/TAP ioctl request number (Linux <linux/if_tun.h>);
# single value, no enum domain.
TUNSETIFF = 0x400454CA


class TunTapFlag(IntFlag):
    """
    TUN/TAP interface flags passed in the 'ifr_flags' field of
    the 'TUNSETIFF' ioctl. Linux numbers from
    '<linux/if_tun.h>'. 'IFF_TUN' and 'IFF_TAP' are mutually
    exclusive (interface type); 'IFF_NO_PI' is a separate
    modifier flag, OR'd in to suppress the 4-byte packet-info
    header on RX/TX.
    """

    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


# Bare module-level aliases — IFF_* are commonly referenced
# directly (mirroring how C code uses '#define IFF_TUN'), and
# the test fixture imports them as 'stack.IFF_TUN'.
IFF_TUN = TunTapFlag.IFF_TUN
IFF_TAP = TunTapFlag.IFF_TAP
IFF_NO_PI = TunTapFlag.IFF_NO_PI

# PyTCP code metadata.
PYTCP_VERSION = "ver 3.0.8"
GITHUB_REPO = "https://github.com/ccie18643/PyTCP"

# RFC 6528 §3 Initial Sequence Number secret. Generated once at
# module import via 'secrets.token_bytes(16)' so each PyTCP stack
# process has a fresh 128-bit keying value for the TCP ISN hash.
# 'pytcp.protocols.tcp.tcp__iss.compute_iss' reads this when TcpSession picks
# its initial sequence number; the secret never leaves the process
# and is regenerated on restart, so attackers who learn one ISN
# cannot infer ISNs for any other 4-tuple or for any future
# stack-process lifetime.
TCP__ISS_SECRET: bytes = secrets.token_bytes(16)

# RFC 6437 §3 IPv6 Flow Label generation secret. Generated
# once at module import via 'secrets.token_bytes(16)' so each
# PyTCP stack process picks a fresh 128-bit keying value for
# the per-(src, dst) flow-label hash. 'pytcp.protocols.ip6.ip6__flow_label.compute_ip6_flow_label'
# reads this when the IPv6 TX path needs a flow label (and
# the caller did not supply one explicitly). Same allocation
# pattern as 'TCP__ISS_SECRET' / 'TCP__FASTOPEN_SECRET'; the
# secret never leaves the process.
IP6__FLOW_SECRET: bytes = secrets.token_bytes(16)

# RFC 7413 TCP Fast Open server-side cookie generation
# secret. Same allocation pattern as 'TCP__ISS_SECRET':
# generated at module import time via 'secrets.token_bytes(16)'
# so each PyTCP stack process has a fresh 128-bit keying
# value for the TFO cookie HMAC. Implementations MAY rotate
# the secret to invalidate outstanding cookies; PyTCP keeps
# it stable for the process lifetime.
TCP__FASTOPEN_SECRET: bytes = secrets.token_bytes(16)

# RFC 6056 §3.3.3 Algorithm 3 port-selection secret. Used
# by 'pytcp.runtime.socket.socket__bind_helpers.pick_local_port_for' to compute
# a per-(local_ip, remote_ip, remote_port) BLAKE2s-keyed
# offset into the ephemeral port range so the source port
# for a TCP connect() is unpredictable to an off-path
# attacker AND independent of the source ports chosen for
# connections to other destinations (the §3.3.3
# per-destination subspace property). Same allocation
# pattern as 'TCP__ISS_SECRET' / 'TCP__FASTOPEN_SECRET' /
# 'IP6__FLOW_SECRET': 128 bits at module import, never
# persisted, regenerated on process restart.
TCP__PORT_SECRET: bytes = secrets.token_bytes(16)

# Mutable TCP-stack-level state (TFO cookie cache + negative
# cache + pending-request counter). Aggregated under one
# 'TcpStack' instance so test fixtures snapshot+restore one
# object instead of three separate fields, and a future new
# field is automatically covered by the existing reset path.
tcp_stack: TcpStack = TcpStack()

# RFC 7413 §3.1 cookie cache size cap. Bounds the per-process
# memory footprint of the TFO cookie cache for long-running
# clients that connect to many distinct servers. The default
# 1024 matches Linux's 'tcp_fastopen_blackhole_timeout_sec'
# era choice for cache size; entries are evicted in FIFO
# order (oldest first) when an insert would push the cache
# past the cap. Adjustable per process via direct assignment;
# tests patch this to small values to exercise the eviction
# path deterministically.
TCP__FASTOPEN_CACHE_MAX_SIZE: int = 1024

# Interface configuration.
INTERFACE__TAP__MTU = 1500
INTERFACE__TUN__MTU = 1500

# Addresses configuration.
MAC_ADDRESS: str = "02:00:00:{x}{x}:{x}{x}:{x}{x}"
IP4_ADDRESS = None
IP4_GATEWAY = None
IP6_ADDRESS = None
IP6_GATEWAY = None

# Protocol support configuration.
IP6__SUPPORT = True
IP4__SUPPORT = True

# Whether the stack accepts inbound IPv4 packets carrying LSRR or
# SSRR source-route options (RFC 791 §3.1, types 131 / 137).
# Default False matches Linux's 'net.ipv4.conf.*.accept_source_route'
# default since the early 2000s — source-routed packets are dropped
# at the IPv4 RX gate. Operators that genuinely need source-route
# acceptance set this to True per-interface.
#
# Per-interface storage — 'dict[str, bool]' keyed by interface
# name with a mandatory '"default"' slot. Operator addresses
# 'ip4.<ifname>.accept_source_route' or 'ip4.default.accept_source_route';
# the IPv4 RX consumer reads through 'sysctl_iface.get_for_iface'
# with the receiving interface's name. Plan:
# docs/refactor/sysctl_per_interface.md.
IP4__ACCEPT_SOURCE_ROUTE: dict[str, bool] = {"default": False}

# ARP runtime configuration constants live alongside the ARP
# protocol code at 'pytcp/protocols/arp/arp__constants.py'.
# Importers should refer to that module directly rather than
# reaching through 'pytcp.stack'.

# ICMPv6 ND cache aging timers moved to the generic NUD
# framework at 'pytcp/lib/neighbor__constants.py' alongside
# their IPv4 ARP counterparts. The 'NdCache' is now a thin
# adapter on 'NeighborCache[Ip6Address]' that reads
# 'neighbor.reachable_time' / 'neighbor.retrans_timer' / etc.
# Operators tune these via 'pytcp.stack.sysctl["neighbor.X"]'
# or the 'sysctls={"neighbor.X": ...}' bag kwarg on
# 'stack.init()'.

# IPv4 and IPv6 fragment flow expiration time, in seconds. Determines
# how long a fragment-reassembly flow is considered valid; flows older
# than this are cleaned up before every fragmented-packet handling
# pass. Linux exposes 'net.ipv4.ipfrag_time' / 'net.ipv6.ip6frag_time'
# with the same semantics; the IPv6 RFC recommends 60 s but Linux
# ships 5 s and PyTCP matches Linux.
IP4__FRAG_FLOW_TIMEOUT__S = 5
IP6__FRAG_FLOW_TIMEOUT__S = 5

# Native support for UDP Echo (used for packet flow unit testing only
# and should always be disabled).
UDP__ECHO_NATIVE = False

# RFC 6056 §3.2 ephemeral port range. Matches the Linux
# default ('net.ipv4.ip_local_port_range = 32768 60999')
# so PyTCP picks from a 28,232-port pool — well above the
# 16,384-port floor RFC 6056 §3.2 mentions for the IANA
# dynamic range, and large enough to give the §3.1
# obfuscation SHOULD meaningful guessing-space against an
# off-path attacker. Step=1 (every port is a candidate);
# the historical step=2 even-only restriction is gone.
# Stored as two ints — low (inclusive) and high (exclusive,
# matching Python's 'range(low, high)' semantics) — so each
# bound is independently tunable via the sysctl registry.
# Consumers build a 'range' on each call.
STACK__EPHEMERAL_PORT_RANGE__LOW = 32768
STACK__EPHEMERAL_PORT_RANGE__HIGH = 61000


# Sysctl registration. Every constant above (the four stack-wide
# policy knobs) is operator-tunable at boot via
# 'stack.init(sysctls={...})' or at runtime via
# 'pytcp.stack.sysctl["<dotted.key>"] = N'. Per the framework's
# per-package-atomic rule (and the documented migration in
# 'docs/refactor/sysctl_migration_remaining.md' §5), the
# 'register' calls live inline at the bottom of the constants
# section — same shape as the protocol packages' '*__constants.py'
# files. Cryptographic boot secrets ('TCP__ISS_SECRET',
# 'IP6__FLOW_SECRET', 'TCP__FASTOPEN_SECRET', 'TCP__PORT_SECRET'),
# boot-time defaults ('MAC_ADDRESS', 'IP4_ADDRESS', etc.),
# per-link MTUs, hard on/off support flags, and logger config
# are deliberately NOT registered — see §5.1 of that doc for
# the rationale.
from pytcp.stack.sysctl import get as _sysctl_get  # noqa: E402
from pytcp.stack.sysctl import is_int_in_range as _sysctl_is_int_in_range  # noqa: E402
from pytcp.stack.sysctl import is_positive_int as _sysctl_is_positive_int  # noqa: E402
from pytcp.stack.sysctl import register as _sysctl_register  # noqa: E402
from pytcp.stack.sysctl import register_finalize_validator as _sysctl_register_finalize_validator  # noqa: E402


def _stack__bool_validator(name: str) -> Any:
    """
    Build a validator that requires a real 'bool' value — rejects
    int / str / None so the knob's 0/1-switch semantics stay clean.
    """

    def validator(value: object) -> None:
        """
        Raise 'ValueError' unless 'value' is exactly 'True' or 'False'.
        """

        if not isinstance(value, bool):
            raise ValueError(
                f"sysctl {name!r} must be a bool; got {type(value).__name__}({value!r})",
            )

    return validator


_sysctl_register(
    key="ip4.accept_source_route",
    module_name=__name__,
    attr="IP4__ACCEPT_SOURCE_ROUTE",
    default=IP4__ACCEPT_SOURCE_ROUTE["default"],
    validator=_stack__bool_validator("ip4.accept_source_route"),
    interface_scope=True,
    description=(
        "RFC 791 §3.1 LSRR / SSRR acceptance gate; Linux" " 'net.ipv4.conf.<iface>.accept_source_route' analogue."
    ),
)
_sysctl_register(
    key="ip4.frag.flow_timeout_s",
    module_name=__name__,
    attr="IP4__FRAG_FLOW_TIMEOUT__S",
    default=IP4__FRAG_FLOW_TIMEOUT__S,
    validator=_sysctl_is_positive_int("ip4.frag.flow_timeout_s"),
    description=("RFC 815 IPv4 fragment-reassembly TTL in seconds; Linux" " 'net.ipv4.ipfrag_time' analogue."),
)
_sysctl_register(
    key="ip6.frag.flow_timeout_s",
    module_name=__name__,
    attr="IP6__FRAG_FLOW_TIMEOUT__S",
    default=IP6__FRAG_FLOW_TIMEOUT__S,
    validator=_sysctl_is_positive_int("ip6.frag.flow_timeout_s"),
    description=(
        "RFC 8200 §4.5 IPv6 fragment-reassembly TTL in seconds (Linux"
        " 'net.ipv6.ip6frag_time' ships 5 s; PyTCP matches Linux)."
    ),
)
_sysctl_register(
    key="net.ephemeral_port_range.low",
    module_name=__name__,
    attr="STACK__EPHEMERAL_PORT_RANGE__LOW",
    default=STACK__EPHEMERAL_PORT_RANGE__LOW,
    validator=_sysctl_is_int_in_range(
        "net.ephemeral_port_range.low",
        low=1024,
        high=65535,
    ),
    description=(
        "RFC 6056 §3.2 ephemeral-port-range lower bound (inclusive);"
        " Linux 'net.ipv4.ip_local_port_range' lower-bound field."
    ),
)
_sysctl_register(
    key="net.ephemeral_port_range.high",
    module_name=__name__,
    attr="STACK__EPHEMERAL_PORT_RANGE__HIGH",
    default=STACK__EPHEMERAL_PORT_RANGE__HIGH,
    validator=_sysctl_is_int_in_range(
        "net.ephemeral_port_range.high",
        low=1024,
        high=65535,
    ),
    description=(
        "RFC 6056 §3.2 ephemeral-port-range upper bound (exclusive,"
        " matching Python 'range' semantics); Linux"
        " 'net.ipv4.ip_local_port_range' upper-bound field."
    ),
)


def _stack__finalize__ephemeral_port_range_low_lt_high() -> None:
    """
    Cross-knob constraint — 'net.ephemeral_port_range.low' must be
    strictly less than 'net.ephemeral_port_range.high'. The pool
    consumers iterate as 'range(low, high)', which is empty when
    'low >= high' and would make every 'bind()' fall into the
    no-free-port branch.
    """

    low = _sysctl_get("net.ephemeral_port_range.low")
    high = _sysctl_get("net.ephemeral_port_range.high")
    if low >= high:
        raise ValueError(
            f"sysctl 'net.ephemeral_port_range.low' ({low}) must be strictly less than "
            f"'net.ephemeral_port_range.high' ({high}); the range pool 'range(low, high)' "
            f"would otherwise be empty."
        )


_sysctl_register_finalize_validator(_stack__finalize__ephemeral_port_range_low_lt_high)


# Logger configuration - LOG__CHANNEL sets which subsystems of stack log to the
# console, LOG__DEBUG adds info about class/method caller.
# Following subsystems are supported:
# stack, timer, rx-ring, tx-ring, arp-c, nd-c, ether, arp, ip4, ip6, icmp4,
# icmp6, udp, tcp, socket, tcp-ss, service.
LOG__CHANNEL = {
    "stack",
    # "timer",
    "rx-ring",
    "tx-ring",
    "arp-c",
    "nd-c",
    "ether",
    "arp",
    "ip4",
    "ip6",
    "icmp4",
    "icmp6",
    "igmp",
    "udp",
    "tcp",
    "socket",
    "tcp-ss",
    "dhcp4",
    "dhcp6",
    "service",
    "client",
}
LOG__DEBUG = False
LOG__OUTPUT = sys.stderr

# Stack subsystems.
timer: Timer
# The per-ifindex interface registry — the single source of truth for the
# stack's interfaces. Linux keys interfaces (and their ARP / ND caches,
# addresses, MTU) per ifindex; PyTCP's 'PacketHandler' instance IS the
# per-interface object, so the registry maps 'ifindex -> handler'. A
# multi-homed host registers one entry per interface; an interface is
# reached via 'interfaces[ifindex]', 'egress_packet_handler(dst)' (TX
# egress), or 'stack.link.interface(ifindex)' (control plane). Rebuilt
# fresh by 'init()' / 'mock__init()' (same reconstruct-per-test lifecycle
# as 'route', so it needs no snapshot/restore). The privileged
# 'stack.{packet_handler,rx_ring,tx_ring,arp_cache,nd_cache}' boot-shim
# singletons that pinned "interface 1" were retired in favour of this
# registry + the egress seam (Phase 7 / Part-6 Slice 4).
STACK__DEFAULT_IFINDEX: int = 1
interfaces: InterfaceTable = InterfaceTable(first_ifindex=STACK__DEFAULT_IFINDEX)
# Phase 4 commit A — IPv4 address-control API, the kernel/userspace
# boundary surface consumed by the DHCPv4 client and (eventually)
# operator-config CLI tools. Mirrors Linux RTNETLINK 'RTM_NEWADDR'
# / 'RTM_DELADDR' semantics. Set in 'init()' / 'mock__init()' after
# 'packet_handler' is constructed.
address: AddressApi
# Link API Phase 0 — link-control surface (MAC, MTU, interface
# layer; mutation lands in Phase 4). Mirrors Linux 'ip link' /
# RTNETLINK 'RTM_GETLINK' / 'RTM_NEWLINK'. Constructed by 'init()'
# / 'mock__init()' alongside 'address'. Replaces the
# 'packet_handler._mac_unicast' reach-through used by DHCP and
# RFC 3927 link-local construction. See
# 'docs/refactor/link_api.md' for the full plan.
link: LinkApi
# Neighbor API — neighbour-control surface (static ARP / ND
# entries, cache flush, neighbour inspection) over each
# interface's ARP / ND caches. Mirrors Linux 'ip neighbor' /
# RTNETLINK 'RTM_NEWNEIGH' / 'RTM_DELNEIGH'. Constructed by
# 'init()' / 'mock__init()' alongside 'address' / 'link'; same
# reconstruct-per-test lifecycle, so it needs no snapshot/restore.
neighbor: NeighborApi
# Membership API — multicast-group-control surface (IPv4 group
# join / leave / list) over each interface's multicast listen
# set. Mirrors the Linux 'IP_ADD_MEMBERSHIP' / 'IP_DROP_MEMBERSHIP'
# socket options and 'ip maddr'. Constructed by 'init()' /
# 'mock__init()' alongside 'address' / 'link' / 'neighbor'; same
# reconstruct-per-test lifecycle, so it needs no snapshot/restore.
membership: MembershipApi
# Default upstream DNS server for the stub resolver. Phase B2 (the
# 'pytcp daemon --dns-server' CLI arg) overrides this at 'init()'.
STACK__DNS_SERVER: Ip4Address = Ip4Address("9.9.9.9")
# Resolver API — DNS resolution control surface (the Linux
# 'getaddrinfo' analogue) over the daemon-side 'DnsResolver'.
# Constructed by 'init()' / 'mock__init()' alongside 'address' /
# 'link' / 'neighbor' / 'membership'; same reconstruct-per-test
# lifecycle, so it needs no snapshot/restore.
resolver: ResolverApi
# Socket introspection API — read-only socket-list observation
# surface (the Linux 'ss' analogue) over the open-socket table.
# Constructed by 'init()' / 'mock__init()'; stateless (it reads the
# global socket table at call time), so it needs no snapshot/restore.
ss: SocketIntrospectApi
# Per-interface activity introspection API — read-only "what is the
# stack doing right now" surface (DHCPv4 FSM state, DAD-in-progress IPv6
# addresses). Constructed by 'init()' / 'mock__init()'; stateless (it
# reads the live interface table at call time), so it needs no
# snapshot/restore.
activity: ActivityIntrospectApi
# Host-mode routing table (FIB) — Phase 1 of
# 'docs/refactor/routing_table_host_mode.md'. One per address
# family. Reconstructed fresh by 'init()' / 'mock__init()'
# (same lifecycle as 'timer' / 'address' / 'link'), so they do
# not leak across the test suite and need no snapshot/restore.
# Phase 1 is inert: the FIBs are populated by the boot
# dual-write but nothing reads them yet — the Ethernet-TX
# next-hop rewrite that consumes 'lookup()' lands in Phase 2.
ip4_fib: RouteTable[Ip4Address, Ip4Network]
ip6_fib: RouteTable[Ip6Address, Ip6Network]
# Route API Phase 1 — read-only routing-control surface over
# the two FIBs. Mirrors Linux 'ip route show' / RTNETLINK
# 'RTM_GETROUTE'. Mutation lands in Phase 3. Constructed by
# 'init()' / 'mock__init()' alongside 'address' / 'link'. See
# 'docs/refactor/routing_table_host_mode.md' for the full plan.
route: RouteApi
# Phase 4 commit B — DHCPv4 client subsystem. Constructed by
# 'init()' iff 'ip4_dhcp=True' on an L2 interface; spawned as a
# background thread by 'start()'; joined by 'stop()'. None on L3
# (TUN, no MAC) or when DHCP is disabled.
dhcp4_client: Dhcp4Client | None = None
# DHCPv6 client subsystem (RFC 8415). Constructed by 'init()' on an
# L2 interface with IPv6 enabled; spawned as a background thread by
# 'start()' and joined by 'stop()'. The worker idles until the RA RX
# handler triggers it on an inbound RA's Managed / Other-config flags.
# None on L3 (TUN, no link-scoped multicast) or when IPv6 is disabled.
dhcp6_client: Dhcp6Client | None = None
# RFC 3927 §2 IPv4 Link-Local autoconfig client subsystem. Phase
# 1 lands the slot only — the subsystem is not yet instantiated
# by 'init()'. The DHCP-fallback wiring lands in Phase 4 of the
# RFC 3927 track (docs/refactor/rfc3927_link_local_autoconfig.md).
link_local: "Ip4LinkLocal | None" = None

# Stack shared data.
stack_initialized: bool = False
# Link API Phase 2 — admin-up / running flag. True once
# 'start()' has spawned every subsystem thread; False after
# 'stop()' has signalled them to wind down. Linux's
# IFF_UP + IFF_RUNNING equivalent (PyTCP collapses the two
# because per-subsystem-up granularity has no consumer
# today). Snapshotted/restored by 'NetworkTestCase' per
# test so the flag does not leak across the integration
# suite.
stack_running: bool = False
sockets: SocketTable = SocketTable()
# AF_PACKET raw link-socket registry — the fan-out tap target for the
# Ethernet RX path (parallel to the IP-keyed 'sockets' above). Every
# packet socket registers here on construction and unregisters on
# close; '_phrx_ethernet' delivers a copy of each matching frame to the
# bound sockets. Module-level singleton (like 'sockets'); snapshotted /
# cleared / restored by 'NetworkTestCase' per test.
packet_sockets: PacketSocketTable = PacketSocketTable()
# ICMP Echo ('ping') datagram-socket registry — Linux 'SOCK_DGRAM +
# IPPROTO_ICMP / IPPROTO_ICMPV6'. Keyed by '(address family, ICMP id)';
# the id is unique per family, so the ICMP Echo Reply handler demuxes a
# reply to its owning socket by id (Linux keeps ping sockets in their own
# 'ping_table', separate from 'sockets'). Module-level singleton;
# snapshotted / cleared / restored by 'NetworkTestCase' per test.
icmp_echo_sockets: dict[tuple[AddressFamily, int], PingSocket] = {}
# RFC 1191 §3 / RFC 8201 §4 per-destination Path-MTU cache. Keyed
# by remote IP (v4 or v6); value is the most recently learned next-
# hop MTU. Populated by ICMP Frag-Needed / Packet-Too-Big handlers
# in Phases 4-6 of the ICMP demux + PMTUD refactor; consulted by
# UDP and TCP TX paths for fragment-or-fail / MSS-recompute
# decisions. Process-lifetime only — entries do not expire.
# Legacy scalar view; new consumers should call 'current_pmtu(dst)'
# below which prefers 'pmtu_state' when present.
pmtu_cache: dict[Ip4Address | Ip6Address, int] = {}

# RFC 4821 / RFC 8899 per-destination PLPMTUD engine state. Each
# entry is a PmtuSearch instance whose state machine
# (BASE / SEARCHING / SEARCH_COMPLETE / ERROR) the per-transport
# adapter drives. Phase 2 of the PLPMTUD plan
# (docs/refactor/plpmtud_unified_engine.md) introduces this dict
# alongside the legacy 'pmtu_cache' above; subsequent phases wire
# the TCP and UDP adapters that mutate it via PmtuSearch's public
# API ('on_probe_ack' / 'on_probe_loss' / 'on_classical_pmtu' /
# 'next_probe_size' / 'confirm_current').
pmtu_state: dict[Ip4Address | Ip6Address, PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]] = {}

# Guards every read / write of 'pmtu_cache' and 'pmtu_state'. The maps
# are written by the RX (ICMP Frag-Needed / Packet-Too-Big) thread and
# the application / TX (UDP / TCP) threads, and read by 'current_pmtu';
# GIL atomicity is not relied upon — PyTCP targets free-threaded
# CPython, where an unguarded dict write racing another access tears
# the map. All access goes through 'current_pmtu' /
# 'record_classical_pmtu' / 'record_pmtu_engine' below.
_pmtu_lock: threading.Lock = threading.Lock()


def current_pmtu(dst: Ip4Address | Ip6Address, /) -> int | None:
    """
    Return the current PLPMTU for 'dst', preferring the active
    PLPMTUD engine state ('pmtu_state') over the legacy
    classical-PMTUD scalar cache ('pmtu_cache'). Returns None
    when no signal has been observed for the destination — the
    caller should fall back to 'egress_interface_mtu(dst)'.
    """

    with _pmtu_lock:
        engine = pmtu_state.get(dst)
        if engine is not None:
            return engine.current_mtu
        return pmtu_cache.get(dst)


def record_classical_pmtu(dst: Ip4Address | Ip6Address, next_hop_mtu: int, /) -> None:
    """
    Record a classical-PMTUD (RFC 1191 / RFC 8201) per-destination
    next-hop MTU into 'pmtu_cache' under the shared pmtu lock.
    """

    with _pmtu_lock:
        pmtu_cache[dst] = next_hop_mtu


def record_pmtu_engine(
    dst: Ip4Address | Ip6Address,
    engine: PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address],
    /,
) -> None:
    """
    Record / replace the PLPMTUD engine state for 'dst' in
    'pmtu_state' under the shared pmtu lock.
    """

    with _pmtu_lock:
        pmtu_state[dst] = engine


def _is_link_scoped(destination: Ip4Address | Ip6Address, /) -> bool:
    """
    Return whether 'destination' is a link-scoped address delivered
    directly on the egress link with no routing-table entry — Linux
    never returns EHOSTUNREACH for these and auto-installs a per-
    interface broadcast / multicast route:
      - IPv4 limited broadcast (255.255.255.255) — a DHCP DISCOVER
        target sent before any address / route exists (RFC 2131 §4.1).
      - IP multicast (RFC 1112 §6.1 / RFC 4291 §2.7).
      - IPv6 link-local (RFC 4291 §2.5.6).
    """

    if isinstance(destination, Ip4Address):
        return destination.is_limited_broadcast or destination.is_multicast
    return destination.is_multicast or destination.is_link_local


def _egress_handler_via_fib(destination: Ip4Address | Ip6Address, /) -> PacketHandlerL2 | PacketHandlerL3 | None:
    """
    Resolve the egress interface for 'destination'.

    A routed destination resolves through the FIB: longest-prefix match,
    then map the matched route's 'oif' to its handler. For an on-link /
    connected destination the matched route carries 'oif' directly; for
    an off-link (gatewayed) route whose own 'oif' is unset, the egress is
    the interface on which the gateway is on-link (a second connected
    lookup).

    A link-scoped destination carries no routing entry — Linux auto-
    installs a per-interface broadcast / multicast route, so it egresses
    the local link: the sole registered interface at N=1, ambiguous
    (unresolved) on a multi-homed host until explicit egress selection
    (IP_MULTICAST_IF / sin6_scope_id) is modelled.

    Returns None when no egress interface can be resolved (no route, an
    oif not in the registry, or a link-scoped destination on a multi-
    homed host) — the caller raises 'EHOSTUNREACH' / falls back.
    """

    handler: PacketHandlerL2 | PacketHandlerL3 | None = None
    if isinstance(destination, Ip4Address):
        ip4_route = ip4_fib.lookup(destination, connected=connected_ip4_networks())
        if ip4_route is not None:
            if ip4_route.oif is not None and ip4_route.oif in interfaces:
                handler = interfaces[ip4_route.oif]
            elif ip4_route.gateway is not None:
                ip4_gw_route = ip4_fib.lookup(ip4_route.gateway, connected=connected_ip4_networks())
                if ip4_gw_route is not None and ip4_gw_route.oif is not None and ip4_gw_route.oif in interfaces:
                    handler = interfaces[ip4_gw_route.oif]
    else:
        ip6_route = ip6_fib.lookup(destination, connected=connected_ip6_networks())
        if ip6_route is not None:
            if ip6_route.oif is not None and ip6_route.oif in interfaces:
                handler = interfaces[ip6_route.oif]
            elif ip6_route.gateway is not None:
                ip6_gw_route = ip6_fib.lookup(ip6_route.gateway, connected=connected_ip6_networks())
                if ip6_gw_route is not None and ip6_gw_route.oif is not None and ip6_gw_route.oif in interfaces:
                    handler = interfaces[ip6_gw_route.oif]

    if handler is not None:
        return handler

    if _is_link_scoped(destination):
        handlers = interfaces.values()
        if len(handlers) == 1:
            return handlers[0]
    return None


def has_route_to(destination: Ip4Address | Ip6Address, /) -> bool:
    """
    Return whether the FIB resolves a usable egress route to
    'destination'. The socket send / connect paths consult this to raise
    a synchronous 'EHOSTUNREACH' (Linux parity: the route lookup happens
    at send/connect time, before the datagram is queued) when no route
    covers the destination.

    Returns True when no routing state is available — a reduced context
    (unit-test fixtures with no FIB installed) — so route-less fixtures
    do not spuriously block sends. The annotation-only 'ip4_fib' /
    'ip6_fib' declarations create no 'globals()' entry until 'init()' /
    'mock__init()' assign them, so the membership test below is the "is
    the routing plane up?" guard.
    """

    if "ip4_fib" not in globals() or "ip6_fib" not in globals():
        return True
    # Link-scoped destinations are delivered directly on the egress link
    # and need no routing-table entry, so they are reachable whenever the
    # routing plane is up — Linux never returns EHOSTUNREACH for them.
    if _is_link_scoped(destination):
        return True
    return _egress_handler_via_fib(destination) is not None


def egress_packet_handler(destination: Ip4Address | Ip6Address, /) -> PacketHandlerL2 | PacketHandlerL3:
    """
    Return the packet handler for the interface that egresses
    stack-originated traffic toward 'destination' — socket sends (UDP /
    raw IP) and TCP control segments. This is the single, centralized
    successor to the bare 'stack.packet_handler' reach-through: every
    socket-originated TX path resolves its egress interface through this
    one seam.

    Egress is the routing table's decision (1:1 Linux): the interface is
    resolved purely from the FIB ('Route.oif'), with link-scoped
    destinations egressing the local link (the sole interface at N=1).
    There is NO sole-interface guess for a routed destination — when the
    FIB cannot resolve an egress (no route covering 'destination', no
    interface registered, or a link-scoped destination on a multi-homed
    host) this raises 'RuntimeError', the way Linux returns EHOSTUNREACH
    rather than picking an interface the routing table did not select.
    """

    handler = _egress_handler_via_fib(destination)
    if handler is not None:
        return handler

    raise RuntimeError(
        f"No egress interface for destination {destination!r}: the routing "
        "table does not resolve one. Install a route covering it, add an "
        "interface, or (for a link-scoped destination on a multi-homed host) "
        "select the egress device explicitly."
    )


def egress_interface_mtu(destination: Ip4Address | Ip6Address, /) -> int | None:
    """
    Return the link MTU of the interface that egresses stack-originated
    traffic toward 'destination', or None when no egress interface can be
    resolved (a reduced context — no interface registered, or a multi-homed
    host with no route covering the destination).

    This is the per-destination successor to the retired
    'stack.interface_mtu' global: TCP MSS computation and the UDP / socket
    Path-MTU fall-back read the EGRESS interface's MTU, so a multi-homed
    host sizes its segments to the interface the FIB selects for the peer.

    Resolution mirrors 'egress_packet_handler' — FIB 'oif', with
    link-scoped destinations egressing the sole interface at N=1 — but
    returns None instead of raising, so MSS / PMTU callers degrade to
    their own conservative fall-back rather than failing a send. There is
    NO sole-interface guess for a routed destination the FIB cannot
    resolve (it returns None). The annotation-only 'ip4_fib' / 'ip6_fib'
    declarations create no 'globals()' entry until 'init()' /
    'mock__init()' assign them, so the membership test below is the "is
    the routing plane up?" guard.
    """

    if "ip4_fib" not in globals() or "ip6_fib" not in globals():
        return None
    handler = _egress_handler_via_fib(destination)
    return handler._interface_mtu if handler is not None else None


def egress_interface_name(destination: Ip4Address | Ip6Address, /) -> str | None:
    """
    Return the name (e.g. 'tap7') of the interface that egresses
    stack-originated traffic toward 'destination', or None when no
    egress interface can be resolved (a reduced context — no interface
    registered, the routing plane is not up yet, or a multi-homed host
    with no route covering the destination).

    The per-destination companion to 'egress_interface_mtu'. The TCP
    PLPMTUD cold-start path reads this so 'TcpSession.__init__' can
    resolve the per-interface 'tcp.mtu_probing' / 'tcp.base_mss'
    sysctls through 'sysctl_iface.get_for_iface(..., ifname)' without
    reaching into 'packet_handler._interface_name' directly — keeping
    the Phase-3 boundary clean.

    Resolution mirrors 'egress_interface_mtu' — FIB 'oif', or None.
    """

    if "ip4_fib" not in globals() or "ip6_fib" not in globals():
        return None
    handler = _egress_handler_via_fib(destination)
    return handler._interface_name if handler is not None else None


def local_ip4_hosts() -> tuple[Ip4IfAddr, ...]:
    """
    Return every configured IPv4 interface address across ALL registered
    interfaces — a read-only, copy-by-value snapshot (the Phase-3
    "introspection is read-only" contract). The cross-interface union is
    the multi-homed-host semantics: INADDR_ANY bind expansion and
    source-address selection consider every local address, not just one
    interface's. Linux equivalent: 'ip -4 addr show'.
    """

    hosts: list[Ip4IfAddr] = []
    for handler in interfaces.values():
        hosts.extend(handler.ip4_host)
    return tuple(hosts)


def local_ip6_hosts() -> tuple[Ip6IfAddr, ...]:
    """
    Return every configured IPv6 interface address across ALL registered
    interfaces — the IPv6 counterpart of 'local_ip4_hosts()'.
    """

    hosts: list[Ip6IfAddr] = []
    for handler in interfaces.values():
        hosts.extend(handler.ip6_host)
    return tuple(hosts)


def local_ip4_unicast() -> tuple[Ip4Address, ...]:
    """
    Return every configured IPv4 unicast address across ALL registered
    interfaces — a read-only snapshot used to validate that a
    socket-supplied source address is one the host owns (sendto / bind
    'EADDRNOTAVAIL' checks). Cross-interface union = multi-homed
    semantics. Linux 'ip -4 addr show' equivalent.
    """

    addresses: list[Ip4Address] = []
    for handler in interfaces.values():
        addresses.extend(handler.ip4_unicast)
    return tuple(addresses)


def local_ip6_unicast() -> tuple[Ip6Address, ...]:
    """
    Return every configured IPv6 unicast address across ALL registered
    interfaces — the IPv6 counterpart of 'local_ip4_unicast()'.
    """

    addresses: list[Ip6Address] = []
    for handler in interfaces.values():
        addresses.extend(handler.ip6_unicast)
    return tuple(addresses)


def connected_ip4_networks() -> tuple[tuple[Ip4Network, int], ...]:
    """
    Return every directly-connected IPv4 network paired with the index
    of the interface that owns it — the '(network, oif)' input the FIB
    'lookup()' synthesizes connected routes from. Spans all registered
    interfaces so cross-interface source selection sees every connected
    network tagged with its egress interface.
    """

    networks: list[tuple[Ip4Network, int]] = []
    for ifindex, handler in interfaces.items():
        for host in handler.ip4_host:
            networks.append((host.network, ifindex))
    return tuple(networks)


def connected_ip6_networks() -> tuple[tuple[Ip6Network, int], ...]:
    """
    Return every directly-connected IPv6 network paired with its owning
    interface index — the IPv6 counterpart of 'connected_ip4_networks()'.
    """

    networks: list[tuple[Ip6Network, int]] = []
    for ifindex, handler in interfaces.items():
        for host in handler.ip6_host:
            networks.append((host.network, ifindex))
    return tuple(networks)


# RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) outbound ICMP error rate
# limiters. One per L3 version so a flood of v4 errors cannot
# starve legitimate v6 error generation (and vice versa). Consumed
# by every ICMP error generator via try_emit_icmp_error().
icmp4_error_rate_limiter: IcmpErrorRateLimiter = IcmpErrorRateLimiter()
icmp6_error_rate_limiter: IcmpErrorRateLimiter = IcmpErrorRateLimiter()


def initialize_interface__tap(interface_name: str, *, mac_address: MacAddress | None = None) -> dict[str, Any]:
    """
    Initialize the TAP interface.
    """

    log("stack", f"Initializing TAP interface: {interface_name}")

    if mac_address is None:
        mac_address = MacAddress(MAC_ADDRESS.format(x=interface_name[3:5]))

    log("stack", f"Assigning MAC address: {mac_address}")

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", interface_name.encode(), IFF_TAP | IFF_NO_PI),
    )

    return {
        "fd": fd,
        "layer": InterfaceLayer.L2,
        "mtu": INTERFACE__TAP__MTU,
        "mac_address": mac_address,
        "interface_name": interface_name,
    }


def initialize_interface__tun(interface_name: str) -> dict[str, Any]:
    """
    Initialize the TUN interface.
    """

    log("stack", f"Initializing TUN interface: {interface_name}")

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", interface_name.encode(), IFF_TUN),
    )

    return {
        "fd": fd,
        "layer": InterfaceLayer.L3,
        "mtu": INTERFACE__TUN__MTU,
        "interface_name": interface_name,
    }


# Lifecycle entry points live in pytcp/stack/lifecycle.py per
# Phase 2 of docs/refactor/pytcp_directory_restructure.md; re-
# exported here so 'pytcp.stack.{init,start,stop,mock__init,
# add_interface}' import paths stay stable. 'add_interface' is the
# per-interface registration surface — the sanctioned way to attach
# a second (and further) interface once N>1 is enabled.
from pytcp.stack.lifecycle import (  # noqa: E402, F401
    add_interface,
    init,
    mock__init,
    remove_interface,
    start,
    stop,
)

# Public API surface of the stack package (source_files.md §2.3:
# __all__ lives only in package __init__.py). Required so mypy's
# strict no_implicit_reexport recognises the lifecycle / handler
# re-exports and the logging / sysctl config names as the
# package's intentional public surface.
__all__ = [
    "LOG__CHANNEL",
    "LOG__DEBUG",
    "LOG__OUTPUT",
    "PacketHandlerL2",
    "PacketHandlerL3",
    "Route",
    "RouteProtocol",
    "RouteScope",
    "TCP__ISS_SECRET",
    "add_interface",
    "init",
    "mock__init",
    "remove_interface",
    "start",
    "stop",
    "sysctl",
]
