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
This module contains the Phase-1 link-control API ('LinkApi')
— the kernel/userspace boundary surface that consumer code
(the DHCPv4 client, the RFC 3927 link-local autoconfig client,
future operator-config tools) uses to read link-level state
(MAC, MTU, interface layer) without reaching into
'PacketHandler' internals. The Linux equivalents are
'ip link show' / RTNETLINK 'RTM_GETLINK' / 'RTM_NEWLINK'.

Phase 0 ships only the read-only minimum surface — MAC, MTU,
interface layer. Subsequent phases add interface name
(Phase 1), running state + flags (Phase 2), stats
introspection (Phase 3), and mutation via 'set_mtu' /
'set_mac_address' (Phase 4). See
'docs/refactor/link_api.md' for the full plan.

pytcp/stack/link.py

ver 3.0.8
"""

from dataclasses import dataclass, fields
from enum import Enum, auto
from typing import TYPE_CHECKING

from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class LinkFlag(Enum):
    """
    Per-interface flag set mirroring Linux's IFF_* flag
    selection from 'linux/include/uapi/linux/if_link.h'.
    PyTCP exposes the four flags that have a meaningful
    semantic in the current stack:

    - BROADCAST   — interface carries broadcast traffic
                    (Ethernet on TAP).
    - MULTICAST   — interface carries multicast traffic
                    (Ethernet on TAP; IPv6 ND requires it).
    - LOOPBACK    — loopback interface (the 'lo' device;
                    internal delivery only, never on the wire).
    - POINTOPOINT — point-to-point link (TUN; no L2 broadcast
                    domain).

    Hardware-offload / multi-queue / qdisc flags from the
    Linux header are deliberately out of scope per the
    CLAUDE.md Project North Star non-goals.
    """

    BROADCAST = auto()
    MULTICAST = auto()
    LOOPBACK = auto()
    POINTOPOINT = auto()


_FLAGS_BY_LAYER: dict[InterfaceLayer, frozenset[LinkFlag]] = {
    InterfaceLayer.L2: frozenset({LinkFlag.BROADCAST, LinkFlag.MULTICAST}),
    InterfaceLayer.L3: frozenset({LinkFlag.POINTOPOINT}),
    InterfaceLayer.LOOPBACK: frozenset({LinkFlag.LOOPBACK}),
}


# RFC 791 §3.2 minimum IPv4 link MTU. The absolute floor for
# any link that carries IPv4. NOTE: links with MTU below 1280
# silently break IPv6 (RFC 8200 §5); operators that enable
# IPv6 SHOULD keep MTU >= 1280. PyTCP does not currently
# enforce the higher floor because there is no per-interface
# IPv6 enable/disable knob to release the constraint when an
# operator genuinely wants an IPv4-only low-MTU link.
LINK_API__MTU__MIN: int = 68

# uint16 wire limit — the largest MTU representable in the
# 'Total Length' field of an IPv4 header (RFC 791 §3.1).
LINK_API__MTU__MAX: int = 65535


@dataclass(frozen=True, kw_only=True, slots=True)
class LinkStats:
    """
    Copy-by-value snapshot of cumulative link-level
    interface statistics — Linux's 'struct
    rtnl_link_stats64' first-eight-buckets equivalent
    surfaced by 'ip -s link show'.

    Bucket → PyTCP counter mapping (documented verbatim
    here so future drop counters know which bucket they
    join):

    - 'rx_packets' / 'tx_packets':
        L2 (TAP) → 'PacketStatsRx.ethernet__pre_parse' +
                   'ethernet_802_3__pre_parse' /
                   'PacketStatsTx.ethernet__pre_assemble' +
                   'ethernet_802_3__pre_assemble'.
        L3 (TUN) → 'ip4__pre_parse' + 'ip6__pre_parse' /
                   'ip4__pre_assemble' + 'ip6__pre_assemble'.

    - 'rx_bytes' / 'tx_bytes':
        Read directly from 'LinkStatsCounters' bumped by
        'RxRing' / 'TxRing' at frame receive / send time.
        Wire-level bytes regardless of which protocol
        consumed them.

    - 'rx_errors':
        Sum of every 'PacketStatsRx' field whose name ends
        in '__failed_parse__drop' — these are structural
        validation failures ("couldn't decode the wire
        format"), Linux's 'rx_errors' equivalent.

    - 'rx_dropped':
        Sum of every 'PacketStatsRx' field whose name ends
        in '__drop' EXCEPT '__failed_parse__drop' — these
        are policy / config drops the stack chose to
        discard for non-error reasons (no listener, MAC
        filter mismatch, rate-limit suppression, etc.).

    - 'tx_errors':
        Sum of every 'PacketStatsTx' field whose name
        starts with 'tx_ring__' AND ends in '__drop' —
        kernel-level transmit failures (queue full,
        OSError on writev).

    - 'tx_dropped':
        Sum of every 'PacketStatsTx' field whose name
        ends in '__drop' EXCEPT the 'tx_ring__*__drop'
        ones — policy / config TX drops (broadcast
        disallowed, src not owned, scope mismatch,
        link-local out-of-scope, etc.).

    Phase 3 does NOT include multicast counters
    ('rx_multicast' / 'tx_multicast' from Linux's
    rtnl_link_stats64); a future revision may add them
    when a consumer materialises.
    """

    rx_packets: int
    rx_bytes: int
    rx_errors: int
    rx_dropped: int
    tx_packets: int
    tx_bytes: int
    tx_errors: int
    tx_dropped: int


def _sum_drops(
    stats: PacketStatsRx | PacketStatsTx,
    *,
    prefix: str = "",
    suffix: str = "__drop",
    exclude_suffix: str | None = None,
    exclude_prefix: str | None = None,
) -> int:
    """
    Sum dataclass int fields matching the prefix / suffix
    filter — used to aggregate '*__drop' counters into
    LinkStats error/dropped buckets without hard-coding
    every field name.
    """

    total = 0
    for field in fields(stats):
        name = field.name
        if not name.endswith(suffix):
            continue
        if prefix and not name.startswith(prefix):
            continue
        if exclude_suffix is not None and name.endswith(exclude_suffix):
            continue
        if exclude_prefix is not None and name.startswith(exclude_prefix):
            continue
        total += getattr(stats, name)
    return total


class LinkApi:
    """
    Phase-1 link-control surface — mirrors Linux 'ip link
    show' / RTNETLINK 'RTM_GETLINK' semantics for the
    read-only subset.

    Phase-1 implementation: thin properties over
    'PacketHandler._mac_unicast' / '_interface_mtu' /
    '_interface_layer'. Consumer code — DHCPv4 client,
    RFC 3927 link-local autoconfig client, future
    operator-config CLI — uses ONLY this surface to read
    link-level facts. Never reaches into 'packet_handler.*'
    directly. This is the architectural seam the Phase-3
    north-star turns into a real IPC channel; the wrapper
    internals swap from direct attribute reads to
    RTNETLINK-equivalent message routing without any
    consumer change.

    Phase 0 covers MAC + MTU + interface layer. Phases 1-4
    add interface name, running state, flags, stats, and
    mutation. See 'docs/refactor/link_api.md' for the full
    roadmap.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the link-control API. With no 'packet_handler' this
        is the unbound, device-independent TOOL (the 'ip link'
        equivalent) — operate on a specific interface via
        'interface(ifindex)'. With a 'packet_handler' (as returned by
        'interface(ifindex)') it is a VIEW bound to that one interface;
        its reads / mutations operate on that interface only.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on — the handler bound by
        'interface(ifindex)'. The unbound tool has no default device:
        every per-interface operation MUST select one first, mirroring
        Linux 'ip link ... dev <ifX>' / RTNETLINK requiring an explicit
        interface index (there is no sole-interface shortcut, even at
        N=1). Raises 'RuntimeError' when called on the unbound tool.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        raise RuntimeError(
            "The bare link tool has no default device; select one via "
            "'stack.link.interface(ifindex)' (Linux 'ip link ... dev <ifX>')."
        )

    def interface(self, ifindex: int, /) -> LinkApi:
        """
        Return a 'LinkApi' bound to the interface registered under
        'ifindex' — the device selector, Linux 'ip link … dev <ifX>'
        equivalent. Every read property and mutation on the returned
        binding operates on that interface. Raises 'KeyError' when no
        interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return LinkApi(packet_handler=stack.interfaces[ifindex])

    def list_interfaces(self) -> tuple[int, ...]:
        """
        Return the registered interface indexes in ascending order —
        the dump-all (no-selector) form, Linux 'ip link show' with no
        device equivalent. Pair with 'interface(ifindex)' to read each.
        """

        from pytcp import stack

        return tuple(sorted(stack.interfaces))

    @property
    def mac_address(self) -> MacAddress | None:
        """
        Return the interface's unicast MAC address — Linux
        'ip link show eth0 | grep link/ether' equivalent.

        Returns None on L3 (TUN) interfaces, which have no
        Ethernet layer and therefore no MAC. The packet
        handler's 'mac_unicast' read surface returns None on
        L3 without an isinstance check here.
        """

        return self._resolve_handler().mac_unicast

    @property
    def mtu(self) -> int:
        """
        Return the interface MTU in bytes — Linux
        'ip link show eth0 | grep mtu' equivalent.
        """

        return self._resolve_handler().interface_mtu

    @property
    def name(self) -> str | None:
        """
        Return the interface name plumbed through by
        'stack.init()' (e.g. 'tap7', 'tun7') — Linux
        'ip link show' first-column equivalent.

        Returns None when the packet handler was
        constructed without an interface name — e.g. a
        unit-test fixture or 'mock__init' that skipped
        the name plumbing.
        """

        return self._resolve_handler().interface_name

    @property
    def interface_layer(self) -> InterfaceLayer:
        """
        Return the interface layer (L2 = TAP, L3 = TUN) —
        Linux 'ip link show eth0 | grep link/' equivalent.
        """

        return self._resolve_handler().interface_layer

    @property
    def is_running(self) -> bool:
        """
        Return True when the stack has been started via
        'stack.start()' and not yet stopped via
        'stack.stop()' — Linux's 'IFF_UP + IFF_RUNNING'
        equivalent. PyTCP collapses the two flags into one
        because per-subsystem-up granularity has no
        consumer today; a future split (e.g. admin-up vs
        link-up) would land as a Phase-2 multi-interface
        extension.

        Reads 'pytcp.stack.stack_running'; the module-level
        flag is maintained by 'start()' / 'stop()' and
        reset to False by 'mock__init()' for unit tests.
        """

        from pytcp import stack

        return stack.stack_running

    @property
    def stats(self) -> LinkStats:
        """
        Return a copy-by-value snapshot of cumulative
        link-level interface statistics — Linux 'ip -s
        link show eth0' RX/TX block equivalent.

        The returned 'LinkStats' is frozen + slotted; the
        caller cannot mutate stack-internal state through
        the snapshot per the Phase-3 north-star
        "introspection is read-only" constraint. See the
        'LinkStats' docstring for the bucket → counter
        mapping; aggregation walks 'PacketStatsRx' /
        'PacketStatsTx' fields by name pattern so adding
        a new '__drop' counter automatically lands in the
        right bucket (failed_parse vs other on RX; tx_ring
        vs other on TX).
        """

        handler = self._resolve_handler()
        rx = handler.packet_stats_rx
        tx = handler.packet_stats_tx
        link = handler.link_stats
        layer = handler.interface_layer

        if layer is InterfaceLayer.L2:
            rx_packets = rx.ethernet__pre_parse + rx.ethernet_802_3__pre_parse
            tx_packets = tx.ethernet__pre_assemble + tx.ethernet_802_3__pre_assemble
        else:
            rx_packets = rx.ip4__pre_parse + rx.ip6__pre_parse
            tx_packets = tx.ip4__pre_assemble + tx.ip6__pre_assemble

        rx_errors = _sum_drops(rx, suffix="__failed_parse__drop")
        rx_dropped = _sum_drops(rx, suffix="__drop", exclude_suffix="__failed_parse__drop")

        tx_errors = _sum_drops(tx, prefix="tx_ring__", suffix="__drop")
        tx_dropped = _sum_drops(tx, suffix="__drop", exclude_prefix="tx_ring__")

        return LinkStats(
            rx_packets=rx_packets,
            rx_bytes=link.rx_bytes,
            rx_errors=rx_errors,
            rx_dropped=rx_dropped,
            tx_packets=tx_packets,
            tx_bytes=link.tx_bytes,
            tx_errors=tx_errors,
            tx_dropped=tx_dropped,
        )

    def set_mtu(self, *, mtu: int) -> None:
        """
        Set the interface MTU in bytes — Linux 'ip link
        set eth0 mtu N' equivalent. Validates the value
        against the RFC 791 §3.2 floor (68) and the uint16
        wire limit (65535); propagates the update to every
        site that caches the MTU (the packet handler and the
        TX/RX rings if present).

        NOTE: values below 1280 break IPv6 (RFC 8200 §5).
        PyTCP does not currently enforce a higher floor —
        the operator owns the IPv4-only-low-MTU
        consequences.

        Raises 'ValueError' on out-of-range; the rejection
        message cites the offending bound.
        """

        if not (LINK_API__MTU__MIN <= mtu <= LINK_API__MTU__MAX):
            raise ValueError(
                f"MTU {mtu} out of range. Must be between "
                f"{LINK_API__MTU__MIN} (RFC 791 §3.2 floor) and "
                f"{LINK_API__MTU__MAX} (uint16 wire limit)."
            )

        handler = self._resolve_handler()

        # The packet handler's 'set_interface_mtu' mutator is the
        # canonical write point — it updates '_interface_mtu' (what the
        # TX paths read for MSS / fragmentation decisions; TCP MSS / UDP &
        # socket Path-MTU consumers reach it per-destination via
        # 'stack.egress_interface_mtu(dst)') and resizes the BOUND
        # interface's own RX / TX rings (their read / writev size bound),
        # not the global 'stack.{tx,rx}_ring' shims. So
        # 'interface(ifindex).set_mtu' resizes the named device's state,
        # not the boot interface's.
        handler.set_interface_mtu(mtu)

    def set_mac_address(self, *, mac_address: MacAddress) -> None:
        """
        Set the interface unicast MAC address — Linux 'ip
        link set eth0 address aa:bb:cc:dd:ee:ff'
        equivalent.

        Requires the stack to be STOPPED ('stack.stop()'
        called, or 'stack.start()' not yet called) — the
        Linux precondition is 'ip link set down' first; the
        PyTCP analog is 'not stack.stack_running'. The
        check exists because changing the MAC while the
        stack is running invalidates in-flight ARP cache
        entries on peers; the canonical recovery
        (gratuitous announce) requires a clean start
        sequence which is only available at boot.

        Validates the new MAC must be unicast (multicast
        bit clear) and non-zero — neither the all-zero MAC
        nor any multicast MAC is a valid unicast
        identifier.

        Available only on L2 (TAP) interfaces; raises on
        L3 (TUN) where there is no Ethernet layer.

        Peer ARP / ND caches retain stale entries for the
        old MAC until they age out naturally; immediate
        refresh is the address manager's job — the DHCPv4
        client and RFC 3927 link-local autoconfig re-announce
        their addresses (RFC 5227 §2.3) over their own
        'Ip4Acd' engine after the next 'stack.start()'.
        """

        from pytcp import stack

        handler = self._resolve_handler()

        if stack.stack_running:
            raise RuntimeError("Cannot set MAC address while the stack is running. " "Call 'stack.stop()' first.")

        if handler.interface_layer is not InterfaceLayer.L2:
            raise RuntimeError("Cannot set MAC address on L3 (TUN) interface — no Ethernet layer.")

        if not mac_address.is_unicast:
            raise ValueError(
                f"MAC address {mac_address} is not a valid unicast MAC "
                "(multicast bit must be clear and value must be non-zero)."
            )

        handler.set_mac_address(mac_address)

    @property
    def flags(self) -> frozenset[LinkFlag]:
        """
        Return the set of 'LinkFlag' values that apply to
        this interface — Linux 'ip link show eth0' '<...>'
        bracket equivalent.

        Phase-1 derives the set from 'interface_layer':
        L2 (TAP) carries BROADCAST + MULTICAST; L3 (TUN)
        carries POINTOPOINT; LOOPBACK (lo) carries LOOPBACK.
        A future commit may add runtime-configurable flags
        (NOARP / DEBUG / PROMISC) when consumers materialise.

        Returns a 'frozenset' (immutable, copy-by-value)
        so the caller cannot mutate stack-internal state
        through the returned reference.
        """

        return _FLAGS_BY_LAYER[self._resolve_handler().interface_layer]
