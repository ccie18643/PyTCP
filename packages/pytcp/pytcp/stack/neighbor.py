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
This module contains the Neighbor-control API ('NeighborApi') —
the kernel/userspace boundary surface for static ARP / ND entries
and neighbour-cache inspection. The Linux equivalents are
'RTM_NEWNEIGH' / 'RTM_DELNEIGH' (rtnetlink) and the 'ip neighbor'
command; the backing state is each interface's per-protocol
ARP / ND cache.

pytcp/stack/neighbor.py

ver 3.0.10
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.lib.logger import log
from pytcp.lib.neighbor import NudState
from pytcp.runtime.socket import AddressFamily

if TYPE_CHECKING:
    from pytcp.protocols.arp.arp__cache import ArpCache
    from pytcp.protocols.icmp6.nd.nd__cache import NdCache
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


@dataclass(frozen=True, kw_only=True, slots=True)
class NeighborSnapshot:
    """
    Immutable point-in-time view of one neighbour-cache entry —
    the unit the introspection side of the Neighbor API returns
    ('ip neighbor show'). Copy-by-value: the caller cannot mutate
    cache state through it (the Phase-3 north-star
    "introspection is read-only" constraint from CLAUDE.md).
    """

    address: Ip4Address | Ip6Address
    mac_address: MacAddress | None
    state: NudState


class NeighborApi:
    """
    Neighbor-control surface — mirrors Linux RTNETLINK
    'RTM_NEWNEIGH' / 'RTM_DELNEIGH' / 'ip neighbor' semantics over
    each interface's ARP (IPv4) and ND (IPv6) caches.

    With no 'packet_handler' this is the unbound, device-independent
    TOOL (the 'ip neighbor' equivalent); select an interface via
    'interface(ifindex)'. With a 'packet_handler' (as returned by
    'interface(ifindex)') it is a VIEW bound to that one interface;
    its reads / mutations operate on that interface's ARP / ND
    caches only.

    Consumer code uses ONLY this surface — never reaches into
    'packet_handler._arp_cache' / '._nd_cache' directly. This is the
    architectural seam the Phase-3 north-star turns into a real IPC
    channel; the wrapper internals swap from direct cache mutation to
    RTNETLINK-equivalent message-bus routing without any consumer
    change.

    ARP / ND are link-layer (L2) operations, so the cache accessors
    'cast' the resolved handler to 'PacketHandlerL2'; calling them on
    an L3 (TUN) binding — which owns neither cache — raises
    AttributeError at runtime, and the cast surfaces that precondition
    to mypy.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the Neighbor-control API — unbound tool when
        'packet_handler' is None, else a view bound to that interface.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on — the handler bound by
        'interface(ifindex)'. The unbound tool has no default device:
        every per-interface operation MUST select one first, mirroring
        Linux 'ip neighbor ... dev <ifX>' / RTNETLINK requiring an
        explicit interface index (there is no sole-interface shortcut,
        even at N=1). Raises 'RuntimeError' when called on the unbound
        tool.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        raise RuntimeError(
            "The bare neighbor tool has no default device; select one via "
            "'stack.neighbor.interface(ifindex)' (Linux 'ip neighbor ... dev <ifX>')."
        )

    def interface(self, ifindex: int, /) -> NeighborApi:
        """
        Return a 'NeighborApi' bound to the interface registered under
        'ifindex' — the device selector, Linux 'ip neighbor … dev <ifX>'
        equivalent. Raises 'KeyError' when no interface is registered
        under 'ifindex'.
        """

        from pytcp import stack

        return NeighborApi(packet_handler=stack.interfaces[ifindex])

    def _arp_cache_if_any(self) -> "ArpCache | None":
        """
        The bound interface's ARP cache, or 'None' when the interface is
        L3 (a TUN device has no ARP cache).
        """

        return cast("PacketHandlerL2", self._resolve_handler()).arp_cache

    def _nd_cache_if_any(self) -> "NdCache | None":
        """
        The bound interface's ND cache, or 'None' when the interface is
        L3 — the IPv6 sibling of '_arp_cache_if_any'.
        """

        return cast("PacketHandlerL2", self._resolve_handler()).nd_cache

    def _arp_cache(self) -> "ArpCache":
        """
        Resolve the bound interface's ARP cache for a mutation. The
        'assert' encodes the L2-only precondition — adding / removing /
        flushing an ARP entry on an L3 interface is invalid.
        """

        cache = self._arp_cache_if_any()
        assert cache is not None, "ARP cache unavailable — the bound interface is not L2."
        return cache

    def _nd_cache(self) -> "NdCache":
        """
        Resolve the bound interface's ND cache for a mutation — the IPv6
        sibling of '_arp_cache'.
        """

        cache = self._nd_cache_if_any()
        assert cache is not None, "ND cache unavailable — the bound interface is not L2."
        return cache

    def add(self, *, ip: Ip4Address | Ip6Address, mac: MacAddress) -> None:
        """
        Install a permanent neighbour entry mapping 'ip' → 'mac' —
        Linux 'ip neighbor add <ip> lladdr <mac> nud permanent'. The
        family is inferred from 'ip': an IPv4 address lands in the
        interface's ARP cache, an IPv6 address in its ND cache. The
        entry never ages out and dynamic learning never overrides it.
        """

        if isinstance(ip, Ip6Address):
            self._nd_cache().add_permanent_entry(ip6_address=ip, mac_address=mac)
            __debug__ and log("stack", f"<lg>Neighbor API</>: added static ND {ip} -> {mac}")
            return
        self._arp_cache().add_permanent_entry(ip4_address=ip, mac_address=mac)
        __debug__ and log("stack", f"<lg>Neighbor API</>: added static ARP {ip} -> {mac}")

    def remove(self, *, ip: Ip4Address | Ip6Address) -> None:
        """
        Remove the neighbour entry for 'ip' — Linux 'ip neighbor del'.
        Dispatches to the ARP cache for an IPv4 address and the ND cache
        for an IPv6 address. No-op when no entry matches.
        """

        removed = (
            self._arp_cache().remove_entry(ip) if isinstance(ip, Ip4Address) else self._nd_cache().remove_entry(ip)
        )
        __debug__ and log("stack", f"<lg>Neighbor API</>: removed neighbour {ip} (matched={removed})")

    def flush(self, *, family: AddressFamily) -> None:
        """
        Drop every entry from the interface's ARP cache (family INET4)
        or ND cache (family INET6) — Linux 'ip neighbor flush'. A no-op on
        an L3 interface (a TUN device has no cache to flush).
        """

        cache = self._arp_cache_if_any() if family is AddressFamily.INET4 else self._nd_cache_if_any()
        if cache is None:
            return
        count = cache.flush()
        __debug__ and log("stack", f"<lg>Neighbor API</>: flushed {count} {family.name} neighbour(s)")

    def list_neighbors(
        self,
        *,
        family: AddressFamily | None = None,
    ) -> tuple[NeighborSnapshot, ...]:
        """
        Return a read-only copy-by-value snapshot of the interface's
        neighbour caches — Linux 'ip neighbor show'. With no 'family'
        the snapshot covers both caches (ARP first, then ND); pass
        'AddressFamily.INET4' / 'INET6' to filter (the Linux 'ip -4' /
        'ip -6' selectors). An L3 interface (a TUN device, with no ARP /
        ND cache) contributes no neighbours rather than erroring.
        """

        arp_cache = self._arp_cache_if_any()
        nd_cache = self._nd_cache_if_any()
        snapshots: list[NeighborSnapshot] = []
        if family in (None, AddressFamily.INET4) and arp_cache is not None:
            snapshots.extend(
                NeighborSnapshot(address=entry.address, mac_address=entry.mac_address, state=entry.state)
                for entry in arp_cache.snapshot()
            )
        if family in (None, AddressFamily.INET6) and nd_cache is not None:
            snapshots.extend(
                NeighborSnapshot(address=entry.address, mac_address=entry.mac_address, state=entry.state)
                for entry in nd_cache.snapshot()
            )
        return tuple(snapshots)
