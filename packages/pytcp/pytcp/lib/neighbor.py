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
This module contains the generic Neighbour Unreachability
Detection state machine — PyTCP's equivalent of Linux's
'net/core/neighbour.c'. The 'NeighborCache[A, P]' class is
generic over address type 'A' and queued-packet type 'P' so
the IPv4 ARP cache and the IPv6 ND cache share a single FSM
implementation; per-protocol adapters supply only the
wire-level solicit / flush hooks and bind 'P' to their
concrete payload type.

State transitions follow RFC 4861 §7.3.2:

    NUD_NONE → NUD_INCOMPLETE  (find_entry on miss)
    NUD_INCOMPLETE → NUD_REACHABLE  (Reply received)
    NUD_INCOMPLETE → NUD_FAILED  (after MAX_MULTICAST_SOLICIT)
    NUD_REACHABLE → NUD_STALE  (after REACHABLE_TIME)
    NUD_STALE → NUD_DELAY  (TX uses entry)
    NUD_DELAY → NUD_PROBE  (after DELAY_FIRST_PROBE_TIME)
    NUD_PROBE → NUD_REACHABLE  (Reply received)
    NUD_PROBE → NUD_FAILED  (after MAX_UNICAST_SOLICIT)

Plus the upper-layer fastpath:
    {STALE, DELAY, PROBE} → NUD_REACHABLE  (confirm_reachability)

PERMANENT entries skip every transition.

Design + per-phase migration plan: docs/refactor/nud_state_machine.md

pytcp/lib/neighbor.py

ver 3.0.8
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import auto
from typing import Callable, override

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.lib import neighbor__constants as nbr_const
from pytcp.lib.logger import log
from pytcp.lib.name_enum import NameEnum
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem
from pytcp.stack import sysctl_iface


class NudState(NameEnum):
    """
    The NUD finite-state-machine states (RFC 4861 §7.3.2 +
    PERMANENT for operator-configured static entries).
    """

    INCOMPLETE = auto()
    REACHABLE = auto()
    STALE = auto()
    DELAY = auto()
    PROBE = auto()
    FAILED = auto()
    PERMANENT = auto()


@dataclass(frozen=True, kw_only=True, slots=True)
class NeighborEntry[A: Ip4Address | Ip6Address, P = object]:
    """
    Per-neighbour FSM state. Frozen by codebase convention
    (net_proto.md §2); state transitions use
    'object.__setattr__' to mutate the instance — same pattern
    as 'CacheEntry.hit_count__increment'.

    Generic over both address type 'A' and queued-packet type
    'P'. Adapters bind 'P' to their wire-format type
    ('EthernetAssembler' for ARP / ND) so the flush callback
    receives a strongly-typed payload; the default 'P = object'
    keeps the unit-test fixture (which only exercises the FSM)
    free of a 'net_proto' dependency.
    """

    address: A
    mac_address: MacAddress | None = None
    state: NudState = NudState.INCOMPLETE
    state_changed_at: float = 0.0
    probe_count: int = 0
    queued_packets: deque[P] = field(default_factory=deque)
    last_used_at: float = 0.0


# Solicit callback signature: (address, cached_mac).
# 'cached_mac' is None for INCOMPLETE-state solicits
# (multicast NS / broadcast Request) and set to the cached
# MAC for PROBE-state solicits (unicast).
type SolicitCallback[A: Ip4Address | Ip6Address] = Callable[[A, MacAddress | None], None]

# Flush callback signature: (queued_packet, resolved_mac).
# Called from 'add_entry' once an INCOMPLETE entry resolves
# and a packet was queued via 'enqueue_pending'. Generic over
# packet type 'P' so adapters get a strongly-typed callback
# signature without runtime 'isinstance' narrowing.
type FlushCallback[P] = Callable[[P, MacAddress], None]


class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    """
    Generic neighbour cache implementing the RFC 4861 §7.3.2
    NUD state machine, parameterised over address type 'A' and
    queued-packet type 'P' so ARP (IPv4) and ND (IPv6) share
    one FSM. Adapters bind 'P' to their wire-format type
    ('EthernetAssembler' in both cases today); the default
    'P = object' lets the unit-test fixture exercise the FSM
    without a 'net_proto' dependency.
    """

    _entries: dict[A, NeighborEntry[A, P]]
    _solicit_callback: SolicitCallback[A]
    _flush_callback: FlushCallback[P] | None
    _lock: threading.Lock

    # Per-cache REACHABLE-state timeout override. Defaults to
    # None — the FSM falls back to the operator-configured
    # 'neighbor.reachable_time' sysctl. The IPv6 NdCache mutates
    # this when an RA carries a non-zero Reachable Time field
    # (RFC 4861 §6.3.4); the IPv4 ArpCache leaves it None so its
    # REACHABLE_TIME comes from the sysctl. Class-level default
    # so 'create_autospec(...)' fixtures pick it up.
    _reachable_time_override_s: float | None = None

    # Per-cache interface name for the 'neighbor.<ifname>.*'
    # sysctl namespace. Set by 'stack.init()' / 'add_interface'
    # alongside '_owner' (each cache binds to exactly one
    # interface). 'None' for harness fixtures with no interface
    # name plumbed; 'sysctl_iface.get_for_iface' treats 'None'
    # as a fallback to the '"default"' slot.
    _iface_name: str | None = None

    @override
    def __init__(
        self,
        *,
        name: str,
        solicit_callback: SolicitCallback[A],
        flush_callback: FlushCallback[P] | None = None,
    ) -> None:
        """
        Initialise the cache with the protocol-specific TX
        hooks. The 'solicit_callback' is mandatory; the
        'flush_callback' is optional (caches without queued-
        packet semantics can omit it).
        """

        # Set the Subsystem name BEFORE 'super().__init__' since
        # the base class logs '_subsystem_name' in its init.
        self._subsystem_name = name
        super().__init__()

        self._entries = {}
        self._solicit_callback = solicit_callback
        self._flush_callback = flush_callback
        self._lock = threading.Lock()

    def set_reachable_time_override_ms(self, value_ms: int | None) -> None:
        """
        Set or clear the per-cache REACHABLE-state timeout
        override. Pass an integer milliseconds value to install
        the override; pass None to revert to the operator-
        configured 'neighbor.reachable_time' sysctl. Used by the
        IPv6 NdCache to wire RA-driven Reachable Time updates per
        RFC 4861 §6.3.4.
        """

        self._reachable_time_override_s = value_ms / 1000.0 if value_ms is not None else None

    # ------------------------------------------------------------
    # Public surface — RX / TX integration points.
    # ------------------------------------------------------------

    def _find_entry(self, address: A) -> MacAddress | None:
        """
        Look up the MAC for an address. Drives the on-TX
        side of the FSM:
            NONE / missing → create INCOMPLETE, fire solicit, return None.
            INCOMPLETE → return None (loop drives retransmits).
            REACHABLE → return MAC.
            STALE → transition to DELAY, return MAC.
            DELAY → return MAC.
            PROBE → return MAC.
            FAILED → return None (FSM has given up).
            PERMANENT → return MAC.
        """

        with self._lock:
            entry = self._entries.get(address)
            now = time.monotonic()
            if entry is None:
                self._entries[address] = NeighborEntry[A, P](
                    address=address,
                    state=NudState.INCOMPLETE,
                    state_changed_at=now,
                    probe_count=1,
                    last_used_at=now,
                )
                __debug__ and log(
                    "stack",
                    f"NUD: {address} INCOMPLETE — first solicit",
                )
                self._solicit_callback(address, None)
                return None

            object.__setattr__(entry, "last_used_at", now)

            if entry.state in (NudState.REACHABLE, NudState.DELAY, NudState.PROBE, NudState.PERMANENT):
                return entry.mac_address
            if entry.state is NudState.STALE:
                # First TX after staleness → DELAY (grace
                # window for upper-layer reachability confirm
                # to fire before we send a unicast probe).
                self._transition(entry, NudState.DELAY, now)
                return entry.mac_address
            # INCOMPLETE / FAILED: no MAC available.
            return None

    def _add_entry(self, address: A, mac_address: MacAddress) -> None:
        """
        Drive the on-Reply side of the FSM. Transitions the
        named entry to REACHABLE (creating it if absent) and
        flushes any queued packet through the flush_callback.
        PERMANENT entries are not overridden — operator-
        configured static neighbours win over dynamic learning.
        """

        with self._lock:
            now = time.monotonic()
            entry = self._entries.get(address)

            if entry is not None and entry.state is NudState.PERMANENT:
                __debug__ and log(
                    "stack",
                    f"NUD: {address} add_entry skipped — entry is PERMANENT",
                )
                return

            if entry is None:
                entry = NeighborEntry[A, P](
                    address=address,
                    mac_address=mac_address,
                    state=NudState.REACHABLE,
                    state_changed_at=now,
                    last_used_at=now,
                )
                self._entries[address] = entry
                __debug__ and log(
                    "stack",
                    f"NUD: {address} → {mac_address} (REACHABLE, fresh)",
                )
                return

            queued_packets = list(entry.queued_packets)
            entry.queued_packets.clear()
            object.__setattr__(entry, "mac_address", mac_address)
            object.__setattr__(entry, "probe_count", 0)
            self._transition(entry, NudState.REACHABLE, now)

            if queued_packets and self._flush_callback is not None:
                __debug__ and log(
                    "stack",
                    f"NUD: {address} resolved → flushing {len(queued_packets)} queued packet(s)",
                )
                for queued_packet in queued_packets:
                    self._flush_callback(queued_packet, mac_address)

    def _add_permanent_entry(self, address: A, mac_address: MacAddress) -> None:
        """
        Install a PERMANENT entry — an operator-configured
        static neighbour that the FSM never ages out and
        dynamic learning never overrides.
        """

        with self._lock:
            now = time.monotonic()
            self._entries[address] = NeighborEntry[A, P](
                address=address,
                mac_address=mac_address,
                state=NudState.PERMANENT,
                state_changed_at=now,
                last_used_at=now,
            )
            __debug__ and log(
                "stack",
                f"NUD: {address} → {mac_address} (PERMANENT)",
            )

    def _remove_entry(self, address: A) -> bool:
        """
        Remove the cache entry for 'address' if present. Returns
        True when an entry was removed, False when none existed.
        The control-plane Neighbor API ('ip neighbor del')
        consumes this; lock-guarded so it is safe against the
        RX / TX threads walking '_entries'.
        """

        with self._lock:
            return self._entries.pop(address, None) is not None

    def _flush(self) -> int:
        """
        Drop every cache entry — the control-plane Neighbor API
        ('ip neighbor flush') consumes this. Returns the number of
        entries removed. Lock-guarded against the RX / TX threads.
        """

        with self._lock:
            count = len(self._entries)
            self._entries = {}
            return count

    def _snapshot(self) -> tuple[NeighborEntry[A, P], ...]:
        """
        Return an immutable point-in-time copy of the cache
        entries — the read side of the Neighbor introspection API
        ('ip neighbor show'). Lock-guarded so the caller sees a
        consistent set, never a mid-mutation view; the entries are
        frozen dataclasses, so the tuple is copy-by-value at the
        public boundary.
        """

        with self._lock:
            return tuple(self._entries.values())

    def _confirm_reachability(self, address: A) -> None:
        """
        Upper-layer fastpath: promote a STALE / DELAY / PROBE
        entry directly to REACHABLE without firing a unicast
        probe. Called by TCP on in-window ACK
        (RFC 4861 §7.3.1). Silent no-op for INCOMPLETE,
        FAILED, PERMANENT, and absent entries — the FSM has
        nothing useful to do with the confirm in those states.
        """

        with self._lock:
            entry = self._entries.get(address)
            if entry is None:
                return
            if entry.state in (NudState.STALE, NudState.DELAY, NudState.PROBE):
                self._transition(entry, NudState.REACHABLE, time.monotonic())
                object.__setattr__(entry, "probe_count", 0)

    def _enqueue_pending(self, address: A, packet: P) -> None:
        """
        Append an outbound packet to the INCOMPLETE address's
        bounded pending queue so 'add_entry' can dispatch all
        of them once the MAC is resolved (RFC 1122 §2.3.2.2).
        A fragmented datagram is several link-layer packets,
        so the queue holds many — bounded by the
        'neighbor.unres_qlen' sysctl, dropping the oldest on
        overflow (Linux 'neigh->arp_queue' policy: keep the
        newest within the limit).
        """

        with self._lock:
            entry = self._entries.get(address)
            if entry is None:
                # No outstanding INCOMPLETE entry — caller
                # forgot to 'find_entry' first. Silently
                # ignore rather than raise; the protocol's
                # next find will create the entry.
                return
            # Re-resolve the bound on every enqueue so a live
            # sysctl override takes effect immediately. Per-iface
            # slot wins; 'self._iface_name' is None for harness
            # fixtures (resolves to '"default"' slot).
            bound = sysctl_iface.get_for_iface("neighbor.unres_qlen", self._iface_name)
            queue = entry.queued_packets
            while len(queue) >= bound:
                queue.popleft()
            queue.append(packet)

    # ------------------------------------------------------------
    # Subsystem loop — timer-driven transitions.
    # ------------------------------------------------------------

    @override
    def _subsystem_loop(self) -> None:
        """
        Per-iteration timer-driven transitions:
            REACHABLE → STALE  after REACHABLE_TIME.
            DELAY → PROBE  after DELAY_FIRST_PROBE_TIME (fires unicast solicit).
            INCOMPLETE / PROBE  retransmit each RETRANS_TIMER until cap.
            INCOMPLETE → FAILED  past MAX_MULTICAST_SOLICIT.
            PROBE → FAILED  past MAX_UNICAST_SOLICIT.
        """

        # Resolve the six per-interface NUD timing knobs once
        # per loop iteration through 'sysctl_iface.get_for_iface',
        # which falls back from 'storage[<ifname>]' to the
        # '"default"' slot. The per-iteration cost is one dict
        # lookup per knob; the alternative (resolve at every
        # FSM branch) would multiply that without observable
        # benefit since the operator-set values change at human
        # timescales, not per-iteration.
        iface = self._iface_name
        sysctl_reachable_time = sysctl_iface.get_for_iface("neighbor.reachable_time", iface)
        delay_first_probe_time = sysctl_iface.get_for_iface("neighbor.delay_first_probe_time", iface)
        retrans_timer = sysctl_iface.get_for_iface("neighbor.retrans_timer", iface)
        max_multicast_solicit = sysctl_iface.get_for_iface("neighbor.max_multicast_solicit", iface)
        max_unicast_solicit = sysctl_iface.get_for_iface("neighbor.max_unicast_solicit", iface)

        now = time.monotonic()
        # Snapshot keys to allow mutation during iteration.
        with self._lock:
            addresses = list(self._entries.keys())

        for address in addresses:
            with self._lock:
                entry = self._entries.get(address)
                if entry is None:
                    continue

                state = entry.state
                age = now - entry.state_changed_at

                # RFC 4861 §6.3.4 RA-driven Reachable Time wins
                # over the operator default when set; ARP leaves
                # the override None.
                effective_reachable_time = (
                    self._reachable_time_override_s
                    if self._reachable_time_override_s is not None
                    else sysctl_reachable_time
                )
                if state is NudState.REACHABLE and age >= effective_reachable_time:
                    self._transition(entry, NudState.STALE, now)
                    continue

                if state is NudState.DELAY and age >= delay_first_probe_time:
                    self._transition(entry, NudState.PROBE, now)
                    object.__setattr__(entry, "probe_count", 1)
                    cached_mac = entry.mac_address
                # Note: the unicast solicit fires below, OUTSIDE
                # the lock, to avoid holding the lock through the
                # callback (the protocol-side TX path may itself
                # take other locks).
                elif state is NudState.INCOMPLETE:
                    if entry.probe_count >= max_multicast_solicit:
                        self._transition(entry, NudState.FAILED, now)
                        continue
                    if age >= retrans_timer:
                        object.__setattr__(entry, "probe_count", entry.probe_count + 1)
                        object.__setattr__(entry, "state_changed_at", now)
                        cached_mac = None
                    else:
                        continue
                elif state is NudState.PROBE:
                    if entry.probe_count >= max_unicast_solicit:
                        self._transition(entry, NudState.FAILED, now)
                        continue
                    if age >= retrans_timer:
                        object.__setattr__(entry, "probe_count", entry.probe_count + 1)
                        object.__setattr__(entry, "state_changed_at", now)
                        cached_mac = entry.mac_address
                    else:
                        continue
                else:
                    continue

            # Outside the lock — fire the solicit. The
            # 'cached_mac' local was set above for the three
            # branches that need to solicit (DELAY → PROBE,
            # INCOMPLETE retrans, PROBE retrans).
            self._solicit_callback(address, cached_mac)

        # Phase 5 — bounded-cache GC pass. Runs after the
        # state-transition pass so freshly-created FAILED
        # entries are immediately eviction-eligible at the
        # current cache size.
        self._gc_pass(now)

        # Inter-iteration sleep — Subsystem-base convention.
        self._event__stop_subsystem.wait(SUBSYSTEM_SLEEP_TIME__SEC)

    def _gc_pass(self, now: float) -> None:
        """
        Three-tier garbage-collection pass driven by the
        Linux 'gc_thresh1' / 'gc_thresh2' / 'gc_thresh3'
        sysctl trio:

            size <= gc_thresh1  no-op (small caches never GC).
            size <= gc_thresh2  evict FAILED entries only (cheap pruning).
            size <= gc_thresh3  also evict STALE entries past gc_stale_time.
            size  > gc_thresh3  hard cap; evict aggressively
                                 (FAILED → STALE → REACHABLE LRU)
                                 until size <= gc_thresh3.

        Entries that are NEVER eviction-eligible:
          - PERMANENT (operator-configured static neighbours).
          - INCOMPLETE / PROBE / DELAY entries with a
            non-empty 'queued_packets' queue (would lose the
            queued TX).

        Eviction priority is deliberately conservative —
        FAILED first (no working neighbour to lose), then
        STALE oldest (last positive evidence of reachability
        is the gc_stale_time-old timestamp), then REACHABLE
        by 'last_used_at' LRU (active flows survive longest).
        """

        with self._lock:
            size = len(self._entries)
            thresh1 = nbr_const.NEIGHBOR__GC_THRESH1
            thresh2 = nbr_const.NEIGHBOR__GC_THRESH2
            thresh3 = nbr_const.NEIGHBOR__GC_THRESH3
            stale_time = nbr_const.NEIGHBOR__GC_STALE_TIME

            if size <= thresh1:
                return

            evictable = [
                entry
                for entry in self._entries.values()
                if entry.state is not NudState.PERMANENT and not entry.queued_packets
            ]

            # Tier 1 — FAILED entries (oldest first).
            failed = sorted(
                (e for e in evictable if e.state is NudState.FAILED),
                key=lambda e: e.state_changed_at,
            )
            for entry in failed:
                del self._entries[entry.address]
                size -= 1
                __debug__ and log(
                    "stack",
                    f"NUD: GC evicted FAILED entry {entry.address}",
                )

            # Tier 2 — STALE entries past gc_stale_time (only
            # when above gc_thresh2).
            if size > thresh2:
                stale_eligible = sorted(
                    (
                        e
                        for e in evictable
                        if e.state is NudState.STALE
                        and now - e.state_changed_at >= stale_time
                        and e.address in self._entries
                    ),
                    key=lambda e: e.state_changed_at,
                )
                for entry in stale_eligible:
                    if size <= thresh2:
                        break
                    del self._entries[entry.address]
                    size -= 1
                    __debug__ and log(
                        "stack",
                        f"NUD: GC evicted STALE entry {entry.address}",
                    )

            # Tier 3 — hard cap. Evict any remaining entries
            # in LRU order (oldest 'last_used_at' first) until
            # size <= gc_thresh3. PERMANENT and queued-packet
            # entries are still skipped.
            if size > thresh3:
                lru = sorted(
                    (e for e in evictable if e.address in self._entries),
                    key=lambda e: e.last_used_at,
                )
                for entry in lru:
                    if size <= thresh3:
                        break
                    del self._entries[entry.address]
                    size -= 1
                    __debug__ and log(
                        "stack",
                        f"NUD: GC evicted (hard cap) {entry.address} state={entry.state}",
                    )

    # ------------------------------------------------------------
    # Internal helpers.
    # ------------------------------------------------------------

    def _transition(self, entry: NeighborEntry[A, P], new_state: NudState, now: float) -> None:
        """
        Update an entry's state + state_changed_at in lockstep.
        The instance is frozen; mutation goes through
        'object.__setattr__' (codebase convention).
        """

        old_state = entry.state
        object.__setattr__(entry, "state", new_state)
        object.__setattr__(entry, "state_changed_at", now)
        __debug__ and log(
            "stack",
            f"NUD: {entry.address} {old_state} → {new_state}",
        )
