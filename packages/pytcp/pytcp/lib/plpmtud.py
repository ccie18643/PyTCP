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
The unified Packetization-Layer PMTUD engine. 'PmtuSearch[A]'
is generic over the address type ('Ip4Address' /
'Ip6Address') and implements the RFC 4821 / RFC 8899 state
machine (BASE / SEARCHING / SEARCH_COMPLETE / ERROR) plus
the binary-search ladder, PROBE_TIMER and PMTU_RAISE_TIMER
machinery, MAX_PROBES black-hole detection, and the
ICMP-classical interaction. Per-transport adapters under
'pytcp/protocols/tcp/' and 'pytcp/protocols/udp/' consume
the public API; this module owns the state.

Design rationale and per-phase migration plan:
docs/refactor/plpmtud_unified_engine.md

pytcp/lib/plpmtud.py

ver 3.0.8
"""

from enum import auto
from typing import override

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.name_enum import NameEnum

# RFC 8899 §5.1.2 MAX_PROBES default — the number of
# consecutive losses on the engine before black-hole
# detection clamps to the family floor.
MAX_PROBES: int = 3

# RFC 8899 §5.1.1 PROBE_TIMER — time between probe-emit
# and loss-declaration. SHOULD be > 15 s; the default of
# 30 s matches the RFC recommendation.
PROBE_TIMER__SEC: float = 30.0

# RFC 8899 §5.1.1 PMTU_RAISE_TIMER — period a sender
# stays in SEARCH_COMPLETE before re-opening the search
# range, also used as the ERROR-recovery confirmation
# timer.
PMTU_RAISE_TIMER__SEC: float = 600.0

# RFC 8899 §5.1.2 MIN_PLPMTU — IPv6 floor is the RFC
# 8200 §5 hard 1280-byte minimum (no exceptions). IPv4
# uses RFC 1122 §3.3.3's EMTU_R minimum reassembly of
# 576 bytes as the practical floor; an IPv4 router is
# only required to forward 68 bytes (RFC 791) but
# probing below 576 is harmful in practice.
MIN_PLPMTU__IP4: int = 576
MIN_PLPMTU__IP6: int = 1280

# RFC 8899 §5.1.2 BASE_PLPMTU — the size of the initial
# connectivity-confirmation probe. The RFC recommends
# 1200 bytes for IPv4; IPv6 uses the 1280-byte minimum
# since BASE MUST be >= MIN_PLPMTU.
BASE_PLPMTU__IP4: int = 1200
BASE_PLPMTU__IP6: int = 1280

# RFC 8899 §5.3 search-algorithm granularity — when the
# remaining (search_high - ack_size) gap falls at or
# below this many bytes, further probing is no longer
# worthwhile and the engine declares convergence.
LADDER_GRANULARITY: int = 8


class PmtuState(NameEnum):
    """
    The DPLPMTUD state machine states (RFC 8899 §5.2).
    """

    DISABLED = auto()
    BASE = auto()
    SEARCHING = auto()
    SEARCH_COMPLETE = auto()
    ERROR = auto()


class PmtuSearch[A: Ip4Address | Ip6Address]:
    """
    The unified per-destination PLPMTUD search engine.
    Generic over the address type 'A'; per-transport
    adapters bind 'A' to their concrete address family
    and drive the engine via the public API
    ('next_probe_size', 'on_probe_ack', 'on_probe_loss',
    'on_classical_pmtu', 'confirm_current').
    """

    __slots__ = (
        "_address",
        "_state",
        "_current_mtu",
        "_candidate_mtu",
        "_ack_size",
        "_max_mtu",
        "_min_mtu",
        "_base_mtu",
        "_search_high",
        "_probe_count",
        "_probe_timer_expiry",
        "_raise_timer_expiry",
    )

    _address: A
    _state: PmtuState
    _current_mtu: int
    _candidate_mtu: int | None
    _ack_size: int
    _max_mtu: int
    _min_mtu: int
    _base_mtu: int
    _search_high: int
    _probe_count: int
    _probe_timer_expiry: float | None
    _raise_timer_expiry: float | None

    def __init__(self, *, address: A, interface_mtu: int) -> None:
        """
        Initialize the PLPMTUD engine for one destination.
        Constructed in the BASE state with the initial
        probe equal to BASE_PLPMTU so the search begins by
        confirming base connectivity (RFC 8899 §5.2).
        """

        self._address = address
        if isinstance(address, Ip6Address):
            self._min_mtu = MIN_PLPMTU__IP6
            self._base_mtu = BASE_PLPMTU__IP6
        else:
            self._min_mtu = MIN_PLPMTU__IP4
            self._base_mtu = BASE_PLPMTU__IP4
        self._max_mtu = max(interface_mtu, self._min_mtu)
        self._state = PmtuState.BASE
        # current_mtu starts at the interface MTU, not BASE_PLPMTU
        # — until probing or ICMP signals tell us otherwise, the
        # link MTU is the best available estimate (matches Linux's
        # pragmatic classical-PMTUD-compatible behaviour). The
        # BASE_PLPMTU value is the size of the initial *probe*, not
        # the working PLPMTU.
        self._current_mtu = self._max_mtu
        self._candidate_mtu = self._base_mtu
        self._ack_size = self._min_mtu
        self._search_high = self._max_mtu
        self._probe_count = 0
        self._probe_timer_expiry = None
        self._raise_timer_expiry = None

    @property
    def state(self) -> PmtuState:
        """
        Get the current engine state.
        """

        return self._state

    @property
    def current_mtu(self) -> int:
        """
        Get the effective current PLPMTU — the value the
        per-transport TX path should size data segments
        against.
        """

        return self._current_mtu

    @property
    def is_probing(self) -> bool:
        """
        Return True while a probe is in flight or pending
        emit (candidate_mtu set).
        """

        return self._candidate_mtu is not None

    @property
    def candidate_mtu(self) -> int | None:
        """
        Get the current candidate probe size without
        committing — read-only peek that does NOT arm the
        PROBE_TIMER. Returns None when no candidate is set
        (idle in SEARCH_COMPLETE / ERROR / DISABLED).
        Callers that want to actually emit a probe must use
        'next_probe_size' which arms the timer.
        """

        return self._candidate_mtu

    def disable(self) -> None:
        """
        Disable probing entirely. Used by adapters that
        opt out (e.g. raw sockets, applications that set
        IP_PMTUDISC_DONT-equivalent).
        """

        self._state = PmtuState.DISABLED
        self._candidate_mtu = None
        self._probe_timer_expiry = None
        self._raise_timer_expiry = None

    def next_probe_size(self, *, now: float) -> int | None:
        """
        Return the size of the probe the adapter should
        emit right now, or None if nothing should be
        emitted. The engine internally tracks the
        PROBE_TIMER and PMTU_RAISE_TIMER so the adapter
        can call this on each subsystem tick without
        knowing the timer details.
        """

        match self._state:
            case PmtuState.DISABLED:
                return None

            case PmtuState.ERROR:
                # RFC 8899 ERROR recovery — re-enter BASE
                # after PMTU_RAISE_TIMER expires to try
                # confirming connectivity again.
                if self._raise_timer_expiry is None or now < self._raise_timer_expiry:
                    return None
                self._state = PmtuState.BASE
                self._candidate_mtu = self._base_mtu
                self._probe_count = 0
                self._probe_timer_expiry = now + PROBE_TIMER__SEC
                self._raise_timer_expiry = None
                return self._candidate_mtu

            case PmtuState.SEARCH_COMPLETE:
                # RFC 8899 §5.1.1 PMTU_RAISE_TIMER —
                # re-open the search range to detect
                # path-MTU increases.
                if self._raise_timer_expiry is None or now < self._raise_timer_expiry:
                    return None
                self._search_high = self._max_mtu
                self._raise_timer_expiry = None
                self._candidate_mtu = self._next_candidate()
                self._state = PmtuState.SEARCHING
                if self._candidate_mtu is not None:
                    self._probe_timer_expiry = now + PROBE_TIMER__SEC
                    return self._candidate_mtu
                return None

            case PmtuState.BASE | PmtuState.SEARCHING:
                if self._candidate_mtu is None:
                    return None
                if self._probe_timer_expiry is None:
                    # First probe of this candidate.
                    self._probe_timer_expiry = now + PROBE_TIMER__SEC
                    return self._candidate_mtu
                # Probe in flight; caller awaits ack or
                # will call on_probe_loss when its timer
                # fires.
                return None

    def on_probe_ack(self, size: int, *, now: float) -> None:
        """
        Notify the engine that a probe of 'size' bytes was
        acknowledged. Resets the consecutive-loss counter
        and advances the search ladder.
        """

        if self._state is PmtuState.DISABLED:
            return

        self._probe_count = 0
        if size > self._ack_size:
            self._ack_size = size
        if size > self._current_mtu:
            self._current_mtu = size

        match self._state:
            case PmtuState.BASE:
                # Base confirmed; open the binary search
                # above ack_size.
                self._probe_timer_expiry = None
                self._candidate_mtu = self._next_candidate()
                if self._candidate_mtu is None:
                    self._enter_search_complete(now=now)
                else:
                    self._state = PmtuState.SEARCHING

            case PmtuState.SEARCHING:
                self._probe_timer_expiry = None
                self._candidate_mtu = self._next_candidate()
                if self._candidate_mtu is None:
                    self._enter_search_complete(now=now)

            case PmtuState.ERROR:
                # Out-of-band recovery: an ack arrived
                # while we'd given up. Re-enter SEARCHING.
                self._probe_timer_expiry = None
                self._raise_timer_expiry = None
                self._candidate_mtu = self._next_candidate()
                if self._candidate_mtu is None:
                    self._enter_search_complete(now=now)
                else:
                    self._state = PmtuState.SEARCHING

            case PmtuState.SEARCH_COMPLETE:
                # Idle ack; just refresh ack_size /
                # current_mtu (already done above).
                pass

    def on_probe_loss(self, *, now: float) -> None:
        """
        Notify the engine that the in-flight probe was
        lost (PROBE_TIMER expired without an ack).
        """

        if self._state in (PmtuState.DISABLED, PmtuState.SEARCH_COMPLETE, PmtuState.ERROR):
            return

        self._probe_count += 1
        self._probe_timer_expiry = None

        # Black-hole detection: MAX_PROBES consecutive
        # losses clamp to the floor and enter ERROR. The
        # PMTU_RAISE_TIMER doubles as the ERROR-recovery
        # confirmation timer per RFC 8899 §5.1.1.
        if self._probe_count >= MAX_PROBES:
            self._state = PmtuState.ERROR
            self._current_mtu = self._min_mtu
            self._candidate_mtu = None
            self._probe_count = 0
            self._raise_timer_expiry = now + PMTU_RAISE_TIMER__SEC
            return

        match self._state:
            case PmtuState.BASE:
                # Retry the base probe at the next tick.
                # Don't narrow search_high — BASE is the
                # connectivity confirmation, not a search.
                pass

            case PmtuState.SEARCHING:
                # The current candidate is too big; lower
                # the search ceiling and try a smaller
                # candidate.
                if self._candidate_mtu is not None:
                    self._search_high = self._candidate_mtu - 1
                self._candidate_mtu = self._next_candidate()
                if self._candidate_mtu is None:
                    self._enter_search_complete(now=now)

    def on_classical_pmtu(self, mtu: int, *, now: float) -> None:
        """
        Absorb a classical RFC 1191 / RFC 8201 PTB hint
        ('mtu' bytes). Per RFC 8201 §4 / RFC 8899 §4.5
        the classical signal can shrink the search range
        but MUST NOT raise the PLPMTU.
        """

        if self._state is PmtuState.DISABLED:
            return

        effective = max(self._min_mtu, mtu)

        match self._state:
            case PmtuState.ERROR:
                # Recovery: ICMP gives us a hint to try.
                self._search_high = max(effective, self._min_mtu)
                self._current_mtu = effective
                self._ack_size = self._min_mtu
                self._candidate_mtu = self._next_candidate()
                self._probe_count = 0
                self._probe_timer_expiry = None
                self._raise_timer_expiry = None
                if self._candidate_mtu is not None:
                    self._state = PmtuState.SEARCHING
                else:
                    self._enter_search_complete(now=now)

            case PmtuState.BASE | PmtuState.SEARCHING | PmtuState.SEARCH_COMPLETE:
                # Linux-aligned: ICMP shrinks 'current_mtu'
                # (the working PLPMTU per RFC 8201 §4) but
                # does NOT lower 'search_high' — the engine
                # must still be able to probe upward toward
                # interface_mtu to detect path-MTU
                # increases / verify the ICMP signal. This
                # matches Linux's 'tcp_mtu_probing'
                # behaviour where ICMP affects 'mss_cache'
                # but leaves the PLPMTUD upper bound alone;
                # 'search_high' only narrows on probe-loss.
                # RFC 4821 §7.6 allows MAY-set-from-ICMP;
                # PyTCP / Linux opt out.
                if effective < self._current_mtu:
                    self._current_mtu = effective
                # In-flight candidates are left unchanged
                # — if a candidate is now > effective the
                # probe will fail on the wire and the
                # probe-loss path will narrow search_high.
                # Linux's pragmatic choice: don't try to
                # second-guess in-flight probes from the
                # ICMP signal.

    def confirm_current(self, size: int) -> None:
        """
        Notify the engine that a non-probe data segment of
        'size' bytes was acknowledged. The implicit-probe
        feedback from regular traffic counts toward the
        search-low advancement per RFC 4821 §7.1 final
        paragraph.
        """

        if self._state is PmtuState.DISABLED:
            return
        if size > self._ack_size:
            self._ack_size = size
        if size > self._current_mtu and size <= self._search_high:
            self._current_mtu = size

    def _next_candidate(self) -> int | None:
        """
        Compute the next probe size via 8-byte-aligned
        binary search midpoint of (_ack_size, _search_high).
        Returns None when convergence is reached.
        """

        gap = self._search_high - self._ack_size
        if gap <= LADDER_GRANULARITY:
            return None
        mid = (self._ack_size + self._search_high) // 2
        # Align down to LADDER_GRANULARITY boundary.
        mid = (mid // LADDER_GRANULARITY) * LADDER_GRANULARITY
        if mid <= self._ack_size:
            mid = self._ack_size + LADDER_GRANULARITY
        if mid >= self._search_high:
            return None
        return mid

    def _enter_search_complete(self, *, now: float) -> None:
        """
        Transition into SEARCH_COMPLETE and arm the
        PMTU_RAISE_TIMER for the next probing round.
        """

        self._state = PmtuState.SEARCH_COMPLETE
        self._candidate_mtu = None
        self._probe_timer_expiry = None
        self._raise_timer_expiry = now + PMTU_RAISE_TIMER__SEC

    @override
    def __repr__(self) -> str:
        return (
            f"PmtuSearch(address={self._address!r}, state={self._state}, "
            f"current_mtu={self._current_mtu}, candidate={self._candidate_mtu}, "
            f"ack_size={self._ack_size}, search_high={self._search_high}, "
            f"probe_count={self._probe_count})"
        )
