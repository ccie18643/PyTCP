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
The TCP-side PLPMTUD adapter. 'TcpPlpmtudAdapter' wraps a
'PmtuSearch' engine and tracks per-session in-flight probe
segments so 'TcpSession' can drive RFC 4821 §3 / §5 / §7
active probing alongside the classical RFC 1191 / RFC 8201
ICMP-driven PMTUD that already exists.

The adapter exposes a thin API on top of 'PmtuSearch':
'maybe_probe(now)' queries whether a probe should be emitted
now; 'record_emitted_probe(seq, size, now)' records that an
emitted probe carries 'size' bytes at sequence number 'seq';
'on_snd_una_advance(new_snd_una, now)' detects probe-ack
events by checking whether any in-flight probe's terminal
sequence has been acknowledged; 'on_rto_timeout(now)'
declares any still-in-flight probes as lost. The adapter
keeps the engine and the TcpSession decoupled — the engine
owns the state-machine logic, the adapter owns the in-flight
probe bookkeeping, and the session glues the two to its
segment-emit and ack-processing paths.

Design rationale and per-phase migration plan:
docs/refactor/plpmtud_unified_engine.md

pytcp/protocols/tcp/tcp__plpmtud_adapter.py

ver 3.0.9
"""

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.plpmtud import PmtuSearch, PmtuState


class TcpPlpmtudAdapter:
    """
    Per-session PLPMTUD adapter. Owns the 'PmtuSearch'
    engine for the session's remote address and the
    in-flight probe-tracking dict.
    """

    __slots__ = ("_engine", "_in_flight")

    _engine: PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]
    _in_flight: dict[int, int]

    def __init__(
        self,
        *,
        remote_ip_address: Ip4Address | Ip6Address,
        interface_mtu: int,
    ) -> None:
        """
        Initialize the adapter for one session. 'remote_ip_address'
        is the session's peer; the engine's family floor (1280 for
        IPv6 / 576 for IPv4) is selected automatically from the
        address type. 'interface_mtu' is the local link MTU, used
        as the engine's MAX_PLPMTU ceiling.
        """

        if isinstance(remote_ip_address, Ip6Address):
            engine_ip6: PmtuSearch[Ip6Address] = PmtuSearch(
                address=remote_ip_address,
                interface_mtu=interface_mtu,
            )
            self._engine = engine_ip6
        else:
            engine_ip4: PmtuSearch[Ip4Address] = PmtuSearch(
                address=remote_ip_address,
                interface_mtu=interface_mtu,
            )
            self._engine = engine_ip4
        self._in_flight = {}

    @property
    def engine(self) -> PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]:
        """
        Get the underlying PLPMTUD engine instance. Test
        fixtures and the per-destination registry on
        'stack.pmtu_state' need direct access; ordinary
        callers should prefer the adapter's own API surface.
        """

        return self._engine

    @property
    def current_mtu(self) -> int:
        """
        Get the engine's current PLPMTU — what the session's
        segment factory should size data segments against.
        """

        return self._engine.current_mtu

    @property
    def state(self) -> PmtuState:
        """
        Get the engine's current state.
        """

        return self._engine.state

    @property
    def candidate_mtu(self) -> int | None:
        """
        Get the engine's current candidate probe size
        without committing (no PROBE_TIMER arming). Callers
        check this before deciding whether they have enough
        application data to fill the probe; only after the
        feasibility check do they call 'maybe_probe' to
        actually reserve the probe slot.
        """

        return self._engine.candidate_mtu

    @property
    def in_flight_probe_sizes(self) -> tuple[int, ...]:
        """
        Get a snapshot of in-flight probe sizes for RFC 4821
        §7.4 cwnd-exempt accounting — callers subtract the
        sum of these sizes from 'bytes_in_flight' so a
        probe-sized segment does not consume the congestion
        window.
        """

        return tuple(self._in_flight.values())

    def maybe_probe(self, *, now: float) -> int | None:
        """
        Query whether a probe should be emitted now. Returns
        the probe size if the engine is ready to probe, or
        None if no probe should be emitted (probe in flight,
        idle in SEARCH_COMPLETE / ERROR / DISABLED, etc.).

        The caller is responsible for actually emitting a
        segment of the returned size and then calling
        'record_emitted_probe' with the chosen sequence
        number.
        """

        return self._engine.next_probe_size(now=now)

    def record_emitted_probe(self, *, seq: int, size: int) -> None:
        """
        Record that a probe segment of 'size' bytes was emitted
        at sequence number 'seq'. The adapter tracks this entry
        so 'on_snd_una_advance' can detect when the probe is
        acknowledged and 'on_rto_timeout' can declare it lost.
        """

        self._in_flight[seq] = size

    def on_snd_una_advance(self, *, new_snd_una: int, now: float) -> None:
        """
        Notify the adapter that 'snd.una' has advanced. Any
        in-flight probe whose seq is now <= new_snd_una
        (modulo TCP's 32-bit wraparound — handled by treating
        'seq < new_snd_una' as "acked" within the active
        session's seq-space window) is declared acknowledged
        and the engine's 'on_probe_ack(size)' is dispatched.
        """

        acked_seqs: list[int] = []
        for seq, size in self._in_flight.items():
            if _seq_le(seq, new_snd_una):
                acked_seqs.append(seq)
                self._engine.on_probe_ack(size, now=now)
        for seq in acked_seqs:
            del self._in_flight[seq]

    def on_rto_timeout(self, *, now: float) -> None:
        """
        Notify the adapter that the session's retransmit
        timer fired. Any still-in-flight probe is declared
        lost and 'engine.on_probe_loss(now)' is dispatched.
        After this call the in-flight dict is empty — RTO is
        a loss event for every outstanding probe.
        """

        if not self._in_flight:
            return
        for _ in self._in_flight.values():
            self._engine.on_probe_loss(now=now)
        self._in_flight.clear()

    def on_classical_pmtu(self, mtu: int, *, now: float) -> None:
        """
        Pass-through to the engine's classical-PMTUD handler.
        Called by TcpSession._apply_pmtu_update so the engine
        absorbs RFC 1191 / RFC 8201 PTB signals.
        """

        self._engine.on_classical_pmtu(mtu, now=now)

    def confirm_current(self, size: int) -> None:
        """
        Pass-through to the engine's regular-data
        confirmation. Called by TcpSession when a non-probe
        segment is acknowledged; the largest such size
        advances ack_size per RFC 4821 §7.1 implicit-probe
        feedback.
        """

        self._engine.confirm_current(size)


def _seq_le(seq_a: int, seq_b: int) -> bool:
    """
    32-bit modular sequence comparison: returns True when
    'seq_a <= seq_b' under TCP's RFC 9293 §3.4 wraparound-
    aware ordering. The valid window is half the sequence
    space (2^31), so a "small" forward distance from 'seq_a'
    to 'seq_b' means 'seq_a' is <=; the symmetric backward
    distance means 'seq_a' is >. The single-byte tolerance
    above the modular comparison handles the inclusive
    "<=" check.
    """

    return ((seq_b - seq_a) & 0xFFFFFFFF) < 0x80000000
