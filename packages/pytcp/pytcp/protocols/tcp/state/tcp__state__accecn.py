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
This module contains the per-session AccECN state container,
decomposed out of 'TcpSession' so the RFC 9768 receiver/sender
counters, last-emit tracker, and negotiation state live as one
coherent object.

The fields cover the §3.1.1 negotiation handshake codepoint, the
§3.2.1 / §3.2.2 receiver counters (r.cep, r.e0b, r.ce_b, r.e1b),
the §3.2.3 last-emit tracker (driving option ordering and
abbreviation), the §3.2.1 / §3.2.2.1 sender mirrors (s.cep,
s.e0b, s.e1b, s.ce_b), and the §3.2.2.1 Note 1 / §3.2.2.3
disable / mangling sentinels.

Mutability mirrors 'CcState' and 'HyStartState':
'@dataclass(slots=True)' rather than 'frozen=True' because the
counters wrap on every inbound segment.

pytcp/protocols/tcp/state/tcp__state__accecn.py

ver 3.0.9
"""

from dataclasses import dataclass

# RFC 9768 §3.2.1 initial counter values. r.e0b / r.e1b / s.e0b /
# s.e1b initialise to 1 (not 0) so a freshly negotiated session
# is distinguishable from middlebox-zeroed fields; r.ceb / s.ce_b
# start at 0 because zero CE marks at connection start is the
# expected steady state.
ACCECN__INITIAL_BYTE_COUNTER: int = 1
ACCECN__INITIAL_CE_BYTE_COUNTER: int = 0

# RFC 9768 §3.2.2.1 initial cep value. 5 (binary 101) distinguishes
# a freshly-negotiated AccECN session from value 0 (special
# meaning) and from middlebox-zeroed fields.
ACCECN__INITIAL_CEP: int = 5

# RFC 9768 §3.2.3 last-emit sentinel. -1 is outside the uint24
# range of the real byte counters, so the very first AccECN-
# option emission always sees 'changed' for all three slots and
# emits the full Length=11 form to seed the peer with our
# initial state.
ACCECN__LAST_EMIT_SENTINEL: int = -1

# AccECN counter width per the option specification. All r.* / s.*
# byte counters and r.cep / s.cep are 24-bit unsigned integers
# carried as uint24 fields in the option wire format.
ACCECN__COUNTER_MASK: int = 0xFF_FFFF


@dataclass(slots=True)
class AccEcnState:
    """
    Per-session AccECN state. Owned by 'TcpSession'; mutated in
    place by the session's RX counter accumulation hook, the
    sender-counter update hook, and the option-emission path.
    """

    # RFC 9768 §3.1.1 bilateral-negotiation flag. True after the
    # handshake exchanged AccECN-setup SYN + AccECN-confirming
    # SYN+ACK. Mutually exclusive with 'EcnState.ecn_enabled'.
    enabled: bool = False

    # RFC 9768 §3.1.1 passive-side codepoint capture. When an
    # AccECN-setup SYN arrives at LISTEN, the listener captures
    # the IP-ECN codepoint of the received SYN here so the
    # outbound SYN+ACK can encode it as the corresponding
    # AE/CWR/ECE codepoint. Values: 0=Not-ECT, 1=ECT(1),
    # 2=ECT(0), 3=CE. Unused on the active-open side.
    synack_codepoint: int = 0

    # RFC 9768 §3.2.2.1 active-side handshake ACE encoding. On
    # the active-open client, when an AccECN-confirming SYN+ACK
    # arrives, the SYN_SENT handler stores the Table-3 ACE value
    # here so the third-leg ACK encodes it instead of the
    # regular 'r.cep & 7' value. Cleared once consumed.
    handshake_ack_pending: int | None = None

    # RFC 9768 §3.2.2 receiver-side r.cep counter. Tracks the
    # cumulative count of CE-marked inbound segments (modulo
    # 2^24). The low 3 bits encode the ACE field on every
    # outbound non-SYN segment.
    r_cep: int = ACCECN__INITIAL_CEP

    # RFC 9768 §3.2.3 receiver-side per-codepoint TCP-payload
    # byte counters. Each accumulates payload bytes received in
    # segments carrying the corresponding IP-ECN codepoint
    # (modulo 2^24). The three counters are emitted in the
    # AccECN0/1 option on every outbound non-SYN segment.
    r_ect0_b: int = ACCECN__INITIAL_BYTE_COUNTER
    r_ce_b: int = ACCECN__INITIAL_CE_BYTE_COUNTER
    r_ect1_b: int = ACCECN__INITIAL_BYTE_COUNTER

    # RFC 9768 §3.2.3 last-emit tracker for the order/length
    # choice. At each outbound AccECN-option emission the
    # session compares the current r.* byte counters against
    # the last-emitted values to decide which counter changed
    # (driving the AccECN0 vs AccECN1 ordering pick) and which
    # counters to include (driving the Length 11/8/5/2 choice).
    r_last_emit_e0b: int = ACCECN__LAST_EMIT_SENTINEL
    r_last_emit_ceb: int = ACCECN__LAST_EMIT_SENTINEL
    r_last_emit_e1b: int = ACCECN__LAST_EMIT_SENTINEL

    # RFC 9768 §3.2.1 / §3.2.2.1 sender-side counters. 's.cep'
    # tracks the peer's r.cep value as inferred from the
    # third-leg ACK's ACE field (Table 4) and from each
    # subsequent ACK's ACE delta. 's.disabled' is the §3.2.2.1
    # Note 1 sentinel: when the third-leg ACK arrives with
    # ACE=000, the server MUST NOT set ECT on outgoing packets
    # and MUST NOT respond to AccECN feedback for the rest of
    # the connection.
    s_cep: int = ACCECN__INITIAL_CEP
    s_disabled: bool = False

    # RFC 9768 §3.2.2.3 IP-ECN mangling detector. Set True when
    # the IP-ECN codepoint peer reports observing on our
    # handshake-leg segment does not match the Not-ECT we
    # actually sent per RFC 3168 §6.1.1. Observational at
    # present; future work may gate outbound ECT marking on it
    # to disable ECT emission on mangled paths while keeping
    # AccECN feedback responsive.
    mangling_detected: bool = False

    # RFC 9768 §3.2.1 sender-side per-codepoint byte counter
    # trackers. Mirror the peer's r.e0b / r.e1b values as
    # carried in the AccECN option's byte-count slots; both
    # initialise to 1 to match the §3.2.1 initial values, so
    # the first delta computed against an inbound option is
    # computed off the correct baseline.
    s_ect0_b: int = ACCECN__INITIAL_BYTE_COUNTER
    s_ect1_b: int = ACCECN__INITIAL_BYTE_COUNTER

    # RFC 9768 §3.4 sender-side r.CE tracker. Holds the last
    # peer-reported r.CE byte counter seen in an inbound AccECN
    # option. The fsm wrapper compares the newly-arrived value
    # against this tracker; a positive delta is the wire signal
    # for a congestion event and triggers RFC 5681 §3.1
    # cwnd-halving.
    s_ce_b: int = ACCECN__INITIAL_CE_BYTE_COUNTER

    def record_received_codepoint(self, ip_ecn: int, payload_len: int) -> None:
        """
        Accumulate the receiver-side r.* counters from one inbound
        segment's IP-ECN codepoint. Increments r.cep by 1 and
        r.ce_b by the payload length on CE; otherwise increments
        the per-codepoint byte counter (r.ect0_b for ECT(0),
        r.ect1_b for ECT(1)). Counters wrap modulo 2^24 per the
        AccECN option width.

        Reference: RFC 9768 §3.2.2 (r.cep increment on CE).
        Reference: RFC 9768 §3.2.3 (per-codepoint byte counters).
        """

        if ip_ecn == 3:
            self.r_cep = (self.r_cep + 1) & ACCECN__COUNTER_MASK
            self.r_ce_b = (self.r_ce_b + payload_len) & ACCECN__COUNTER_MASK
        elif ip_ecn == 2:
            self.r_ect0_b = (self.r_ect0_b + payload_len) & ACCECN__COUNTER_MASK
        elif ip_ecn == 1:
            self.r_ect1_b = (self.r_ect1_b + payload_len) & ACCECN__COUNTER_MASK

    def update_sender_counters_from_option(
        self,
        accecn0_counters: tuple[int | None, int | None, int | None],
    ) -> None:
        """
        Apply the inbound AccECN option's byte counters to the
        sender-side mirrors (s.ect0_b, s.ce_b, s.ect1_b). Each
        slot is updated only when the inbound option included
        the counter (per the §3.2.3 abbreviation rule, an omitted
        slot is None).

        Reference: RFC 9768 §3.2.1 (sender mirror state).
        Reference: RFC 9768 §3.2.3 (abbreviation rule slot omission).
        """

        if accecn0_counters[0] is not None:
            self.s_ect0_b = accecn0_counters[0]
        if accecn0_counters[1] is not None:
            self.s_ce_b = accecn0_counters[1]
        if accecn0_counters[2] is not None:
            self.s_ect1_b = accecn0_counters[2]

    def next_ace_field(self) -> int:
        """
        Return the 3-bit ACE field value to encode into AE+CWR+ECE
        on the next outbound non-SYN segment. Consumes
        handshake_ack_pending if set (the §3.2.2.1 Table-3 form on
        the active-open client's third-leg ACK); otherwise returns
        'r_cep & 0b111' (the §3.2.2.1 regular form).

        Reference: RFC 9768 §3.2.2.1 (ACE encoding regular + handshake forms).
        """

        if self.handshake_ack_pending is not None:
            ace = self.handshake_ack_pending
            self.handshake_ack_pending = None
            return ace
        return self.r_cep & 0b111

    def next_emit_counters(
        self,
    ) -> tuple[
        tuple[int | None, int | None, int | None] | None,
        tuple[int | None, int | None, int | None] | None,
    ]:
        """
        Compute the (accecn0_counters, accecn1_counters) tuple to
        attach to the next outbound non-SYN segment, then advance
        the last-emit trackers. Caller is responsible for the
        wire-eligibility gate (non-SYN, non-RST, AccECN-enabled);
        this method always emits a counter tuple.

        Order choice between AccECN0 (Kind 172, ECT(0) first)
        and AccECN1 (Kind 174, ECT(1) first) per §3.2.3 'whichever
        order is more efficient': pick AccECN1 when r.ECT(1)
        advanced since the last emission and r.ECT(0) did not
        (the L4S-style workload pattern — putting the changed
        counter first minimises bytes under the abbreviation
        rule). Otherwise pick AccECN0.

        Length choice per §3.2.3 / §3.2.3.3 abbreviation rule:
        include any counter that changed since the last emission;
        once included, the ordering rule forces all preceding
        (less-trailing) counters in the natural wire order to
        also be included. Lengths 11/8/5/2 correspond to including
        3/2/1/0 counters respectively.

        Returns exactly one populated tuple and one None — never
        both populated, never both None.

        Reference: RFC 9768 §3.2.3 (option emission + ordering).
        Reference: RFC 9768 §3.2.3.3 (abbreviation rule / wire lengths).
        """

        e0b_changed = self.r_ect0_b != self.r_last_emit_e0b
        ceb_changed = self.r_ce_b != self.r_last_emit_ceb
        e1b_changed = self.r_ect1_b != self.r_last_emit_e1b
        accecn0_counters: tuple[int | None, int | None, int | None] | None = None
        accecn1_counters: tuple[int | None, int | None, int | None] | None = None
        if e1b_changed and not e0b_changed:
            # AccECN1 (wire order: e1b, ceb, e0b).
            if e0b_changed:
                # Length 11: all three on wire.
                accecn1_counters = (self.r_ect0_b, self.r_ce_b, self.r_ect1_b)
            elif ceb_changed:
                # Length 8: drop trailing e0b.
                accecn1_counters = (None, self.r_ce_b, self.r_ect1_b)
            else:
                # Length 5: only e1b on wire (the gating outer
                # condition guarantees e1b_changed=True).
                accecn1_counters = (None, None, self.r_ect1_b)
        else:
            # AccECN0 (wire order: e0b, ceb, e1b).
            if e1b_changed:
                # Length 11: all three on wire.
                accecn0_counters = (self.r_ect0_b, self.r_ce_b, self.r_ect1_b)
            elif ceb_changed:
                # Length 8: drop trailing e1b.
                accecn0_counters = (self.r_ect0_b, self.r_ce_b, None)
            elif e0b_changed:
                # Length 5: only e0b on wire.
                accecn0_counters = (self.r_ect0_b, None, None)
            else:
                # Length 2: empty option (no counters changed
                # since last emission).
                accecn0_counters = (None, None, None)
        self.r_last_emit_e0b = self.r_ect0_b
        self.r_last_emit_ceb = self.r_ce_b
        self.r_last_emit_e1b = self.r_ect1_b
        return accecn0_counters, accecn1_counters

    def apparent_ce_delta(self, incoming_ace: int) -> int:
        """
        Compute the §3.2.2.5 ACE-based fallback CE-delta for an
        inbound non-SYN ACK that arrived without an AccECN option
        (e.g. a middlebox stripped it). Returns the apparent
        increment in r.cep since the last seen ACE, then advances
        s.cep by that delta so subsequent ACKs reporting the same
        ACE are idempotent. Caller decides whether a positive
        delta drives the CC-side congestion response.

        The §3.2.2.5.2 safest-likely-case wrap correction is
        omitted — for typical Internet workloads the AccECN
        option is rarely stripped, so the apparent delta is
        almost always the true delta; the simpler 3-bit-modular
        subtraction captures the common case without the
        over-aggressive wrap-correction risk.

        Reference: RFC 9768 §3.2.2.5 (ACE-based fallback).
        """

        apparent_delta = (incoming_ace - (self.s_cep & 0b111)) & 0b111
        self.s_cep = (self.s_cep + apparent_delta) & ACCECN__COUNTER_MASK
        return apparent_delta
