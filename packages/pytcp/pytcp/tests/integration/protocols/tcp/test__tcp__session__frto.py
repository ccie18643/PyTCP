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
This module contains integration tests for RFC 5682 F-RTO
(Forward RTO-Recovery) in 'TcpSession'. F-RTO detects
"spurious" RTOs - where the timeout fires but the original
segments were actually delivered (the ACK was just delayed,
e.g. due to a brief latency spike). On detection, the
session restores the pre-RTO cwnd and ssthresh values, so a
single spurious RTO does not collapse the connection's
throughput. Without F-RTO, every spurious RTO reduces cwnd
to 1 MSS and halves ssthresh - on lossy networks (mobile
handoffs, satellite, wifi) this materially degrades
throughput.

PyTCP implements a SIMPLIFIED F-RTO: the first post-RTO ACK
that advances SND.UNA to the pre-RTO SND.MAX is treated as
the spurious signal, and pre-RTO cwnd/ssthresh are restored.
This handles the canonical spurious case (ACK was delayed,
all originals delivered) without the 2-segment probe step
in the strict RFC 5682 §3 algorithm. The probe step would
only help for the "in between" case where some originals
were delivered but not all - rare in practice.

pytcp/tests/integration/protocols/tcp/test__tcp__session__frto.py

ver 3.0.10
"""

from net_addr import Ip4Address  # noqa: F401
from pytcp.protocols.tcp.tcp__constants import TCP__RTO__INITIAL_MS
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised window + MSS.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpSession__Frto(TcpTestCase):
    """
    Integration tests for the RFC 5682 F-RTO spurious-RTO
    detection and recovery undo.
    """

    def test__frto__spurious_rto_restores_pre_rto_cwnd_and_ssthresh(self) -> None:
        """
        Ensure that when an RTO fires, the original segments
        are subsequently acknowledged in full (the canonical
        "ACK was just delayed" spurious-RTO scenario), the
        session restores the pre-RTO cwnd and ssthresh
        values. Without F-RTO, the connection collapses
        cwnd to 1 MSS and halves ssthresh on every spurious
        timeout, materially degrading throughput on lossy
        networks where brief latency spikes are common
        (mobile handoffs, wifi roaming, satellite jitter).

        Reference: RFC 5682 §3.1 (F-RTO spurious-RTO detection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Send 3 segments worth of data. PyTCP's transmit
        # loop fires one segment per ms tick, so advance
        # several ms to drain the send buffer before snapshot.
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=10)

        cwnd_before_rto = session._cc.cwnd
        ssthresh_before_rto = session._cc.ssthresh
        snd_max_at_rto = session._snd_seq.max

        # Don't ACK; advance past TCP__RTO__INITIAL_MS
        # so the RTO fires. After RTO, cwnd is collapsed to
        # 1 MSS and ssthresh is halved per RFC 5681 §3.1.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        self.assertNotEqual(
            session._cc.cwnd,
            cwnd_before_rto,
            msg=(
                "Setup precondition: RTO MUST collapse cwnd "
                "below the pre-RTO value before F-RTO can "
                f"restore it. Got cwnd={session._cc.cwnd}, "
                f"cwnd_before_rto={cwnd_before_rto}."
            ),
        )

        # Peer's cumulative ACK arrives covering ALL three
        # original segments. In the spurious-RTO scenario,
        # the originals were delivered but the ACK was just
        # delayed - now it covers seq up to the pre-RTO
        # SND.MAX, the canonical signal.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_max_at_rto,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cc.cwnd,
            cwnd_before_rto,
            msg=(
                "RFC 5682 §3.1: when the first post-RTO ACK "
                "covers all pre-RTO outstanding data, the RTO "
                "is spurious and cwnd MUST be restored to its "
                f"pre-RTO value. Got cwnd={session._cc.cwnd}, "
                f"expected {cwnd_before_rto}."
            ),
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before_rto,
            msg=(
                "RFC 5682 §3.1: spurious-RTO detection MUST "
                "restore ssthresh to the pre-RTO value. Got "
                f"ssthresh={session._cc.ssthresh}, expected "
                f"{ssthresh_before_rto}."
            ),
        )

    def test__frto__genuine_rto_keeps_cwnd_halved(self) -> None:
        """
        Ensure that when an RTO fires and the first post-RTO
        ACK covers ONLY the retransmitted segment (not the
        full pre-RTO outstanding data) - the canonical
        "genuine packet loss" scenario - the session does
        NOT restore pre-RTO cwnd / ssthresh. The RTO
        recovery cadence (cwnd=1 MSS slow-start, halved
        ssthresh) stays in effect because the partial-ACK
        signature confirms data really was lost.

        Reference: RFC 5682 §3.1 (F-RTO genuine-RTO regression guard).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Same 3-segment send so flight_size matches the
        # spurious test for symmetry.
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=10)

        cwnd_before_rto = session._cc.cwnd
        ssthresh_before_rto = session._cc.ssthresh

        # Don't ACK; trigger RTO.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        ssthresh_after_rto = session._cc.ssthresh

        # Peer's ACK covers only the FIRST segment (the
        # retransmit) - segments B and C were genuinely
        # lost. ack = LOCAL__ISS + 1 + PEER__MSS = end of A.
        peer_partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_partial_ack)

        self.assertLess(
            session._cc.cwnd,
            cwnd_before_rto,
            msg=(
                "RFC 5682 §3.1: when the first post-RTO ACK "
                "covers only the retransmit (not all pre-RTO "
                "data), the RTO was genuine and cwnd MUST "
                "NOT be restored to the pre-RTO value. "
                "Slow-start growth on the partial cum-ACK is "
                "expected, but cwnd should stay well below "
                f"the pre-RTO {cwnd_before_rto}. Got "
                f"cwnd={session._cc.cwnd}."
            ),
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_after_rto,
            msg=(
                "RFC 5682 §3.1: genuine-RTO recovery MUST "
                "leave ssthresh at its halved post-RTO value "
                "(F-RTO restoration MUST NOT fire). Got "
                f"ssthresh={session._cc.ssthresh}, expected "
                f"{ssthresh_after_rto} (which is < pre-RTO "
                f"{ssthresh_before_rto})."
            ),
        )

    def test__frto__spurious_rto_restores_cubic_state(self) -> None:
        """
        Ensure that when a spurious RTO is detected (the
        first post-RTO ACK covers all pre-RTO outstanding
        data), the CUBIC-specific state ('_cubic_w_max',
        '_cubic_K_ms', '_cubic_epoch_start_ms', '_cubic_w_est')
        is also restored to its pre-RTO snapshot, alongside
        the cwnd / ssthresh restore the §3.1 F-RTO machinery
        already performs. Without this, a spurious RTO would
        leave CUBIC's curve permanently anchored at the
        artificially-reduced W_max even after cwnd is
        restored, degrading post-recovery throughput.

        Reference: RFC 9438 §4.9.1 (CUBIC spurious-timeout state restore via F-RTO).
        """

        from pytcp.protocols.tcp.tcp__enums import CcMode

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Force CUBIC mode (default may be RENO depending on
        # the surrounding test fixture).
        session._cc.cc_mode = CcMode.CUBIC

        # Drive 3 segments and snapshot CUBIC state pre-RTO.
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=10)

        cwnd_before_rto = session._cc.cwnd
        snd_max_at_rto = session._snd_seq.max
        cubic_w_max_before = session._cc.cubic_w_max
        cubic_K_ms_before = session._cc.cubic_K_ms
        cubic_epoch_before = session._cc.cubic_epoch_start_ms
        cubic_w_est_before = session._cc.cubic_w_est

        # Trigger RTO without peer ACK.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        # Peer's cum-ACK covers all pre-RTO data: spurious
        # signature.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_max_at_rto,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # cwnd restored (already covered by the parent F-RTO
        # test) - assert here as a setup invariant.
        self.assertEqual(
            session._cc.cwnd,
            cwnd_before_rto,
            msg="Setup invariant: F-RTO restores cwnd on spurious detection.",
        )
        # CUBIC state restored too.
        self.assertEqual(
            session._cc.cubic_w_max,
            cubic_w_max_before,
            msg=(
                "RFC 9438 §4.9.1: spurious-timeout detection MUST "
                "restore _cubic_w_max to the pre-RTO snapshot. Got "
                f"{session._cc.cubic_w_max}, expected {cubic_w_max_before}."
            ),
        )
        self.assertEqual(
            session._cc.cubic_K_ms,
            cubic_K_ms_before,
            msg=(
                "RFC 9438 §4.9.1: spurious-timeout detection MUST "
                "restore _cubic_K_ms to the pre-RTO snapshot. Got "
                f"{session._cc.cubic_K_ms}, expected {cubic_K_ms_before}."
            ),
        )
        self.assertEqual(
            session._cc.cubic_epoch_start_ms,
            cubic_epoch_before,
            msg=(
                "RFC 9438 §4.9.1: spurious-timeout detection MUST "
                "restore _cubic_epoch_start_ms to the pre-RTO snapshot. "
                f"Got {session._cc.cubic_epoch_start_ms}, expected "
                f"{cubic_epoch_before}."
            ),
        )
        self.assertEqual(
            session._cc.cubic_w_est,
            cubic_w_est_before,
            msg=(
                "RFC 9438 §4.9.1: spurious-timeout detection MUST "
                "restore _cubic_w_est to the pre-RTO snapshot. Got "
                f"{session._cc.cubic_w_est}, expected {cubic_w_est_before}."
            ),
        )

    def test__frto__genuine_rto_keeps_cubic_state_reduced(self) -> None:
        """
        Ensure the regression-guard direction for §4.9.1: when
        a genuine RTO fires (first post-RTO ACK covers only
        the retransmit, not all pre-RTO data), the CUBIC
        state stays at its post-loss-event values - the
        snapshot MUST NOT be restored on a non-spurious RTO.

        Reference: RFC 9438 §4.9.1 (CUBIC restore only on detected spurious timeout).
        """

        from pytcp.protocols.tcp.tcp__enums import CcMode

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cc_mode = CcMode.CUBIC
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=10)

        snd_una_at_rto = session._snd_seq.una
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        # Snapshot post-RTO CUBIC state.
        cubic_w_max_after_rto = session._cc.cubic_w_max

        # Peer ACK covers ONLY the retransmit (snd_una + 1
        # MSS), not all pre-RTO data.
        peer_partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_una_at_rto + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_partial_ack)

        # CUBIC state MUST NOT be restored on a genuine RTO.
        self.assertEqual(
            session._cc.cubic_w_max,
            cubic_w_max_after_rto,
            msg=(
                "RFC 9438 §4.9.1: a genuine-RTO partial cum-ACK "
                "MUST NOT trigger CUBIC state restore. Got "
                f"_cubic_w_max={session._cc.cubic_w_max}, "
                f"expected {cubic_w_max_after_rto}."
            ),
        )


class TestTcpSession__FrtoStep2Step3(TcpTestCase):
    """
    RFC 5682 §2.1 step 2 / step 3 / already-in-RTO gate.
    Pins behaviours that go beyond PyTCP's prior one-step
    simplification (which only declared spurious when the
    FIRST post-RTO ACK covered all pre-RTO data):

    - Step 2 → step 3 path: a partial first cum-ACK (advances
      window but does NOT cover 'recover') sets the F-RTO
      step to 2 waiting for the second ACK.
    - Step 3 spurious declaration: if the second ACK advances
      the window further (acknowledges data that was NOT
      retransmitted post-RTO), declare spurious and restore
      pre-RTO state.
    - Already-in-RTO gate (step 1's "if already in F-RTO and
      recover >= SND.UNA, skip step 2"): a second RTO firing
      while the first F-RTO is still pending must not
      overwrite the original snapshot in a way that loses
      pre-RTO state.
    """

    def test__frto__step2_step3__partial_then_advancing_ack_declares_spurious(self) -> None:
        """
        Ensure that when the first post-RTO ACK partially
        advances the window (but does NOT cover the pre-RTO
        SND.MAX), F-RTO enters step 2 (waiting for second
        ACK) rather than clearing state. When the second ACK
        further advances the window, F-RTO declares the
        timeout spurious and pre-RTO cwnd / ssthresh are
        restored.

        Reference: RFC 5682 §2.1 step 2 (partial-ACK -> wait for second ACK).
        Reference: RFC 5682 §2.1 step 3b (second-ACK-advances declares spurious).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=10)

        cwnd_before_rto = session._cc.cwnd
        ssthresh_before_rto = session._cc.ssthresh
        snd_max_at_rto = session._snd_seq.max
        peer_iss_after_handshake = PEER__ISS + 1

        # Force RTO.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)
        assert session._cc.cwnd != cwnd_before_rto, "Setup precondition: cwnd must collapse on RTO."

        # First post-RTO ACK: partial — covers ONE segment past
        # SND.UNA, well below pre-RTO SND.MAX. RFC §2.1 step 2b:
        # this advances window but doesn't cover recover, so we
        # transmit up to two new segments and enter step 3.
        partial_ack_value = LOCAL__ISS + 1 + PEER__MSS  # one segment past SYN
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss_after_handshake,
            ack=partial_ack_value,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        # F-RTO must NOT be cleared yet — we're in step 2
        # waiting for the second ACK.
        self.assertNotEqual(
            session._cc.frto_step,
            0,
            msg=(
                "RFC 5682 §2.1 step 2: partial first post-RTO "
                "ACK MUST leave F-RTO in step 2 (waiting for "
                f"second ACK). Got _frto_step={session._cc.frto_step}."
            ),
        )
        self.assertNotEqual(
            session._cc.cwnd,
            cwnd_before_rto,
            msg=(
                "Setup invariant: pre-RTO cwnd MUST NOT be "
                "restored on partial first ACK (step 2 defers "
                f"restoration). Got cwnd={session._cc.cwnd}."
            ),
        )

        # Second post-RTO ACK: advances further to cover
        # snd_max_at_rto. Per §2.1 step 3b, this declares
        # spurious and restores pre-RTO state.
        advancing_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss_after_handshake,
            ack=snd_max_at_rto,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=advancing_ack)

        self.assertEqual(
            session._cc.cwnd,
            cwnd_before_rto,
            msg=(
                "RFC 5682 §2.1 step 3b: second post-RTO ACK "
                "advancing past pre-RTO SND.MAX MUST declare "
                "spurious and restore cwnd to pre-RTO value. "
                f"Got cwnd={session._cc.cwnd}, expected "
                f"{cwnd_before_rto}."
            ),
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before_rto,
            msg=(
                "RFC 5682 §2.1 step 3b: second-ACK spurious "
                f"detection MUST restore ssthresh. Got "
                f"{session._cc.ssthresh}, expected {ssthresh_before_rto}."
            ),
        )
        self.assertEqual(
            session._cc.frto_step,
            0,
            msg=("F-RTO MUST clear after spurious declaration. " f"Got _frto_step={session._cc.frto_step}."),
        )

    def test__frto__already_in_rto_gate__second_rto_skips_step2(self) -> None:
        """
        Ensure that when an RTO fires while F-RTO is already
        active and 'recover' (= the first RTO's snapshotted
        SND.MAX) is at-or-below SND.UNA — the marker the
        first F-RTO was waiting on has been surpassed —
        the second RTO MUST NOT enter step 2 again. Per §2.1
        step 1's already-in-RTO gate, this prevents the F-RTO
        algorithm from looping during sustained loss.

        The session-level expectation: the second RTO updates
        the recover marker to the new SND.MAX but does not
        re-snapshot pre-RTO cwnd / ssthresh.

        Reference: RFC 5682 §2.1 step 1 (already-in-RTO gate).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        payload = b"A" * PEER__MSS * 3
        session.send(data=payload)
        self._advance(ms=10)

        first_pre_rto_cwnd = session._cc.cwnd

        # First RTO: snapshot taken.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)
        first_pre_cwnd = session._cc.frto_pre_cwnd
        first_pre_ssthresh = session._cc.frto_pre_ssthresh

        self.assertEqual(
            first_pre_cwnd,
            first_pre_rto_cwnd,
            msg="Setup precondition: first F-RTO snapshot captures pre-RTO cwnd.",
        )
        self.assertNotEqual(
            session._cc.frto_step,
            0,
            msg="Setup precondition: F-RTO step != 0 after first RTO.",
        )

        # Second RTO without intervening ACK. PyTCP's retransmit
        # back-off doubles RTO; advance enough to fire it.
        self._advance(ms=session._rto_state.rto_ms + 100)

        # The already-in-RTO gate condition: recover (=
        # first_pre_snd_max) >= SND.UNA. SND.UNA hasn't moved
        # since first RTO (peer never ACKed), so recover ==
        # SND.UNA + flight, which is >= SND.UNA. Gate fires.
        # Expected behaviour:
        #   - _frto_pre_cwnd / _frto_pre_ssthresh stay at the
        #     ORIGINAL pre-first-RTO values (NOT overwritten
        #     with the post-first-RTO collapsed values which
        #     would lose pre-RTO knowledge entirely).
        self.assertEqual(
            session._cc.frto_pre_cwnd,
            first_pre_cwnd,
            msg=(
                "RFC 5682 §2.1 step 1 already-in-RTO gate: "
                "second RTO MUST NOT overwrite the original "
                "pre-RTO cwnd snapshot. Got "
                f"_frto_pre_cwnd={session._cc.frto_pre_cwnd}, "
                f"expected {first_pre_cwnd} (pre-first-RTO)."
            ),
        )
        self.assertEqual(
            session._cc.frto_pre_ssthresh,
            first_pre_ssthresh,
            msg=(
                "RFC 5682 §2.1 step 1 already-in-RTO gate: "
                "second RTO MUST NOT overwrite the original "
                f"pre-RTO ssthresh snapshot. Got "
                f"_frto_pre_ssthresh={session._cc.frto_pre_ssthresh}, "
                f"expected {first_pre_ssthresh}."
            ),
        )
