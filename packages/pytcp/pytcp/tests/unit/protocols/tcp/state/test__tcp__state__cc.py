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
This module contains unit tests for the per-session congestion-
control state container in 'pytcp/protocols/tcp/state/tcp__state__cc.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__cc.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__cc import (
    CC_STATE__SSTHRESH_INF,
    CcState,
)
from pytcp.protocols.tcp.tcp__enums import CcMode
from pytcp.protocols.tcp.tcp__hystart import HyStartState


class TestCcState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'CcState'.
    """

    @override
    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._cc = CcState()

    def test__cc_state__cwnd_default_zero(self) -> None:
        """
        Ensure 'cwnd' defaults to 0 so 'TcpSession.__init__' must
        explicitly initialise it from 'snd_mss' before the session
        can transmit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._cc.cwnd,
            0,
            msg="CcState.cwnd must default to 0.",
        )

    def test__cc_state__ssthresh_default_inf(self) -> None:
        """
        Ensure 'ssthresh' defaults to the canonical large constant
        0x7FFF_FFFF so post-handshake the session enters slow-start
        cleanly (cwnd < ssthresh holds for any realistic peer
        window).

        Reference: RFC 5681 §3.1 (ssthresh SHOULD be set arbitrarily high).
        """

        self.assertEqual(
            self._cc.ssthresh,
            CC_STATE__SSTHRESH_INF,
            msg="CcState.ssthresh must default to INT32_MAX.",
        )
        self.assertEqual(
            CC_STATE__SSTHRESH_INF,
            0x7FFF_FFFF,
            msg="CC_STATE__SSTHRESH_INF must equal 0x7FFF_FFFF.",
        )

    def test__cc_state__snd_ewn_default_zero(self) -> None:
        """
        Ensure 'snd_ewn' defaults to 0 so 'TcpSession.__init__' must
        explicitly initialise it; mirrors the 'cwnd' default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._cc.snd_ewn,
            0,
            msg="CcState.snd_ewn must default to 0.",
        )

    def test__cc_state__recovery_markers_default_zero(self) -> None:
        """
        Ensure 'recovery_point' and 'recover_seq' default to 0 — the
        sentinel for "not currently in recovery" / "no RTO marker
        active". A fresh session must be able to enter fast recovery
        on the first dup-ACK burst without an artificial barrier.

        Reference: RFC 6675 §5 (RecoveryPoint sentinel).
        Reference: RFC 6582 §3.2 (NewReno recover sentinel).
        """

        self.assertEqual(
            self._cc.recovery_point,
            0,
            msg="recovery_point must default to 0 (not in recovery).",
        )
        self.assertEqual(
            self._cc.recover_seq,
            0,
            msg="recover_seq must default to 0 (no RTO marker).",
        )

    def test__cc_state__prr_counters_default_zero(self) -> None:
        """
        Ensure 'recover_fs', 'prr_delivered', and 'prr_out' default
        to 0 so PRR pacing state is empty outside any recovery
        episode. The first loss event snapshots fresh values.

        Reference: RFC 6937 §3.1 (PRR per-recovery state).
        """

        self.assertEqual(
            self._cc.recover_fs,
            0,
            msg="recover_fs must default to 0.",
        )
        self.assertEqual(
            self._cc.prr_delivered,
            0,
            msg="prr_delivered must default to 0.",
        )
        self.assertEqual(
            self._cc.prr_out,
            0,
            msg="prr_out must default to 0.",
        )

    def test__cc_state__frto_state_default_inactive(self) -> None:
        """
        Ensure F-RTO state defaults represent "no RTO recovery in
        progress": 'frto_active' False, 'frto_step' 0, all snapshot
        fields zero.

        Reference: RFC 5682 §2.1 (F-RTO step tracker).
        """

        self.assertFalse(
            self._cc.frto_active,
            msg="frto_active must default to False.",
        )
        self.assertEqual(
            self._cc.frto_step,
            0,
            msg="frto_step must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_cwnd,
            0,
            msg="frto_pre_cwnd must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_ssthresh,
            0,
            msg="frto_pre_ssthresh must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_snd_max,
            0,
            msg="frto_pre_snd_max must default to 0.",
        )

    def test__cc_state__frto_cubic_snapshot_default_zero(self) -> None:
        """
        Ensure the CUBIC-specific F-RTO snapshot fields default to
        zero so a spurious-RTO declaration on a never-entered-CUBIC-
        CA session restores zeros (no-op for the cubic curve).

        Reference: RFC 9438 §4.9.1 (CUBIC F-RTO snapshot).
        """

        self.assertEqual(
            self._cc.frto_pre_cubic_w_max,
            0,
            msg="frto_pre_cubic_w_max must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_cubic_K_ms,
            0,
            msg="frto_pre_cubic_K_ms must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_cubic_epoch_start_ms,
            0,
            msg="frto_pre_cubic_epoch_start_ms must default to 0.",
        )
        self.assertEqual(
            self._cc.frto_pre_cubic_w_est,
            0,
            msg="frto_pre_cubic_w_est must default to 0.",
        )

    def test__cc_state__fr_cubic_snapshot_default_invalid(self) -> None:
        """
        Ensure 'fr_cubic_snapshot_valid' defaults to False so a
        DSACK arriving on a session that never entered fast
        recovery does not roll back uninitialised snapshot values.

        Reference: RFC 9438 §4.9.2 (gate restoration on snapshot validity).
        """

        self.assertFalse(
            self._cc.fr_cubic_snapshot_valid,
            msg="fr_cubic_snapshot_valid must default to False.",
        )
        self.assertEqual(
            self._cc.fr_pre_cubic_w_max,
            0,
            msg="fr_pre_cubic_w_max must default to 0.",
        )
        self.assertEqual(
            self._cc.fr_pre_cwnd,
            0,
            msg="fr_pre_cwnd must default to 0.",
        )
        self.assertEqual(
            self._cc.fr_pre_ssthresh,
            0,
            msg="fr_pre_ssthresh must default to 0.",
        )

    def test__cc_state__cc_mode_default_cubic(self) -> None:
        """
        Ensure 'cc_mode' defaults to CUBIC, mirroring Linux's
        default since kernel 2.6.18. RENO is selectable per
        connection via setsockopt.

        Reference: RFC 9438 (CUBIC default).
        """

        self.assertIs(
            self._cc.cc_mode,
            CcMode.CUBIC,
            msg="cc_mode must default to CcMode.CUBIC.",
        )

    def test__cc_state__cubic_curve_default_zero(self) -> None:
        """
        Ensure CUBIC curve state defaults to the all-zero
        pre-loss-event values. 'cubic_in_ca' False keeps the
        session on the slow-start path until the first cwnd >=
        ssthresh crossing or first loss event.

        Reference: RFC 9438 §4 (CUBIC curve state).
        """

        self.assertEqual(
            self._cc.cubic_w_max,
            0,
            msg="cubic_w_max must default to 0.",
        )
        self.assertEqual(
            self._cc.cubic_w_last_max,
            0,
            msg="cubic_w_last_max must default to 0.",
        )
        self.assertEqual(
            self._cc.cubic_K_ms,
            0,
            msg="cubic_K_ms must default to 0.",
        )
        self.assertEqual(
            self._cc.cubic_epoch_start_ms,
            0,
            msg="cubic_epoch_start_ms must default to 0.",
        )
        self.assertEqual(
            self._cc.cubic_w_est,
            0,
            msg="cubic_w_est must default to 0.",
        )
        self.assertFalse(
            self._cc.cubic_in_ca,
            msg="cubic_in_ca must default to False.",
        )

    def test__cc_state__hystart_state_is_fresh_instance(self) -> None:
        """
        Ensure 'hystart_state' defaults to a fresh 'HyStartState'
        instance via 'default_factory'. Two separate
        'CcState' instances must own independent
        'HyStartState' objects so per-session HyStart++ progress
        does not bleed across sessions.

        Reference: RFC 9406 §4.2 (per-connection HyStart++ state).
        """

        cc_a = CcState()
        cc_b = CcState()

        self.assertIsInstance(
            cc_a.hystart_state,
            HyStartState,
            msg="hystart_state must be a HyStartState instance.",
        )
        self.assertIsNot(
            cc_a.hystart_state,
            cc_b.hystart_state,
            msg="Distinct CC-state instances must own distinct HyStartState instances.",
        )


class TestCcState__FrtoSnapshot(TestCase):
    """
    Save / restore lifecycle of the F-RTO snapshot.
    """

    def test__cc_state__save_frto_snapshot_captures_all_fields(self) -> None:
        """
        Ensure 'save_frto_snapshot' captures the full pre-RTO
        cwnd / ssthresh / SND.MAX plus the CUBIC curve state, sets
        'frto_active' True, and sets 'frto_step' to 1 so a
        subsequent ACK is interpreted as the first-post-RTO ACK.

        Reference: RFC 5682 §2.1 step 1 (snapshot).
        Reference: RFC 9438 §4.9.1 (snapshot CUBIC state).
        """

        cc = CcState()
        cc.cwnd = 8000
        cc.ssthresh = 12000
        cc.cubic_w_max = 16000
        cc.cubic_K_ms = 25
        cc.cubic_epoch_start_ms = 1000
        cc.cubic_w_est = 9000

        cc.save_frto_snapshot(snd_max=0xDEAD_BEEF)

        self.assertTrue(
            cc.frto_active,
            msg="save_frto_snapshot must set frto_active True.",
        )
        self.assertEqual(
            cc.frto_step,
            1,
            msg="save_frto_snapshot must set frto_step to 1.",
        )
        self.assertEqual(
            cc.frto_pre_cwnd,
            8000,
            msg="save_frto_snapshot must capture cwnd.",
        )
        self.assertEqual(
            cc.frto_pre_ssthresh,
            12000,
            msg="save_frto_snapshot must capture ssthresh.",
        )
        self.assertEqual(
            cc.frto_pre_snd_max,
            0xDEAD_BEEF,
            msg="save_frto_snapshot must capture snd_max from kwarg.",
        )
        self.assertEqual(
            cc.frto_pre_cubic_w_max,
            16000,
            msg="save_frto_snapshot must capture cubic_w_max.",
        )
        self.assertEqual(
            cc.frto_pre_cubic_K_ms,
            25,
            msg="save_frto_snapshot must capture cubic_K_ms.",
        )
        self.assertEqual(
            cc.frto_pre_cubic_epoch_start_ms,
            1000,
            msg="save_frto_snapshot must capture cubic_epoch_start_ms.",
        )
        self.assertEqual(
            cc.frto_pre_cubic_w_est,
            9000,
            msg="save_frto_snapshot must capture cubic_w_est.",
        )

    def test__cc_state__restore_frto_snapshot_clamped_by_snd_wnd(self) -> None:
        """
        Ensure 'restore_frto_snapshot' restores cwnd / ssthresh /
        CUBIC fields and recomputes 'snd_ewn' as 'min(cwnd,
        snd_wnd)' so the receiver-window flow-control ceiling is
        re-applied after restoration. When 'snd_wnd' is the
        smaller of the two, 'snd_ewn' takes the snd_wnd value.

        Reference: RFC 5682 §2.1 step 3b (declare spurious + restore).
        Reference: RFC 9438 §4.9.1 (restore CUBIC state).
        """

        cc = CcState()
        cc.frto_pre_cwnd = 20000
        cc.frto_pre_ssthresh = 30000
        cc.frto_pre_cubic_w_max = 40000
        cc.frto_pre_cubic_K_ms = 50
        cc.frto_pre_cubic_epoch_start_ms = 2000
        cc.frto_pre_cubic_w_est = 25000

        cc.restore_frto_snapshot(snd_wnd=15000)

        self.assertEqual(
            cc.cwnd,
            20000,
            msg="restore_frto_snapshot must restore cwnd from snapshot.",
        )
        self.assertEqual(
            cc.ssthresh,
            30000,
            msg="restore_frto_snapshot must restore ssthresh from snapshot.",
        )
        self.assertEqual(
            cc.snd_ewn,
            15000,
            msg="restore_frto_snapshot must clamp snd_ewn to snd_wnd when smaller.",
        )
        self.assertEqual(
            cc.cubic_w_max,
            40000,
            msg="restore_frto_snapshot must restore cubic_w_max.",
        )
        self.assertEqual(
            cc.cubic_K_ms,
            50,
            msg="restore_frto_snapshot must restore cubic_K_ms.",
        )
        self.assertEqual(
            cc.cubic_epoch_start_ms,
            2000,
            msg="restore_frto_snapshot must restore cubic_epoch_start_ms.",
        )
        self.assertEqual(
            cc.cubic_w_est,
            25000,
            msg="restore_frto_snapshot must restore cubic_w_est.",
        )

    def test__cc_state__restore_frto_snapshot_clamped_by_cwnd(self) -> None:
        """
        Ensure 'restore_frto_snapshot' takes the cwnd value for
        'snd_ewn' when cwnd is the smaller of (cwnd, snd_wnd) so a
        large peer-advertised window does not let the session emit
        beyond the restored cwnd.

        Reference: RFC 5681 §2 (cwnd as send-rate ceiling).
        """

        cc = CcState()
        cc.frto_pre_cwnd = 8000
        cc.frto_pre_ssthresh = 16000

        cc.restore_frto_snapshot(snd_wnd=64000)

        self.assertEqual(
            cc.snd_ewn,
            8000,
            msg="restore_frto_snapshot must clamp snd_ewn to cwnd when smaller.",
        )


class TestCcState__FrCubicSnapshot(TestCase):
    """
    Save / restore / clear lifecycle of the spurious-fast-retransmit
    CUBIC snapshot.
    """

    def test__cc_state__save_fr_cubic_snapshot_captures_and_validates(self) -> None:
        """
        Ensure 'save_fr_cubic_snapshot' captures the pre-FR cwnd /
        ssthresh / CUBIC state and sets 'fr_cubic_snapshot_valid'
        True so a subsequent same-episode DSACK is honoured.

        Reference: RFC 9438 §4.9.2 (snapshot for spurious-FR rollback).
        """

        cc = CcState()
        cc.cwnd = 12000
        cc.ssthresh = 24000
        cc.cubic_w_max = 30000
        cc.cubic_K_ms = 40
        cc.cubic_epoch_start_ms = 500
        cc.cubic_w_est = 11000

        cc.save_fr_cubic_snapshot()

        self.assertTrue(
            cc.fr_cubic_snapshot_valid,
            msg="save_fr_cubic_snapshot must set fr_cubic_snapshot_valid True.",
        )
        self.assertEqual(
            cc.fr_pre_cwnd,
            12000,
            msg="save_fr_cubic_snapshot must capture cwnd.",
        )
        self.assertEqual(
            cc.fr_pre_ssthresh,
            24000,
            msg="save_fr_cubic_snapshot must capture ssthresh.",
        )
        self.assertEqual(
            cc.fr_pre_cubic_w_max,
            30000,
            msg="save_fr_cubic_snapshot must capture cubic_w_max.",
        )
        self.assertEqual(
            cc.fr_pre_cubic_K_ms,
            40,
            msg="save_fr_cubic_snapshot must capture cubic_K_ms.",
        )
        self.assertEqual(
            cc.fr_pre_cubic_epoch_start_ms,
            500,
            msg="save_fr_cubic_snapshot must capture cubic_epoch_start_ms.",
        )
        self.assertEqual(
            cc.fr_pre_cubic_w_est,
            11000,
            msg="save_fr_cubic_snapshot must capture cubic_w_est.",
        )

    def test__cc_state__restore_fr_cubic_snapshot_rolls_back_and_invalidates(self) -> None:
        """
        Ensure 'restore_fr_cubic_snapshot' restores cwnd / ssthresh
        / CUBIC fields from the snapshot and clears
        'fr_cubic_snapshot_valid' so a second same-episode DSACK
        does not roll back twice.

        Reference: RFC 9438 §4.9.2 (rollback on spurious-FR DSACK).
        """

        cc = CcState()
        cc.fr_pre_cwnd = 10000
        cc.fr_pre_ssthresh = 20000
        cc.fr_pre_cubic_w_max = 25000
        cc.fr_pre_cubic_K_ms = 30
        cc.fr_pre_cubic_epoch_start_ms = 750
        cc.fr_pre_cubic_w_est = 9500
        cc.fr_cubic_snapshot_valid = True
        cc.cwnd = 5000
        cc.ssthresh = 10000
        cc.cubic_w_max = 15000

        cc.restore_fr_cubic_snapshot()

        self.assertEqual(
            cc.cwnd,
            10000,
            msg="restore_fr_cubic_snapshot must restore cwnd.",
        )
        self.assertEqual(
            cc.ssthresh,
            20000,
            msg="restore_fr_cubic_snapshot must restore ssthresh.",
        )
        self.assertEqual(
            cc.cubic_w_max,
            25000,
            msg="restore_fr_cubic_snapshot must restore cubic_w_max.",
        )
        self.assertEqual(
            cc.cubic_K_ms,
            30,
            msg="restore_fr_cubic_snapshot must restore cubic_K_ms.",
        )
        self.assertEqual(
            cc.cubic_epoch_start_ms,
            750,
            msg="restore_fr_cubic_snapshot must restore cubic_epoch_start_ms.",
        )
        self.assertEqual(
            cc.cubic_w_est,
            9500,
            msg="restore_fr_cubic_snapshot must restore cubic_w_est.",
        )
        self.assertFalse(
            cc.fr_cubic_snapshot_valid,
            msg="restore_fr_cubic_snapshot must clear the validity flag.",
        )

    def test__cc_state__clear_fr_cubic_snapshot_invalidates_only(self) -> None:
        """
        Ensure 'clear_fr_cubic_snapshot' flips
        'fr_cubic_snapshot_valid' False but does NOT mutate the
        underlying snapshot fields. The clear is invoked on
        recovery exit; the snapshot bytes can stay since the gate
        flag is the only thing 'restore_fr_cubic_snapshot' checks.

        Reference: RFC 9438 §4.9.2 (snapshot scope is one episode).
        """

        cc = CcState()
        cc.fr_pre_cwnd = 7777
        cc.fr_pre_ssthresh = 8888
        cc.fr_cubic_snapshot_valid = True

        cc.clear_fr_cubic_snapshot()

        self.assertFalse(
            cc.fr_cubic_snapshot_valid,
            msg="clear_fr_cubic_snapshot must set the gate False.",
        )
        self.assertEqual(
            cc.fr_pre_cwnd,
            7777,
            msg="clear_fr_cubic_snapshot must not mutate fr_pre_cwnd.",
        )
        self.assertEqual(
            cc.fr_pre_ssthresh,
            8888,
            msg="clear_fr_cubic_snapshot must not mutate fr_pre_ssthresh.",
        )
