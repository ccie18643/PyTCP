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
This module contains the per-session congestion-control state
container, decomposed out of 'TcpSession' so the CC variables and
their snapshot/restore operations live as one coherent object.

The fields cover RFC 5681 (cwnd / ssthresh / snd_ewn), RFC 6582 +
RFC 6675 (recovery markers), RFC 6937 (PRR per-recovery counters),
RFC 5682 (F-RTO snapshot), RFC 9438 §4.9 (CUBIC F-RTO + spurious-
fast-retransmit snapshots), RFC 9438 §4 (CUBIC curve state), and
RFC 9406 (HyStart++ — the existing 'HyStartState' is referenced
here so all CC state is reachable from one place).

Snapshot/restore patterns ('save_frto_snapshot',
'restore_frto_snapshot', 'save_fr_cubic_snapshot',
'restore_fr_cubic_snapshot', 'clear_fr_cubic_snapshot') are methods
on the dataclass so the call-site code in 'TcpSession' becomes a
single named operation rather than a 7-line block of attribute
shuffles.

Mutability mirrors 'HyStartState' in 'tcp__hystart.py': '@dataclass(
slots=True)' rather than 'frozen=True' because CC state evolves on
every cum-ACK and every RTO. The frozen-protocol-header convention
from 'net_proto.md' §2 applies to wire-format dataclasses,
not session state.

pytcp/protocols/tcp/state/tcp__state__cc.py

ver 3.0.9
"""

from dataclasses import dataclass, field

from pytcp.protocols.tcp.tcp__enums import CcMode
from pytcp.protocols.tcp.tcp__hystart import HyStartState
from pytcp.protocols.tcp.tcp__seq import Seq32

# RFC 5681 §3.1: "ssthresh SHOULD be set arbitrarily high (e.g., to
# the size of the largest possible advertised window)". 'INT32_MAX'
# (0x7FFF_FFFF) is the canonical large-constant choice (mirrors
# Linux's 'int_max'); it is well above any realistic peer-advertised
# window so the session enters slow-start cleanly post-handshake.
CC_STATE__SSTHRESH_INF: int = 0x7FFF_FFFF


@dataclass(slots=True)
class CcState:
    """
    Per-session congestion-control variables and their snapshot /
    restore operations. Owned by 'TcpSession'; mutated in place by
    the session's CC hooks ('_process_ack_packet',
    '_retransmit_packet_timeout', '_retransmit_packet_request',
    '_hystart_check_phase_transition').
    """

    # RFC 5681 cwnd / ssthresh and PyTCP's effective send window.
    # 'snd_ewn' is the simplified pacing variable that conflates
    # cwnd and the receiver-imposed flow-control ceiling.
    cwnd: int = 0
    ssthresh: int = CC_STATE__SSTHRESH_INF
    snd_ewn: int = 0

    # RFC 6675 §5 RecoveryPoint - the SND.MAX value at the moment
    # the most recent fast-retransmit fired. Zero means "not in
    # recovery"; non-zero gates further fast-retransmit triggers.
    recovery_point: Seq32 = 0

    # RFC 6582 §3.2 step 4 'recover' - the highest SND.MAX recorded
    # at the most recent RTO boundary. The fast-retransmit entry
    # gate refuses to enter recovery while 'SND.UNA <= recover_seq'
    # so post-RTO dup-ACKs cannot spuriously re-trigger FR before
    # the cum-ACK has progressed past the marker.
    recover_seq: Seq32 = 0

    # RFC 6937 PRR per-recovery state. 'recover_fs' is FlightSize
    # at recovery entry; 'prr_delivered' / 'prr_out' are cumulative
    # bytes ACK'd-or-SACK'd / sent during the current recovery
    # episode. All three reset to zero on recovery exit.
    recover_fs: int = 0
    prr_delivered: int = 0
    prr_out: int = 0

    # RFC 5682 F-RTO state. 'frto_active' indicates the RTO-recovery
    # window is open. 'frto_step' tracks §2.1 step progress: 0 = not
    # active; 1 = post-RTO step 1 done, awaiting first ACK; 2 = step
    # 2b entered (partial first ACK), awaiting second ACK. The
    # pre-RTO cwnd / ssthresh / SND.MAX snapshot anchors the
    # restoration when the first/second ACK declares spurious.
    frto_active: bool = False
    frto_step: int = 0
    frto_pre_cwnd: int = 0
    frto_pre_ssthresh: int = 0
    frto_pre_snd_max: int = 0

    # RFC 9438 §4.9.1 CUBIC F-RTO snapshot. Captured alongside the
    # cwnd/ssthresh snapshot; restored alongside them when the first
    # post-RTO ACK covers the snapshotted SND.MAX (the spurious
    # signature). Without restoring these the cubic curve would stay
    # anchored at the artificially-reduced W_max.
    frto_pre_cubic_w_max: int = 0
    frto_pre_cubic_K_ms: int = 0
    frto_pre_cubic_epoch_start_ms: int = 0
    frto_pre_cubic_w_est: int = 0

    # RFC 9438 §4.9.2 spurious-fast-retransmit snapshot. When fast-
    # retransmit fires, snapshot the CUBIC + cwnd/ssthresh state so
    # a subsequent DSACK in the same recovery episode (proving the
    # retransmit was spurious) can roll the state back. Gated by
    # 'fr_cubic_snapshot_valid' so a DSACK outside a recovery
    # episode does not spuriously restore.
    fr_pre_cubic_w_max: int = 0
    fr_pre_cubic_K_ms: int = 0
    fr_pre_cubic_epoch_start_ms: int = 0
    fr_pre_cubic_w_est: int = 0
    fr_pre_cwnd: int = 0
    fr_pre_ssthresh: int = 0
    fr_cubic_snapshot_valid: bool = False

    # RFC 9438 CUBIC curve state. Active when 'cc_mode == CUBIC';
    # in 'RENO' mode all fields stay at their initial values and
    # the existing RFC 5681 cwnd helpers run unchanged.
    cc_mode: CcMode = CcMode.CUBIC
    cubic_w_max: int = 0
    cubic_w_last_max: int = 0
    cubic_K_ms: int = 0
    cubic_epoch_start_ms: int = 0
    cubic_w_est: int = 0
    cubic_in_ca: bool = False

    # RFC 9406 HyStart++ state. The dataclass owns the instance so
    # all CC-related state is reachable from one container; the
    # helper functions in 'tcp__hystart.py' update it in place.
    hystart_state: HyStartState = field(default_factory=HyStartState)

    def save_frto_snapshot(self, *, snd_max: int) -> None:
        """
        Snapshot pre-RTO cwnd / ssthresh / SND.MAX and the CUBIC
        curve state. Called from the F-RTO entry path in
        'TcpSession._retransmit_packet_timeout' immediately before
        the conventional RFC 5681 §3.1 ssthresh halving.

        Reference: RFC 5682 §2.1 step 1 (snapshot).
        Reference: RFC 9438 §4.9.1 (snapshot CUBIC state).
        """

        self.frto_active = True
        self.frto_step = 1
        self.frto_pre_cwnd = self.cwnd
        self.frto_pre_ssthresh = self.ssthresh
        self.frto_pre_snd_max = snd_max
        self.frto_pre_cubic_w_max = self.cubic_w_max
        self.frto_pre_cubic_K_ms = self.cubic_K_ms
        self.frto_pre_cubic_epoch_start_ms = self.cubic_epoch_start_ms
        self.frto_pre_cubic_w_est = self.cubic_w_est

    def restore_frto_snapshot(self, *, snd_wnd: int) -> None:
        """
        Restore the pre-RTO cwnd / ssthresh / CUBIC state on an
        F-RTO spurious-RTO declaration. Called from the spurious-
        detection branch in 'TcpSession._process_ack_packet' when
        either step 2 (single-ACK strong-spurious) or step 3b
        (second-ACK advancing) fires. 'snd_ewn' is recomputed as
        'min(cwnd, snd_wnd)' so the receiver-window clamp is
        re-applied after restoration.

        Reference: RFC 5682 §2.1 step 3b (declare spurious + restore).
        Reference: RFC 9438 §4.9.1 (restore CUBIC state).
        """

        self.cwnd = self.frto_pre_cwnd
        self.ssthresh = self.frto_pre_ssthresh
        self.snd_ewn = min(self.cwnd, snd_wnd)
        self.cubic_w_max = self.frto_pre_cubic_w_max
        self.cubic_K_ms = self.frto_pre_cubic_K_ms
        self.cubic_epoch_start_ms = self.frto_pre_cubic_epoch_start_ms
        self.cubic_w_est = self.frto_pre_cubic_w_est

    def save_fr_cubic_snapshot(self) -> None:
        """
        Snapshot pre-fast-retransmit cwnd / ssthresh and the CUBIC
        curve state. Called from the fast-retransmit entry path in
        'TcpSession._retransmit_packet_request' immediately before
        the multiplicative decrease + curve re-anchor. The snapshot
        is consumed by 'restore_fr_cubic_snapshot' on a same-episode
        DSACK observation.

        Reference: RFC 9438 §4.9.2 (snapshot for spurious-FR rollback).
        """

        self.fr_pre_cubic_w_max = self.cubic_w_max
        self.fr_pre_cubic_K_ms = self.cubic_K_ms
        self.fr_pre_cubic_epoch_start_ms = self.cubic_epoch_start_ms
        self.fr_pre_cubic_w_est = self.cubic_w_est
        self.fr_pre_cwnd = self.cwnd
        self.fr_pre_ssthresh = self.ssthresh
        self.fr_cubic_snapshot_valid = True

    def restore_fr_cubic_snapshot(self) -> None:
        """
        Restore the pre-fast-retransmit cwnd / ssthresh / CUBIC state
        on a DSACK observation that proves the fast retransmit was
        spurious. The snapshot-valid flag is cleared so a subsequent
        DSACK in the same recovery episode does not roll back twice.

        Reference: RFC 9438 §4.9.2 (rollback on spurious-FR DSACK).
        """

        self.cubic_w_max = self.fr_pre_cubic_w_max
        self.cubic_K_ms = self.fr_pre_cubic_K_ms
        self.cubic_epoch_start_ms = self.fr_pre_cubic_epoch_start_ms
        self.cubic_w_est = self.fr_pre_cubic_w_est
        self.cwnd = self.fr_pre_cwnd
        self.ssthresh = self.fr_pre_ssthresh
        self.fr_cubic_snapshot_valid = False

    def clear_fr_cubic_snapshot(self) -> None:
        """
        Invalidate the spurious-fast-retransmit snapshot without
        restoring it. Called on recovery exit so a DSACK arriving
        post-recovery does not roll back unrelated state.

        Reference: RFC 9438 §4.9.2 (snapshot scope is one episode).
        """

        self.fr_cubic_snapshot_valid = False
