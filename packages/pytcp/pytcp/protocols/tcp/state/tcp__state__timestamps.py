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
This module contains the per-session RFC 7323 Timestamps state
container. Holds the bilateral 'send_ts' active flag plus the
'ts_recent' tracker (peer's most-recent valid TSval) and its
last-update timestamp.

pytcp/protocols/tcp/state/tcp__state__timestamps.py

ver 3.0.8
"""

from dataclasses import dataclass


@dataclass(slots=True)
class TimestampsState:
    """
    Per-session RFC 7323 Timestamps state. Owned by 'TcpSession';
    'send_ts' is set at handshake completion; 'ts_recent' +
    'ts_recent_updated_at_ms' are updated by the §4.3 PAWS path
    on every accepted in-window segment.
    """

    # RFC 7323 §2.2 bilateral-success flag for the Timestamps
    # option. Set True post-handshake when both sides advertised
    # TSopt; False otherwise. While True, every outbound segment
    # carries TSval = now_ms and TSecr = ts_recent; inbound
    # segments are PAWS-checked (§5.4) against ts_recent.
    send_ts: bool = False

    # RFC 7323 §4.3 'TS.Recent' tracker — peer's most-recent
    # valid TSval, updated on every accepted in-window segment
    # (segments that pass §5.2 / §5.3 acceptability AND §5.4
    # PAWS). The next outbound segment's TSecr field carries
    # this value back to peer.
    ts_recent: int = 0

    # RFC 7323 §4.3 staleness clock: 'now_ms' at the moment of
    # the most recent ts_recent update. Used for the §5.4
    # 24-day staleness check that bypasses PAWS when ts_recent
    # itself has gone stale (the §5.4 'safe to accept old
    # TSvals after 24 days of silence' clause).
    ts_recent_updated_at_ms: int = 0

    def update(self, *, tsval: int, now_ms: int) -> None:
        """
        Record a fresh TS.Recent value and refresh its staleness
        clock. Called from the §4.3 PAWS path in
        '_check_paws_and_update_ts_recent' on every accepted
        in-window segment whose TSval is at-or-after the
        current ts_recent.

        Reference: RFC 7323 §4.3 (TS.Recent update rule).
        """

        self.ts_recent = tsval
        self.ts_recent_updated_at_ms = now_ms
