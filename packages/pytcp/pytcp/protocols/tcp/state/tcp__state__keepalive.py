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
This module contains the per-session keep-alive state container,
covering RFC 9293 §3.8.4 / RFC 1122 §4.2.3.6 (TCP keep-alive).

Holds the bilateral 'enabled' flag, the lazy-arm 'active' flag,
the probe-counter, and the three setsockopt-equivalent override
knobs (idle / interval / max_count). Helper accessors return
the override-or-default for each tunable so the timer arming
sites stay one-liner.

pytcp/protocols/tcp/state/tcp__state__keepalive.py

ver 3.0.8
"""

from dataclasses import dataclass


@dataclass(slots=True)
class KeepaliveState:
    """
    Per-session keep-alive state. Owned by 'TcpSession'; mutated
    by the session's keep-alive arm/tick paths and by the socket-
    layer setsockopt knobs.
    """

    # RFC 9293 §3.8.4 bilateral keep-alive opt-in. False by
    # default (RFC 9293's RECOMMENDED stance: do not initiate
    # keep-alive without an explicit application request);
    # flipped True via the socket-layer setsockopt knob.
    enabled: bool = False

    # RFC 1122 §4.2.3.6 unanswered-probe counter. Reset to 0 on
    # every observation of peer activity (any inbound segment,
    # any outbound segment we send) and on the lazy arm. Tear
    # down the connection when this reaches the §4.2.3.6
    # max-probes ceiling without an answering ACK.
    probes_unacked: int = 0

    # Per-session setsockopt overrides for the three keep-alive
    # tunables. None means "use the canonical KEEPALIVE_* default
    # from tcp__constants". Set by the socket-layer setsockopt
    # path; consumed by the timer arm/tick paths via the helper
    # accessors below.
    idle_override: int | None = None
    interval_override: int | None = None
    max_count_override: int | None = None

    # Lazy-arm gate. False on a fresh session and on transitions
    # out of synchronized state; flipped True by the first
    # arm_idle() so the per-tick service knows whether keep-alive
    # idling has begun (an orthogonal concern from whether the
    # 'keepalive' logical timer is currently armed/expired).
    active: bool = False

    def reset_for_idle(self) -> None:
        """
        Clear the unanswered-probe counter and flip 'active' True
        on a fresh idle-window arm. Called from 'arm_idle' on the
        session whenever peer activity is observed; also called
        from the lazy-arm branch of '_keepalive_tick' when
        'enabled' was flipped True after handshake completion.

        Reference: RFC 1122 §4.2.3.6 (idle-window reset on activity).
        """

        self.probes_unacked = 0
        self.active = True

    def idle_timeout(self, *, default: int) -> int:
        """
        Return the idle-window timeout in milliseconds: the
        per-session override if set, else the supplied canonical
        default (TCP__KEEPALIVE__IDLE_TIME_MS from tcp__constants).

        Reference: RFC 1122 §4.2.3.6 (idle-window default).
        """

        return self.idle_override if self.idle_override is not None else default

    def interval_timeout(self, *, default: int) -> int:
        """
        Return the inter-probe interval timeout in milliseconds:
        the per-session override if set, else the supplied
        canonical default (TCP__KEEPALIVE__PROBE_INTERVAL_MS).

        Reference: RFC 1122 §4.2.3.6 (probe interval default).
        """

        return self.interval_override if self.interval_override is not None else default

    def max_probes(self, *, default: int) -> int:
        """
        Return the unanswered-probe ceiling: the per-session
        override if set, else the supplied canonical default
        (TCP__KEEPALIVE__PROBE_MAX_COUNT).

        Reference: RFC 1122 §4.2.3.6 (probe-count ceiling).
        """

        return self.max_count_override if self.max_count_override is not None else default
