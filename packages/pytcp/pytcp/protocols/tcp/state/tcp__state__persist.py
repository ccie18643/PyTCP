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
This module contains the per-session zero-window-probe persist
state container, covering the RFC 9293 §3.8.6.1 persist timer's
'active' gate and back-off interval.

pytcp/protocols/tcp/state/tcp__state__persist.py

ver 3.0.9
"""

from dataclasses import dataclass


@dataclass(slots=True)
class PersistState:
    """
    Per-session persist-timer state. Owned by 'TcpSession';
    armed when peer reports a zero window with data pending in
    the TX buffer; cleared when peer reopens the window.
    """

    # RFC 9293 §3.8.6.1 'active' gate. True while a persist
    # timer is registered; the timer-tick path uses this to
    # distinguish "expired" from "never registered".
    active: bool = False

    # Current persist back-off interval (ms). Resets to the
    # initial RTO when the timer arms; doubles on each probe
    # firing up to TCP__PERSIST__TIMEOUT_MAX_MS (RFC 9293 §3.8.6.1
    # exponential back-off).
    timeout: int = 0

    def deactivate(self, *, initial_timeout: int) -> None:
        """
        Clear the active gate and reset the back-off interval to
        the supplied initial timeout. Called from
        '_phase5_consume_segment_and_postprocess' when peer's
        reported window reopens (snd_wnd > 0).

        Reference: RFC 9293 §3.8.6.1 (persist deactivation on reopen).
        """

        self.active = False
        self.timeout = initial_timeout
