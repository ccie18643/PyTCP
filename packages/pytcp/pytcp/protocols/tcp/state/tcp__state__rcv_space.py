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
This module contains the per-session receive-buffer Dynamic Right-Sizing
(DRS) measurement state — the Tier-3 Track R analogue of Linux's
'tcp_sock.rcvq_space'. It records the high-water-mark of bytes the
application copied out in one receiver-RTT ('space') plus the anchor the
next measurement is taken from ('copied_anchor' / 'time_ms'), so the
grow policy can compare the current per-RTT throughput against the last.

pytcp/protocols/tcp/state/tcp__state__rcv_space.py

ver 3.0.8
"""

from dataclasses import dataclass


@dataclass(slots=True)
class RcvSpaceState:
    """
    Per-session DRS measurement window. Owned by 'TcpSession' and
    touched only on the application thread (inside 'receive()'), so it
    needs no lock. 'space' is seeded from the initial 'rcv_wnd_max' so
    the first grow fires only once per-RTT throughput exceeds the
    starting window.
    """

    # High-water-mark of bytes copied to the application in a single
    # receiver-RTT. The grow policy fires when the latest per-RTT
    # 'copied' exceeds this; then 'space' rises to that 'copied'.
    space: int = 0

    # Value of the session's cumulative copied-bytes counter at the
    # last measurement — 'copied = total - copied_anchor' is the bytes
    # drained in the window just ending.
    copied_anchor: int = 0

    # 'stack.timer.now_ms' at the last measurement; the next adjust is
    # gated until one receiver-RTT has elapsed past this.
    time_ms: int = 0
