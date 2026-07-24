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
This module contains the per-session application-level shutdown
half-state container, covering the BSD-style 'shutdown(SHUT_RD)' /
'shutdown(SHUT_WR)' application gates.

pytcp/protocols/tcp/state/tcp__state__shutdown.py

ver 3.0.9
"""

from dataclasses import dataclass


@dataclass(slots=True)
class ShutdownState:
    """
    Per-session application-shutdown state. Owned by 'TcpSession';
    set by the BSD-style 'shutdown' syscall on the socket layer.
    Distinct from the FSM-level CLOSE / CLOSED transitions: half-
    shutdown affects which application-side I/O operations succeed,
    not the wire-level connection state.
    """

    # SHUT_RD: application has called shutdown(SHUT_RD). Inbound
    # data is silently discarded; recv() returns 0 after the
    # buffer drains. The wire-level connection stays open.
    rd: bool = False

    # SHUT_WR: application has called shutdown(SHUT_WR). Drains
    # the TX buffer and emits FIN (same effect as a graceful
    # close of the send side). Subsequent send() calls fail.
    wr: bool = False
