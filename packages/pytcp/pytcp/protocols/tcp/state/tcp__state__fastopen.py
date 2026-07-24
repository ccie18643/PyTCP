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
This module contains the per-session TFO (RFC 7413) state
container. Holds the listener-side cookie pending emission,
the §4.2 PendingFastOpenRequests-counted flag, and the §4.4
SYN-retransmit-without-TFO sentinel.

Stack-wide TFO state (cookie cache, negative-response cache,
pending-request counter) lives on 'pytcp.stack.tcp_stack'
(TcpStack) because it is process-wide, not per-session.

pytcp/protocols/tcp/state/tcp__state__fastopen.py

ver 3.0.8
"""

from dataclasses import dataclass


@dataclass(slots=True)
class FastOpenState:
    """
    Per-session TFO state. Owned by 'TcpSession'; mutated by the
    LISTEN handler (cookie stash on AccECN-setup SYN), by the
    SYN-retransmit path (§4.4 marker), and by the cleanup path
    on session teardown (§4.2 counter decrement).
    """

    # RFC 7413 §3.1 listener-side cookie pending emission. When
    # peer's passive-open SYN carries the TFO option, the
    # LISTEN handler generates a cookie and stashes it here so
    # the SYN+ACK we emit on the next tick carries it back. The
    # field is consumed (cleared back to None) by '_transmit_packet'
    # once the SYN+ACK fires so a SYN+ACK retransmit does not
    # re-issue a stale cookie.
    cookie_to_emit: bytes | None = None

    # RFC 7413 §4.2 PendingFastOpenRequests bookkeeping: True
    # iff this session was accepted via TFO and counted into
    # 'stack.tcp_stack.fastopen_pending_count'. Decremented on
    # session teardown so the listening socket's
    # 'fastopen_qlen' admission gate sees an accurate count.
    pending_counted: bool = False

    # RFC 7413 §4.4 SYN-retransmit-without-TFO sentinel. Set
    # True on a SYN retransmit (TFO connection that timed out
    # waiting for SYN+ACK); subsequent active-open emissions
    # bypass the TFO option so the second attempt is a plain
    # 3WHS.
    syn_retransmitted: bool = False
