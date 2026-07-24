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
This module contains the TCP FSM CLOSED state handler.

pytcp/protocols/tcp/fsm/tcp__fsm__closed.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


def fsm__closed__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM CLOSED state syscall handler.
    """

    # Got CONNECT syscall -> Send SYN packet (this actually will be done in
    # SYN_SENT state) / change state to SYN_SENT.
    if syscall is SysCall.CONNECT:
        session._change_state(FsmState.SYN_SENT)

    # Got LISTEN syscall -> Change state to LISTEN.
    if syscall is SysCall.LISTEN:
        session._change_state(FsmState.LISTEN)
