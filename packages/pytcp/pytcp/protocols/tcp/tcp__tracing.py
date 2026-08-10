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

# pyright: reportPrivateUsage=false

"""
This module contains the TCP session tracing decorators.

pytcp/protocols/tcp/tcp__tracing.py

ver 3.0.9
"""

import functools
from collections.abc import Callable
from typing import Any

from pytcp.protocols.tcp.session import TcpSession


def trace_fsm(function: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """
    Decorator for tracing FSM state.
    """

    # pylint: disable=protected-access

    @functools.wraps(function)
    def wrapper(self: TcpSession, *args: list[Any], **kwargs: dict[str, Any]) -> Any:
        print(
            f"[ >>> ] snd_nxt {self._snd_seq.nxt}, snd_una {self._snd_seq.una},",
            f"rcv_nxt {self._rcv_seq.nxt}, rcv_una {self._rcv_seq.una}",
        )
        retval = function(self, *args, **kwargs)
        print(
            f"[ <<< ] snd_nxt {self._snd_seq.nxt}, snd_una {self._snd_seq.una},",
            f"rcv_nxt {self._rcv_seq.nxt}, rcv_una {self._rcv_seq.una}",
        )
        return retval

    return wrapper


def trace_win(self: TcpSession) -> None:
    """
    Method used to trace sliding window operation, invoke as 'trace_win(self)'
    from within the TcpSession object.
    """

    # pylint: disable=protected-access

    remaining_data_len = len(self._tx.buffer) - self._tx_buffer_nxt
    usable_window = self._tx_buffer_una + self._cc.snd_ewn - self._tx_buffer_nxt
    transmit_data_len = min(self._win.snd_mss, usable_window, remaining_data_len)

    print("unsent_data:", remaining_data_len)
    print("usable_window:", usable_window)
    print("transmit_data_len:", transmit_data_len)
    print("self._snd_seq.nxt:", self._snd_seq.nxt)
    print("self._snd_seq.una:", self._snd_seq.una)
    print("self._tx.seq_mod:", self._tx.seq_mod)
    print("self._tx_buffer_nxt:", self._tx_buffer_nxt)
    print("self._tx_buffer_una:", self._tx_buffer_una)
