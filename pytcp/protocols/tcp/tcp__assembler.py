#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the TCP packet assembler class.

pytcp/protocols/tcp/tcp__assembler.py

ver 3.0.0
"""


from __future__ import annotations

from pytcp.lib.int_checks import is_4_byte_alligned
from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.tcp.options.tcp_option__eol import TcpOptionEol
from pytcp.protocols.tcp.options.tcp_options import (
    TCP__OPTIONS__MAX_LEN,
    TcpOptions,
)
from pytcp.protocols.tcp.tcp__base import Tcp
from pytcp.protocols.tcp.tcp__header import TCP__HEADER__LEN, TcpHeader


class TcpAssembler(Tcp, ProtoAssembler):
    """
    The TCP packet base.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        tcp__sport: int = 0,
        tcp__dport: int = 0,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__flag_ns: bool = False,
        tcp__flag_cwr: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_urg: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_syn: bool = False,
        tcp__flag_fin: bool = False,
        tcp__win: int = 0,
        tcp__urg: int = 0,
        tcp__options: TcpOptions = TcpOptions(),
        tcp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the TCP packet parser.
        """

        assert (
            len(tcp__options) <= TCP__OPTIONS__MAX_LEN
        ), f"The TCP options length must be less than or equal to {TCP__OPTIONS__MAX_LEN}."

        assert is_4_byte_alligned(
            len(tcp__options)
        ), "The TCP options length must be 4-byte aligned."

        assert (
            TcpOptionEol() not in tcp__options
            or tcp__options[-1] == TcpOptionEol()
        ), "The TCP EOL option must be the last option."

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = tcp__payload

        self._options = tcp__options

        self._header = TcpHeader(
            sport=tcp__sport,
            dport=tcp__dport,
            seq=tcp__seq,
            ack=tcp__ack,
            hlen=TCP__HEADER__LEN + len(self._options),
            flag_ns=tcp__flag_ns,
            flag_cwr=tcp__flag_cwr,
            flag_ece=tcp__flag_ece,
            flag_urg=tcp__flag_urg,
            flag_ack=tcp__flag_ack,
            flag_psh=tcp__flag_psh,
            flag_rst=tcp__flag_rst,
            flag_syn=tcp__flag_syn,
            flag_fin=tcp__flag_fin,
            win=tcp__win,
            cksum=0,
            urg=tcp__urg,
        )
