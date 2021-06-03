#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# tcp/fpa.py - Fast Packet Assembler support class for TCP protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import Optional

import ip4.ps
import ip6.ps
import tcp.ps
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker


class TcpAssembler:
    """TCP packet assembler support class"""

    ip4_proto = ip4.ps.IP4_PROTO_TCP
    ip6_next = ip6.ps.IP6_NEXT_HEADER_TCP

    def __init__(
        self,
        sport: int,
        dport: int,
        seq: int = 0,
        ack: int = 0,
        flag_ns: bool = False,
        flag_crw: bool = False,
        flag_ece: bool = False,
        flag_urg: bool = False,
        flag_ack: bool = False,
        flag_psh: bool = False,
        flag_rst: bool = False,
        flag_syn: bool = False,
        flag_fin: bool = False,
        win: int = 0,
        urp: int = 0,
        options: Optional[list] = None,
        data: Optional[bytes] = None,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flag_ns = flag_ns
        self.flag_crw = flag_crw
        self.flag_ece = flag_ece
        self.flag_urg = flag_urg
        self.flag_ack = flag_ack
        self.flag_psh = flag_psh
        self.flag_rst = flag_rst
        self.flag_syn = flag_syn
        self.flag_fin = flag_fin
        self.win = win
        self.urp = urp
        self.options = [] if options is None else options
        self.data = b"" if data is None else data
        self.hlen = tcp.ps.TCP_HEADER_LEN + sum([len(_) for _ in self.options])

        assert self.hlen % 4 == 0, f"TCP header len {self.hlen} is not multiplcation of 4 bytes, check options... {self.options}"

    def __len__(self) -> int:
        """Length of the packet"""

        return self.hlen + len(self.data)

    from tcp.ps import __str__

    @property
    def raw_options(self) -> bytes:
        """Packet options in raw format"""

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    def assemble(self, frame: bytearray, hptr: int, pshdr_sum: int):
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! HH L L BBH HH {len(self.raw_options)}s {len(self.data)}s",
            frame,
            hptr,
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            self.hlen << 2 | self.flag_ns,
            self.flag_crw << 7
            | self.flag_ece << 6
            | self.flag_urg << 5
            | self.flag_ack << 4
            | self.flag_psh << 3
            | self.flag_rst << 2
            | self.flag_syn << 1
            | self.flag_fin,
            self.win,
            0,
            self.urp,
            self.raw_options,
            self.data,
        )

        struct.pack_into("! H", frame, hptr + 16, inet_cksum(frame, hptr, len(self), pshdr_sum))


#
# TCP options
#


class TcpOptEol(tcp.ps.TcpOptEol):
    """TCP option - End of Option List (0)"""

    @property
    def raw_option(self) -> bytes:
        return struct.pack("!B", tcp.ps.TCP_OPT_EOL)


class TcpOptNop(tcp.ps.TcpOptNop):
    """TCP option - No Operation (1)"""

    @property
    def raw_option(self) -> bytes:
        return struct.pack("!B", tcp.ps.TCP_OPT_NOP)


class TcpOptMss(tcp.ps.TcpOptMss):
    """TCP option - Maximum Segment Size (2)"""

    def __init__(self, mss: int) -> None:
        self.mss = mss

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB H", tcp.ps.TCP_OPT_MSS, tcp.ps.TCP_OPT_MSS_LEN, self.mss)


class TcpOptWscale(tcp.ps.TcpOptWscale):
    """TCP option - Window Scale (3)"""

    def __init__(self, wscale: int) -> None:
        self.wscale = wscale

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB B", tcp.ps.TCP_OPT_WSCALE, tcp.ps.TCP_OPT_WSCALE_LEN, self.wscale)


class TcpOptSackPerm(tcp.ps.TcpOptSackPerm):
    """TCP option - Sack Permit (4)"""

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB", tcp.ps.TCP_OPT_SACKPERM, tcp.ps.TCP_OPT_SACKPERM_LEN)


class TcpOptTimestamp(tcp.ps.TcpOptTimestamp):
    """TCP option - Timestamp (8)"""

    def __init__(self, tsval: int, tsecr: int) -> None:
        self.tsval = tsval
        self.tsecr = tsecr

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB LL", tcp.ps.TCP_OPT_TIMESTAMP, tcp.ps.TCP_OPT_TIMESTAMP_LEN, self.tsval, self.tsecr)
