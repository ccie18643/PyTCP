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

# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-locals

"""
Module contains Fast Packet Assembler support class for the TCP protocol.

pytcp/protocols/tcp/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ip4.ps import IP4_PROTO_TCP
from pytcp.protocols.ip6.ps import IP6_NEXT_TCP
from pytcp.protocols.tcp.ps import (
    TCP_HEADER_LEN,
    TCP_OPT_EOL,
    TCP_OPT_EOL_LEN,
    TCP_OPT_MSS,
    TCP_OPT_MSS_LEN,
    TCP_OPT_NOP,
    TCP_OPT_NOP_LEN,
    TCP_OPT_SACKPERM,
    TCP_OPT_SACKPERM_LEN,
    TCP_OPT_TIMESTAMP,
    TCP_OPT_TIMESTAMP_LEN,
    TCP_OPT_WSCALE,
    TCP_OPT_WSCALE_LEN,
)


class TcpAssembler:
    """
    TCP packet assembler support class.
    """

    ip4_proto = IP4_PROTO_TCP
    ip6_next = IP6_NEXT_TCP

    def __init__(
        self,
        *,
        sport: int = 0,
        dport: int = 0,
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
        options: (
            list[
                TcpOptMss
                | TcpOptWscale
                | TcpOptSackPerm
                | TcpOptTimestamp
                | TcpOptEol
                | TcpOptNop
            ]
            | None
        ) = None,
        data: bytes | None = None,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Class constructor.
        """

        assert 0 <= sport <= 0xFFFF, f"{sport=}"
        assert 0 <= dport <= 0xFFFF, f"{dport=}"
        assert 0 <= seq <= 0xFFFFFFFF, f"{seq=}"
        assert 0 <= ack <= 0xFFFFFFFF, f"{ack=}"
        assert 0 <= win <= 0xFFFF, f"{win=}"
        assert 0 <= urp <= 0xFFFF, f"{urp=}"

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._sport: int = sport
        self._dport: int = dport
        self._seq: int = seq
        self._ack: int = ack
        self._flag_ns: bool = flag_ns
        self._flag_crw: bool = flag_crw
        self._flag_ece: bool = flag_ece
        self._flag_urg: bool = flag_urg
        self._flag_ack: bool = flag_ack
        self._flag_psh: bool = flag_psh
        self._flag_rst: bool = flag_rst
        self._flag_syn: bool = flag_syn
        self._flag_fin: bool = flag_fin
        self._win: int = win
        self._urp: int = urp
        self._options: list[
            TcpOptMss
            | TcpOptWscale
            | TcpOptSackPerm
            | TcpOptTimestamp
            | TcpOptEol
            | TcpOptNop
        ] = ([] if options is None else options)
        self._data: bytes = b"" if data is None else data
        self._hlen: int = TCP_HEADER_LEN + sum(len(_) for _ in self._options)

        assert self._hlen % 4 == 0, (
            f"TCP header len {self._hlen} is not multiplication of 4 bytes, "
            f"check options... {self._options}"
        )

    def __len__(self) -> int:
        """
        Length of the packet.
        """
        return self._hlen + len(self._data)

    def __str__(self) -> str:
        """
        Packet log string.
        """

        log = (
            f"TCP {self._sport} > {self._dport}, "
            f"{'N' if self._flag_ns else ''}{'C' if self._flag_crw else ''}"
            f"{'E' if self._flag_ece else ''}{'U' if self._flag_urg else ''}"
            f"{'A' if self._flag_ack else ''}{'P' if self._flag_psh else ''}"
            f"{'R' if self._flag_rst else ''}{'S' if self._flag_syn else ''}"
            f"{'F' if self._flag_fin else ''}, seq {self._seq}, "
            f"ack {self._ack}, win {self._win}, dlen {len(self._data)}"
        )

        for option in self._options:
            log += ", " + str(option)

        return log

    @property
    def tracker(self) -> Tracker:
        """
        Getter for '_tracker' attribute.
        """
        return self._tracker

    @property
    def _raw_options(self) -> bytes:
        """
        Packet options in raw format.
        """
        return b"".join(bytes(option) for option in self._options)

    def assemble(self, frame: memoryview, pshdr_sum: int) -> None:
        """
        Assemble packet into the raw form.
        """
        struct.pack_into(
            f"! HH L L BBH HH {len(self._raw_options)}s {len(self._data)}s",
            frame,
            0,
            self._sport,
            self._dport,
            self._seq,
            self._ack,
            self._hlen << 2 | self._flag_ns,
            self._flag_crw << 7
            | self._flag_ece << 6
            | self._flag_urg << 5
            | self._flag_ack << 4
            | self._flag_psh << 3
            | self._flag_rst << 2
            | self._flag_syn << 1
            | self._flag_fin,
            self._win,
            0,
            self._urp,
            self._raw_options,
            self._data,
        )
        struct.pack_into("! H", frame, 16, inet_cksum(frame, pshdr_sum))


#
# TCP options
#


class TcpOptEol:
    """
    TCP option - End of Option List (0).
    """

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "eol"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_EOL_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return "TcpOptEol()"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("!B", TCP_OPT_EOL)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class TcpOptNop:
    """
    TCP option - No Operation (1).
    """

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "nop"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_NOP_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return "TcpOptNop()"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("!B", TCP_OPT_NOP)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class TcpOptMss:
    """
    TCP option - Maximum Segment Size (2).
    """

    def __init__(self, mss: int) -> None:
        """
        Option constructor.
        """
        assert 0 <= mss <= 0xFFFF, f"{mss=}"
        self._mss = mss

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"mss {self._mss}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_MSS_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return f"TcpOptMss({self._mss})"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("! BB H", TCP_OPT_MSS, TCP_OPT_MSS_LEN, self._mss)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class TcpOptWscale:
    """
    TCP option - Window Scale (3).
    """

    def __init__(self, wscale: int) -> None:
        """
        Option constructor.
        """
        assert 0 <= wscale <= 0xFF, f"{wscale=}"
        self._wscale = wscale

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"wscale {self._wscale}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_WSCALE_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return f"TcpOptWscale({self._wscale})"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB B", TCP_OPT_WSCALE, TCP_OPT_WSCALE_LEN, self._wscale
        )

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class TcpOptSackPerm:
    """
    TCP option - Sack Permit (4).
    """

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "sack_perm"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_SACKPERM_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return "TcpOptSackPerm()"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("! BB", TCP_OPT_SACKPERM, TCP_OPT_SACKPERM_LEN)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class TcpOptTimestamp:
    """
    TCP option - Timestamp (8).
    """

    def __init__(self, tsval: int, tsecr: int) -> None:
        """
        Optional constructor.
        """
        assert 0 <= tsval <= 0xFFFFFFFF, f"{tsval=}"
        assert 0 <= tsecr <= 0xFFFFFFFF, f"{tsecr=}"
        self._tsval = tsval
        self._tsecr = tsecr

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"ts {self._tsval}/{self._tsecr}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return TCP_OPT_TIMESTAMP_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return f"TcpOptTimestamp({self._tsval}, {self._tsecr})"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB LL",
            TCP_OPT_TIMESTAMP,
            TCP_OPT_TIMESTAMP_LEN,
            self._tsval,
            self._tsecr,
        )

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)
