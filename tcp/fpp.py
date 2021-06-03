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
# tcp/fpp.py - Fast Packet Parser support class for TCP protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Optional

import config
import tcp.ps
from misc.ip_helper import inet_cksum

if TYPE_CHECKING:
    from misc.packet import PacketRx


class TcpParser:
    """TCP packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        assert packet_rx.ip is not None

        packet_rx.tcp = self

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip.dlen

        packet_rx.parse_failed = self._packet_integrity_check(packet_rx.ip.pshdr_sum) or self._packet_sanity_check()

        if packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[self.hlen :]

    def __len__(self) -> int:
        """Packet length"""

        return len(self._frame)

    def __str__(self) -> str:
        """Packet log string"""

        log = (
            f"TCP {self.sport} > {self.dport}, {'N' if self.flag_ns else ''}{'C' if self.flag_crw else ''}"
            + f"{'E' if self.flag_ece else ''}{'U' if self.flag_urg else ''}{'A' if self.flag_ack else ''}"
            + f"{'P' if self.flag_psh else ''}{'R' if self.flag_rst else ''}{'S' if self.flag_syn else ''}"
            + f"{'F' if self.flag_fin else ''}, seq {self.seq}, ack {self.ack}, win {self.win}, dlen {len(self.data)}"
        )

        for option in self.options:
            log += ", " + str(option)

        return log

    @property
    def sport(self) -> int:
        """Read 'Source port' field"""

        if "_cache__sport" not in self.__dict__:
            self._cache__sport: int = struct.unpack("!H", self._frame[0:2])[0]
        return self._cache__sport

    @property
    def dport(self) -> int:
        """Read 'Destianation port' field"""

        if "_cache__dport" not in self.__dict__:
            self._cache__dport: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__dport

    @property
    def seq(self) -> int:
        """Read 'Sequence number' field"""

        if "_cache__seq" not in self.__dict__:
            self._cache__seq: int = struct.unpack("!L", self._frame[4:8])[0]
        return self._cache__seq

    @property
    def ack(self) -> int:
        """Read 'Acknowledge number' field"""

        if "_cache__ack" not in self.__dict__:
            self._cache__ack: int = struct.unpack("!L", self._frame[8:12])[0]
        return self._cache__ack

    @property
    def hlen(self) -> int:
        """Read 'Header length' field"""

        if "_cache__hlen" not in self.__dict__:
            self._cache__hlen = (self._frame[12] & 0b11110000) >> 2
        return self._cache__hlen

    @property
    def flag_ns(self) -> bool:
        """Read 'NS flag' field"""

        if "_cache__flag_ns" not in self.__dict__:
            self._cache__flag_ns = bool(self._frame[12] & 0b00000001)
        return self._cache__flag_ns

    @property
    def flag_crw(self) -> bool:
        """Read 'CRW flag' field"""

        if "_cache__flag_crw" not in self.__dict__:
            self._cache__flag_crw = bool(self._frame[13] & 0b10000000)
        return self._cache__flag_crw

    @property
    def flag_ece(self) -> bool:
        """Read 'ECE flag' field"""

        if "_cache__flag_ece" not in self.__dict__:
            self._cache__flag_ece = bool(self._frame[13] & 0b01000000)
        return self._cache__flag_ece

    @property
    def flag_urg(self) -> bool:
        """Read 'URG flag' field"""

        if "_cache__flag_urg" not in self.__dict__:
            self._cache__flag_urg = bool(self._frame[13] & 0b00100000)
        return self._cache__flag_urg

    @property
    def flag_ack(self) -> bool:
        """Read 'ACK flag' field"""

        if "_cache__flag_ack" not in self.__dict__:
            self._cache__flag_ack = bool(self._frame[13] & 0b00010000)
        return self._cache__flag_ack

    @property
    def flag_psh(self) -> bool:
        """Read 'PSH flag' field"""

        if "_cache__flag_psh" not in self.__dict__:
            self._cache__flag_psh = bool(self._frame[13] & 0b00001000)
        return self._cache__flag_psh

    @property
    def flag_rst(self) -> bool:
        """Read 'RST flag' field"""

        if "_cache__flag_rst" not in self.__dict__:
            self._cache__flag_rst = bool(self._frame[13] & 0b00000100)
        return self._cache__flag_rst

    @property
    def flag_syn(self) -> bool:
        """Read 'SYN flag' field"""

        if "_cache__flag_syn" not in self.__dict__:
            self._cache__flag_syn = bool(self._frame[13] & 0b00000010)
        return self._cache__flag_syn

    @property
    def flag_fin(self) -> bool:
        """Read 'FIN flag' field"""

        if "_cache__flag_fin" not in self.__dict__:
            self._cache__flag_fin = bool(self._frame[13] & 0b00000001)
        return self._cache__flag_fin

    @property
    def win(self) -> int:
        """Read 'Window' field"""

        if "_cache__win" not in self.__dict__:
            self._cache__win: int = struct.unpack("!H", self._frame[14:16])[0]
        return self._cache__win

    @property
    def cksum(self) -> int:
        """Read 'Checksum' field"""

        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum: int = struct.unpack("!H", self._frame[16:18])[0]
        return self._cache__cksum

    @property
    def urg(self) -> int:
        """Read 'Urgent pointer' field"""

        if "_cache__urg" not in self.__dict__:
            self._cache__urg: int = struct.unpack("!H", self._frame[18:20])[0]
        return self._cache__urg

    @property
    def data(self) -> memoryview:
        """Read the data packet carries"""

        if "_cache__data" not in self.__dict__:
            self._cache__data = self._frame[self.hlen : self.plen]
        return self._cache__data

    @property
    def olen(self) -> int:
        """Calculate options length"""

        if "_cache__olen" not in self.__dict__:
            self._cache__olen = self.hlen - tcp.ps.TCP_HEADER_LEN
        return self._cache__olen

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        return self._plen - self.hlen

    @property
    def plen(self) -> int:
        """Calculate packet length"""

        return self._plen

    @property
    def header_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(self._frame[: tcp.ps.TCP_HEADER_LEN])
        return self._cache__header_copy

    @property
    def options_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__options_copy" not in self.__dict__:
            self._cache__options_copy = bytes(self._frame[tcp.ps.TCP_HEADER_LEN : self.hlen])
        return self._cache__options_copy

    @property
    def data_copy(self) -> bytes:
        """Return copy of packet data"""

        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(self._frame[self.hlen : self.plen])
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """Return copy of whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[: self.plen])
        return self._cache__packet_copy

    @property
    def options(self) -> list[TcpOptMss | TcpOptWscale | TcpOptSackPerm | TcpOptTimestamp | TcpOptUnk | TcpOptEol | TcpOptNop]:
        """Read list of options"""

        if "_cache__options" not in self.__dict__:
            self._cache__options: list = []
            optr = tcp.ps.TCP_HEADER_LEN
            while optr < self.hlen:
                if self._frame[optr] == tcp.ps.TCP_OPT_EOL:
                    self._cache__options.append(TcpOptEol())
                    break
                if self._frame[optr] == tcp.ps.TCP_OPT_NOP:
                    self._cache__options.append(TcpOptNop())
                    optr += tcp.ps.TCP_OPT_NOP_LEN
                    continue
                self._cache__options.append(
                    {
                        tcp.ps.TCP_OPT_MSS: TcpOptMss,
                        tcp.ps.TCP_OPT_WSCALE: TcpOptWscale,
                        tcp.ps.TCP_OPT_SACKPERM: TcpOptSackPerm,
                        tcp.ps.TCP_OPT_TIMESTAMP: TcpOptTimestamp,
                    }.get(self._frame[optr], TcpOptUnk)(self._frame[optr:])
                )
                optr += self._frame[optr + 1]

        return self._cache__options

    @property
    def mss(self) -> int:
        """TCP option - Maximum Segment Size (2)"""

        if "_cache__mss" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptMss):
                    self._cache__mss = option.mss
                    break
            else:
                self._cache__mss = 536
        return self._cache__mss

    @property
    def wscale(self) -> Optional[int]:
        """TCP option - Window Scale (3)"""

        if "_cache__wscale" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptWscale):
                    self._cache__wscale: Optional[int] = 1 << option.wscale
                    break
            else:
                self._cache__wscale = None
        return self._cache__wscale

    @property
    def sackperm(self) -> Optional[bool]:
        """TCP option - Sack Permit (4)"""

        if "_cache__sackperm" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptSackPerm):
                    self._cache__sackperm: Optional[bool] = True
                    break
            else:
                self._cache__sackperm = None
        return self._cache__sackperm

    @property
    def timestamp(self) -> Optional[tuple[int, int]]:
        """TCP option - Timestamp (8)"""

        if "_cache__timestamp" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptTimestamp):
                    self._cache__timestamp: Optional[tuple[int, int]] = (option.tsval, option.tsecr)
                    break
            else:
                self._cache__timestamp = None
        return self._cache__timestamp

    def _packet_integrity_check(self, pshdr_sum: int) -> str:
        """Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if inet_cksum(self._frame[: self._plen], pshdr_sum):
            return "TCP integrity - wrong packet checksum"

        if not tcp.ps.TCP_HEADER_LEN <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (I)"

        hlen = (self._frame[12] & 0b11110000) >> 2
        if not tcp.ps.TCP_HEADER_LEN <= hlen <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (II)"

        optr = tcp.ps.TCP_HEADER_LEN
        while optr < hlen:
            if self._frame[optr] == tcp.ps.TCP_OPT_EOL:
                break
            if self._frame[optr] == tcp.ps.TCP_OPT_NOP:
                optr += 1
                if optr > hlen:
                    return "TCP integrity - wrong option length (I)"
                continue
            if optr + 1 > hlen:
                return "TCP integrity - wrong option length (II)"
            if self._frame[optr + 1] == 0:
                return "TCP integrity - wrong option length (III)"
            optr += self._frame[optr + 1]
            if optr > hlen:
                return "TCP integrity - wrong option length (IV)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.sport == 0:
            return "TCP sanity - 'sport' must be greater than 0"

        if self.dport == 0:
            return "TCP sanity - 'dport' must be greater than  0"

        if self.flag_syn and self.flag_fin:
            return "TCP sanity - 'flag_syn' and 'flag_fin' must not be set simultaneously"

        if self.flag_syn and self.flag_rst:
            return "TCP sanity - 'flag_syn' and 'flag_rst' must not set simultaneously"

        if self.flag_fin and self.flag_rst:
            return "TCP sanity - 'flag_fin' and 'flag_rst' must not be set simultaneously"

        if self.flag_fin and not self.flag_ack:
            return "TCP sanity - 'flag_ack' must be set when 'flag_fin' is set"

        if self.ack and not self.flag_ack:
            return "TCP sanity - 'flag_ack' must be set when 'ack' is not 0"

        if self.urg and not self.flag_urg:
            return "TCP sanity - 'flag_urg' must be set when 'urg' is not 0"

        return ""


#
# TCP options
#


class TcpOptEol:
    """TCP option - End of TcpOption List (0)"""

    def __init__(self) -> None:
        self.kind = tcp.ps.TCP_OPT_EOL

    def __str__(self) -> str:
        """Option log string"""

        return "eol"

    def __len__(self) -> int:
        """Option length"""

        return tcp.ps.TCP_OPT_EOL_LEN


class TcpOptNop:
    """TCP option - No Operation (1)"""

    def __init__(self) -> None:
        self.kind = tcp.ps.TCP_OPT_NOP

    def __str__(self) -> str:
        """Option log string"""

        return "nop"

    def __len__(self) -> int:
        """Option length"""

        return tcp.ps.TCP_OPT_NOP_LEN


class TcpOptMss:
    """TCP option - Maximum Segment Size (2)"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.mss: int = struct.unpack_from("!H", frame, 2)[0]

    def __str__(self) -> str:
        """Option log string"""

        return f"mss {self.mss}"

    def __len__(self) -> int:
        """Option length"""

        return self.len


class TcpOptWscale:
    """TCP option - Window Scale (3)"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.wscale = frame[2]

    def __str__(self) -> str:
        """Option log string"""

        return f"wscale {self.wscale}"

    def __len__(self) -> int:
        """Option length"""

        return self.len


class TcpOptSackPerm:
    """TCP option - Sack Permit (4)"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]

    def __str__(self) -> str:
        """Option log string"""

        return "sack_perm"

    def __len__(self) -> int:
        """Option length"""

        return self.len


class TcpOptTimestamp:
    """TCP option - Timestamp (8)"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.tsval: int = struct.unpack_from("!L", frame, 2)[0]
        self.tsecr: int = struct.unpack_from("!L", frame, 6)[0]

    def __str__(self) -> str:
        """Option log string"""

        return f"ts {self.tsval}/{self.tsecr}"

    def __len__(self) -> int:
        """Option length"""

        return self.len


class TcpOptUnk:
    """TCP option not supported by this stack"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.data = frame[2 : self.len]

    def __str__(self) -> str:
        """Option log string"""

        return f"unk-{self.kind}-{self.len}"

    def __len__(self) -> int:
        """Option length"""

        return self.len
