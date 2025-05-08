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
# pylint: disable = too-many-return-statements
# pylint: disable = too-many-public-methods
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parser support class the for TCP protocol.

pytcp/protocols/tcp/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.tcp.ps import (
    TCP_HEADER_LEN,
    TCP_OPT_EOL,
    TCP_OPT_EOL_LEN,
    TCP_OPT_MSS,
    TCP_OPT_NOP,
    TCP_OPT_NOP_LEN,
    TCP_OPT_SACKPERM,
    TCP_OPT_TIMESTAMP,
    TCP_OPT_WSCALE,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class TcpParser:
    """
    TCP packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        assert packet_rx.ip is not None

        packet_rx.tcp = self

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip.dlen

        packet_rx.parse_failed = (
            self._packet_integrity_check(packet_rx.ip.pshdr_sum)
            or self._packet_sanity_check()
        )

        if packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[self.hlen :]

    def __len__(self) -> int:
        """
        Packet length.
        """
        return len(self._frame)

    def __str__(self) -> str:
        """
        Packet log string.
        """

        log = (
            f"TCP {self.sport} > {self.dport}, "
            f"{'N' if self.flag_ns else ''}{'C' if self.flag_crw else ''}"
            f"{'E' if self.flag_ece else ''}{'U' if self.flag_urg else ''}"
            f"{'A' if self.flag_ack else ''}{'P' if self.flag_psh else ''}"
            f"{'R' if self.flag_rst else ''}{'S' if self.flag_syn else ''}"
            f"{'F' if self.flag_fin else ''}, seq {self.seq}, ack {self.ack}, "
            f"win {self.win}, dlen {len(self.data)}"
        )

        for option in self.options:
            log += ", " + str(option)

        return log

    @property
    def sport(self) -> int:
        """
        Read the 'Source port' field.
        """
        if "_cache__sport" not in self.__dict__:
            self._cache__sport: int = struct.unpack("!H", self._frame[0:2])[0]
        return self._cache__sport

    @property
    def dport(self) -> int:
        """
        Read the 'Destination port' field.
        """
        if "_cache__dport" not in self.__dict__:
            self._cache__dport: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__dport

    @property
    def seq(self) -> int:
        """
        Read the 'Sequence number' field.
        """
        if "_cache__seq" not in self.__dict__:
            self._cache__seq: int = struct.unpack("!L", self._frame[4:8])[0]
        return self._cache__seq

    @property
    def ack(self) -> int:
        """
        Read the 'Acknowledge number' field.
        """
        if "_cache__ack" not in self.__dict__:
            self._cache__ack: int = struct.unpack("!L", self._frame[8:12])[0]
        return self._cache__ack

    @property
    def hlen(self) -> int:
        """
        Read the 'Header length' field.
        """
        if "_cache__hlen" not in self.__dict__:
            self._cache__hlen = (self._frame[12] & 0b11110000) >> 2
        return self._cache__hlen

    @property
    def flag_ns(self) -> bool:
        """
        Read the 'NS flag' field.
        """
        if "_cache__flag_ns" not in self.__dict__:
            self._cache__flag_ns = bool(self._frame[12] & 0b00000001)
        return self._cache__flag_ns

    @property
    def flag_crw(self) -> bool:
        """
        Read the 'CRW flag' field.
        """
        if "_cache__flag_crw" not in self.__dict__:
            self._cache__flag_crw = bool(self._frame[13] & 0b10000000)
        return self._cache__flag_crw

    @property
    def flag_ece(self) -> bool:
        """
        Read the 'ECE flag' field.
        """
        if "_cache__flag_ece" not in self.__dict__:
            self._cache__flag_ece = bool(self._frame[13] & 0b01000000)
        return self._cache__flag_ece

    @property
    def flag_urg(self) -> bool:
        """
        Read the 'URG flag' field.
        """
        if "_cache__flag_urg" not in self.__dict__:
            self._cache__flag_urg = bool(self._frame[13] & 0b00100000)
        return self._cache__flag_urg

    @property
    def flag_ack(self) -> bool:
        """
        Read the 'ACK flag' field.
        """
        if "_cache__flag_ack" not in self.__dict__:
            self._cache__flag_ack = bool(self._frame[13] & 0b00010000)
        return self._cache__flag_ack

    @property
    def flag_psh(self) -> bool:
        """
        Read the 'PSH flag' field.
        """
        if "_cache__flag_psh" not in self.__dict__:
            self._cache__flag_psh = bool(self._frame[13] & 0b00001000)
        return self._cache__flag_psh

    @property
    def flag_rst(self) -> bool:
        """
        Read the 'RST flag' field.
        """
        if "_cache__flag_rst" not in self.__dict__:
            self._cache__flag_rst = bool(self._frame[13] & 0b00000100)
        return self._cache__flag_rst

    @property
    def flag_syn(self) -> bool:
        """
        Read the 'SYN flag' field.
        """
        if "_cache__flag_syn" not in self.__dict__:
            self._cache__flag_syn = bool(self._frame[13] & 0b00000010)
        return self._cache__flag_syn

    @property
    def flag_fin(self) -> bool:
        """
        Read the 'FIN flag' field.
        """
        if "_cache__flag_fin" not in self.__dict__:
            self._cache__flag_fin = bool(self._frame[13] & 0b00000001)
        return self._cache__flag_fin

    @property
    def win(self) -> int:
        """
        Read the 'Window' field.
        """
        if "_cache__win" not in self.__dict__:
            self._cache__win: int = struct.unpack("!H", self._frame[14:16])[0]
        return self._cache__win

    @property
    def cksum(self) -> int:
        """
        Read the 'Checksum' field.
        """
        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum: int = struct.unpack("!H", self._frame[16:18])[0]
        return self._cache__cksum

    @property
    def urg(self) -> int:
        """
        Read the 'Urgent pointer' field.
        """
        if "_cache__urg" not in self.__dict__:
            self._cache__urg: int = struct.unpack("!H", self._frame[18:20])[0]
        return self._cache__urg

    @property
    def data(self) -> memoryview:
        """
        Read the data packet carries.
        """
        if "_cache__data" not in self.__dict__:
            self._cache__data = self._frame[self.hlen : self.plen]
        return self._cache__data

    @property
    def olen(self) -> int:
        """
        Calculate options length.
        """
        if "_cache__olen" not in self.__dict__:
            self._cache__olen = self.hlen - TCP_HEADER_LEN
        return self._cache__olen

    @property
    def dlen(self) -> int:
        """
        Calculate data length.
        """
        return self._plen - self.hlen

    @property
    def plen(self) -> int:
        """
        Calculate packet length.
        """
        return self._plen

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(self._frame[:TCP_HEADER_LEN])
        return self._cache__header_copy

    @property
    def options_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__options_copy" not in self.__dict__:
            self._cache__options_copy = bytes(
                self._frame[TCP_HEADER_LEN : self.hlen]
            )
        return self._cache__options_copy

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """
        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(self._frame[self.hlen : self.plen])
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """
        Return copy of whole packet.
        """
        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[: self.plen])
        return self._cache__packet_copy

    @property
    def options(
        self,
    ) -> list[
        TcpOptMss
        | TcpOptWscale
        | TcpOptSackPerm
        | TcpOptTimestamp
        | TcpOptUnk
        | TcpOptEol
        | TcpOptNop
    ]:
        """
        Read list of options.
        """

        if "_cache__options" not in self.__dict__:
            self._cache__options: list = []
            optr = TCP_HEADER_LEN
            while optr < self.hlen:
                if self._frame[optr] == TCP_OPT_EOL:
                    self._cache__options.append(TcpOptEol())
                    break
                if self._frame[optr] == TCP_OPT_NOP:
                    self._cache__options.append(TcpOptNop())
                    optr += TCP_OPT_NOP_LEN
                    continue
                self._cache__options.append(
                    {
                        TCP_OPT_MSS: TcpOptMss,
                        TCP_OPT_WSCALE: TcpOptWscale,
                        TCP_OPT_SACKPERM: TcpOptSackPerm,
                        TCP_OPT_TIMESTAMP: TcpOptTimestamp,
                    }.get(self._frame[optr], TcpOptUnk)(self._frame[optr:])
                )
                optr += self._frame[optr + 1]

        return self._cache__options

    @property
    def mss(self) -> int:
        """
        TCP option - Maximum Segment Size (2).
        """
        if "_cache__mss" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptMss):
                    self._cache__mss = option.mss
                    break
            else:
                self._cache__mss = 536
        return self._cache__mss

    @property
    def wscale(self) -> int | None:
        """
        TCP option - Window Scale (3).
        """
        if "_cache__wscale" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptWscale):
                    self._cache__wscale: int | None = 1 << option.wscale
                    break
            else:
                self._cache__wscale = None
        return self._cache__wscale

    @property
    def sackperm(self) -> bool | None:
        """
        TCP option - Sack Permit (4).
        """
        if "_cache__sackperm" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptSackPerm):
                    self._cache__sackperm: bool | None = True
                    break
            else:
                self._cache__sackperm = None
        return self._cache__sackperm

    @property
    def timestamp(self) -> tuple[int, int] | None:
        """
        TCP option - Timestamp (8).
        """
        if "_cache__timestamp" not in self.__dict__:
            for option in self.options:
                if isinstance(option, TcpOptTimestamp):
                    self._cache__timestamp: tuple[int, int] | None = (
                        option.tsval,
                        option.tsecr,
                    )
                    break
            else:
                self._cache__timestamp = None
        return self._cache__timestamp

    def _packet_integrity_check(self, pshdr_sum: int) -> str:
        """
        Packet integrity check to be run on raw frame prior to parsing
        to make sure parsing is safe.
        """

        if not config.PACKET_INTEGRITY_CHECK:
            return ""

        if inet_cksum(self._frame[: self._plen], pshdr_sum):
            return "TCP integrity - wrong packet checksum"

        if not TCP_HEADER_LEN <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (I)"

        hlen = (self._frame[12] & 0b11110000) >> 2
        if not TCP_HEADER_LEN <= hlen <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (II)"

        optr = TCP_HEADER_LEN
        while optr < hlen:
            if self._frame[optr] == TCP_OPT_EOL:
                break
            if self._frame[optr] == TCP_OPT_NOP:
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
        """
        Packet sanity check to be run on parsed packet to make sure packets's
        fields contain sane values.
        """

        if not config.PACKET_SANITY_CHECK:
            return ""

        if self.sport == 0:
            return "TCP sanity - 'sport' must be greater than 0"

        if self.dport == 0:
            return "TCP sanity - 'dport' must be greater than  0"

        if self.flag_syn and self.flag_fin:
            return (
                "TCP sanity - 'flag_syn' and 'flag_fin' must not be set "
                "simultaneously"
            )

        if self.flag_syn and self.flag_rst:
            return (
                "TCP sanity - 'flag_syn' and 'flag_rst' must not set "
                "simultaneously"
            )

        if self.flag_fin and self.flag_rst:
            return (
                "TCP sanity - 'flag_fin' and 'flag_rst' must not be set "
                "simultaneously"
            )

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
    """
    TCP option - End of TcpOption List (0).
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """
        self.kind = TCP_OPT_EOL

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


class TcpOptNop:
    """
    TCP option - No Operation (1).
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """
        self.kind = TCP_OPT_NOP

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


class TcpOptMss:
    """
    TCP option - Maximum Segment Size (2).
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """
        self.kind = frame[0]
        self.len = frame[1]
        self.mss: int = struct.unpack_from("!H", frame, 2)[0]

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"mss {self.mss}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return self.len


class TcpOptWscale:
    """
    TCP option - Window Scale (3).
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """
        self.kind = frame[0]
        self.len = frame[1]
        self.wscale = frame[2]

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"wscale {self.wscale}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return self.len


class TcpOptSackPerm:
    """
    TCP option - Sack Permit (4).
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """
        self.kind = frame[0]
        self.len = frame[1]

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "sack_perm"

    def __len__(self) -> int:
        """
        Option length.
        """
        return self.len


class TcpOptTimestamp:
    """
    TCP option - Timestamp (8).
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """
        self.kind = frame[0]
        self.len = frame[1]
        self.tsval: int = struct.unpack_from("!L", frame, 2)[0]
        self.tsecr: int = struct.unpack_from("!L", frame, 6)[0]

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"ts {self.tsval}/{self.tsecr}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return self.len


class TcpOptUnk:
    """
    TCP option not supported by this stack.
    """

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.data = frame[2 : self.len]

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"unk-{self.kind}-{self.len}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return self.len
