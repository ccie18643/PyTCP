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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpp_tcp.py - Fast Packet Parser support class for TCP protocol
#


import struct

import config
from ip_helper import inet_cksum

# TCP packet header (RFC 793)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hlen | Res |N|C|E|U|A|P|R|S|F|            Window             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP_HEADER_LEN = 20


class TcpPacket:
    """TCP packet support class"""

    class __not_cached:
        pass

    def __init__(self, packet_rx):
        """Class constructor"""

        packet_rx.tcp = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip.dlen

        self.__sport = self.__not_cached
        self.__dport = self.__not_cached
        self.__seq = self.__not_cached
        self.__ack = self.__not_cached
        self.__hlen = self.__not_cached
        self.__flag_ns = self.__not_cached
        self.__flag_crw = self.__not_cached
        self.__flag_ece = self.__not_cached
        self.__flag_urg = self.__not_cached
        self.__flag_ack = self.__not_cached
        self.__flag_psh = self.__not_cached
        self.__flag_rst = self.__not_cached
        self.__flag_syn = self.__not_cached
        self.__flag_fin = self.__not_cached
        self.__win = self.__not_cached
        self.__cksum = self.__not_cached
        self.__urg = self.__not_cached
        self.__data = self.__not_cached
        self.__olen = self.__not_cached
        self.__options = self.__not_cached
        self.__header_copy = self.__not_cached
        self.__options_copy = self.__not_cached
        self.__data_copy = self.__not_cached
        self.__packet_copy = self.__not_cached
        self.__mss = self.__not_cached
        self.__wscale = self.__not_cached
        self.__sackperm = self.__not_cached
        self.__timestamp = self.__not_cached

        packet_rx.parse_failed = self._packet_integrity_check(packet_rx.ip.pshdr_sum) or self._packet_sanity_check()

        if packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + self.hlen

    def __str__(self):
        """Packet log string"""

        log = (
            f"TCP {self.sport} > {self.dport}, {'N' if self.flag_ns else ''}{'C' if self.flag_crw else ''}"
            + f"{'E' if self.flag_ece else ''}{'U' if self.flag_urg else ''}{'A' if self.flag_ack else ''}"
            + f"{'P' if self.flag_psh else ''}{'R' if self.flag_rst else ''}{'S' if self.flag_syn else ''}"
            + f"{'F' if self.flag_fin else ''}, seq {self.seq}, ack {self.ack}, win {self.win}, dlen {self.dlen}"
        )

        for option in self.options:
            log += ", " + str(option)

        return log

    def __len__(self):
        """Packet length"""

        return len(self._frame) - self._hptr

    @property
    def sport(self):
        """Read 'Source port' field"""

        if self.__sport is self.__not_cached:
            self.__sport = struct.unpack_from("!H", self._frame, self._hptr + 0)[0]
        return self.__sport

    @property
    def dport(self):
        """Read 'Destianation port' field"""

        if self.__dport is self.__not_cached:
            self.__dport = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self.__dport

    @property
    def seq(self):
        """Read 'Sequence number' field"""

        if self.__seq is self.__not_cached:
            self.__seq = struct.unpack_from("!L", self._frame, self._hptr + 4)[0]
        return self.__seq

    @property
    def ack(self):
        """Read 'Acknowledge number' field"""

        if self.__ack is self.__not_cached:
            self.__ack = struct.unpack_from("!L", self._frame, self._hptr + 8)[0]
        return self.__ack

    @property
    def hlen(self):
        """Read 'Header length' field"""

        if self.__hlen is self.__not_cached:
            self.__hlen = (self._frame[self._hptr + 12] & 0b11110000) >> 2
        return self.__hlen

    @property
    def flag_ns(self):
        """Read 'NS flag' field"""

        if self.__flag_ns is self.__not_cached:
            self.__flag_ns = bool(self._frame[self._hptr + 12] & 0b00000001)
        return self.__flag_ns

    @property
    def flag_crw(self):
        """Read 'CRW flag' field"""

        if self.__flag_crw is self.__not_cached:
            self.__flag_crw = bool(self._frame[self._hptr + 13] & 0b10000000)
        return self.__flag_crw

    @property
    def flag_ece(self):
        """Read 'ECE flag' field"""

        if self.__flag_ece is self.__not_cached:
            self.__flag_ece = bool(self._frame[self._hptr + 13] & 0b01000000)
        return self.__flag_ece

    @property
    def flag_urg(self):
        """Read 'URG flag' field"""

        if self.__flag_urg is self.__not_cached:
            self.__flag_urg = bool(self._frame[self._hptr + 13] & 0b00100000)
        return self.__flag_urg

    @property
    def flag_ack(self):
        """Read 'ACK flag' field"""

        if self.__flag_ack is self.__not_cached:
            self.__flag_ack = bool(self._frame[self._hptr + 13] & 0b00010000)
        return self.__flag_ack

    @property
    def flag_psh(self):
        """Read 'PSH flag' field"""

        if self.__flag_psh is self.__not_cached:
            self.__flag_psh = bool(self._frame[self._hptr + 13] & 0b00001000)
        return self.__flag_psh

    @property
    def flag_rst(self):
        """Read 'RST flag' field"""

        if self.__flag_rst is self.__not_cached:
            self.__flag_rst = bool(self._frame[self._hptr + 13] & 0b00000100)
        return self.__flag_rst

    @property
    def flag_syn(self):
        """Read 'SYN flag' field"""

        if self.__flag_syn is self.__not_cached:
            self.__flag_syn = bool(self._frame[self._hptr + 13] & 0b00000010)
        return self.__flag_syn

    @property
    def flag_fin(self):
        """Read 'FIN flag' field"""

        if self.__flag_fin is self.__not_cached:
            self.__flag_fin = bool(self._frame[self._hptr + 13] & 0b00000001)
        return self.__flag_fin

    @property
    def win(self):
        """Read 'Window' field"""

        if self.__win is self.__not_cached:
            self.__win = struct.unpack_from("!H", self._frame, self._hptr + 14)[0]
        return self.__win

    @property
    def cksum(self):
        """Read 'Checksum' field"""

        if self.__cksum is self.__not_cached:
            self.__cksum = struct.unpack_from("!H", self._frame, self._hptr + 16)[0]
        return self.__cksum

    @property
    def urg(self):
        """Read 'Urgent pointer' field"""

        if self.__urg is self.__not_cached:
            self.__urg = struct.unpack_from("!H", self._frame, self._hptr + 18)[0]
        return self.__urg

    @property
    def data(self):
        """Read the data packet carries"""

        if self.__data is self.__not_cached:
            self.__data = self._frame[self._hptr + self.hlen : self._hptr + self.plen]
        return self.__data

    @property
    def olen(self):
        """Calculate options length"""

        if self.__olen is self.__not_cached:
            self.__olen = self.hlen - TCP_HEADER_LEN
        return self.__olen

    @property
    def dlen(self):
        """Calculate data length"""

        return self._plen - self.hlen

    @property
    def plen(self):
        """Calculate packet length"""

        return self._plen

    @property
    def header_copy(self):
        """Return copy of packet header"""

        if self.__header_copy is self.__not_cached:
            self.__header_copy = self._frame[self._hptr : self._hptr + TCP_HEADER_LEN]
        return self.__header_copy

    @property
    def options_copy(self):
        """Return copy of packet header"""

        if self.__options_copy is self.__not_cached:
            self.__options_copy = self._frame[self._hptr + TCP_HEADER_LEN : self._hptr + self.hlen]
        return self.__options_copy

    @property
    def data_copy(self):
        """Return copy of packet data"""

        if self.__data_copy is self.__not_cached:
            self.__data_copy = self._frame[self._hptr + self.hlen : self._hptr + self.plen]
        return self.__data_copy

    @property
    def packet_copy(self):
        """Return copy of whole packet"""

        if self.__packet_copy is self.__not_cached:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    @property
    def options(self):
        """Read list of options"""

        if self.__options is self.__not_cached:
            self.__options = []
            optr = self._hptr + TCP_HEADER_LEN
            while optr < self._hptr + self.hlen:
                if self._frame[optr] == TCP_OPT_EOL:
                    self.__options.append(TcpOptEol())
                    break
                if self._frame[optr] == TCP_OPT_NOP:
                    self.__options.append(TcpOptNop())
                    optr += TCP_OPT_NOP_LEN
                    continue
                self.__options.append(
                    {TCP_OPT_MSS: TcpOptMss, TCP_OPT_WSCALE: TcpOptWscale, TCP_OPT_SACKPERM: TcpOptSackPerm, TCP_OPT_TIMESTAMP: TcpOptTimestamp}.get(
                        self._frame[optr], TcpOptUnk
                    )(self._frame, optr)
                )
                optr += self._frame[optr + 1]

        return self.__options

    @property
    def mss(self):
        """TCP option - Maximum Segment Size (2)"""

        if self.__mss is self.__not_cached:
            for option in self.options:
                if option.kind == TCP_OPT_MSS:
                    self.__mss = option.mss
                    break
            else:
                self.__mss = 536
        return self.__mss

    @property
    def wscale(self):
        """TCP option - Window Scale (3)"""

        if self.__wscale is self.__not_cached:
            for option in self.options:
                if option.kind == TCP_OPT_WSCALE:
                    self.__wscale = 1 << option.wscale
                    break
            else:
                self.__wscale = None
        return self.__wscale

    @property
    def sackperm(self):
        """TCP option - Sack Permit (4)"""

        if self.__sackperm is self.__not_cached:
            for option in self.options:
                if option.kind == TCP_OPT_SACKPERM:
                    self.__sackperm = True
                    break
            else:
                self.__sackperm = None
        return self.__sackperm

    @property
    def timestamp(self):
        """TCP option - Timestamp (8)"""

        if self.__timestamp is self.__not_cached:
            for option in self.options:
                if option.kind == TCP_OPT_TIMESTAMP:
                    self.__timestamp = (option.tsval, option.tsecr)
                    break
            else:
                self.__timestamp = None
        return self.__timestamp

    def _packet_integrity_check(self, pshdr_sum):
        """Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return False

        if inet_cksum(self._frame, self._hptr, self._plen, pshdr_sum):
            return "TCP integrity - wrong packet checksum"

        if not TCP_HEADER_LEN <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (I)"

        hlen = (self._frame[self._hptr + 12] & 0b11110000) >> 2
        if not TCP_HEADER_LEN <= hlen <= self._plen <= len(self):
            return "TCP integrity - wrong packet length (II)"

        optr = self._hptr + TCP_HEADER_LEN
        while optr < self._hptr + hlen:
            if self._frame[optr] == TCP_OPT_EOL:
                break
            if self._frame[optr] == TCP_OPT_NOP:
                optr += 1
                if optr > self._hptr + hlen:
                    return "TCP integrity - wrong option length (I)"
                continue
            if optr + 1 > self._hptr + hlen:
                return "TCP integrity - wrong option length (II)"
            if self._frame[optr + 1] == 0:
                return "TCP integrity - wrong option length (III)"
            optr += self._frame[optr + 1]
            if optr > self._hptr + hlen:
                return "TCP integrity - wrong option length (IV)"

        return False

    def _packet_sanity_check(self):
        """Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values"""

        if not config.packet_sanity_check:
            return False

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

        return False


#
# TCP options
#


# TCP option - End of Option List (0)

TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1


class TcpOptEol:
    """TCP option - End of Option List (0)"""

    def __init__(self):
        self.kind = TCP_OPT_EOL

    def __str__(self):
        return "eol"


# TCP option - No Operation (1)

TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1


class TcpOptNop:
    """TCP option - No Operation (1)"""

    def __init__(self):
        self.kind = TCP_OPT_NOP

    def __str__(self):
        return "nop"


# TCP option - Maximum Segment Size (2)

TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4


class TcpOptMss:
    """TCP option - Maximum Segment Size (2)"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.mss = struct.unpack_from("!H", frame, optr + 2)[0]

    def __str__(self):
        return f"mss {self.mss}"


# TCP option - Window Scale (3)

TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3


class TcpOptWscale:
    """TCP option - Window Scale (3)"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.wscale = frame[optr + 2]

    def __str__(self):
        return f"wscale {self.wscale}"


# TCP option - Sack Permit (4)

TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2


class TcpOptSackPerm:
    """TCP option - Sack Permit (4)"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]

    def __str__(self):
        return "sack_perm"


# TCP option - Timestamp

TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10


class TcpOptTimestamp:
    """TCP option - Timestamp (8)"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.tsval = struct.unpack_from("!L", frame, optr + 2)[0]
        self.tsecr = struct.unpack_from("!L", frame, optr + 6)[0]

    def __str__(self):
        return f"ts {self.tsval}/{self.tsecr}"


# TCP option not supported by this stack


class TcpOptUnk:
    """TCP option not supported by this stack"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.data = frame[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.kind}-{self.len}"
