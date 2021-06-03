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
# fpa_tcp.py - Fast Packet Assembler support class for TCP protocol
#


import struct

from ip_helper import inet_cksum
from tracker import Tracker

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

    protocol = "TCP"

    def __init__(
        self,
        sport,
        dport,
        seq=0,
        ack=0,
        flag_ns=False,
        flag_crw=False,
        flag_ece=False,
        flag_urg=False,
        flag_ack=False,
        flag_psh=False,
        flag_rst=False,
        flag_syn=False,
        flag_fin=False,
        win=0,
        urp=0,
        options=None,
        data=b"",
        echo_tracker=None,
    ):
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

        self.data = data

        self.hlen = TCP_HEADER_LEN + sum([len(_) for _ in self.options])

        assert self.hlen % 4 == 0, f"TCP header len {self.hlen} is not multiplcation of 4 bytes, check options... {self.options}"

    def __str__(self):
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

    def __len__(self):
        """Length of the packet"""

        return self.hlen + len(self.data)

    @property
    def raw_options(self):
        """Packet options in raw format"""

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    def assemble_packet(self, frame, hptr, pshdr_sum):
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


# TCP option - End of Option List (0)

TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1


class TcpOptEol:
    """TCP option - End of Option List (0)"""

    @property
    def raw_option(self):
        return struct.pack("!B", TCP_OPT_EOL)

    def __str__(self):
        return "eol"

    def __len__(self):
        return TCP_OPT_EOL_LEN


# TCP option - No Operation (1)

TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1


class TcpOptNop:
    """TCP option - No Operation (1)"""

    @property
    def raw_option(self):
        return struct.pack("!B", TCP_OPT_NOP)

    def __str__(self):
        return "nop"

    def __len__(self):
        return TCP_OPT_NOP_LEN


# TCP option - Maximum Segment Size (2)

TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4


class TcpOptMss:
    """TCP option - Maximum Segment Size (2)"""

    def __init__(self, mss):
        self.mss = mss

    @property
    def raw_option(self):
        return struct.pack("! BB H", TCP_OPT_MSS, TCP_OPT_MSS_LEN, self.mss)

    def __str__(self):
        return f"mss {self.mss}"

    def __len__(self):
        return TCP_OPT_MSS_LEN


# TCP option - Window Scale (3)

TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3


class TcpOptWscale:
    """TCP option - Window Scale (3)"""

    def __init__(self, wscale):
        self.wscale = wscale

    @property
    def raw_option(self):
        return struct.pack("! BB B", TCP_OPT_WSCALE, TCP_OPT_WSCALE_LEN, self.wscale)

    def __str__(self):
        return f"wscale {self.wscale}"

    def __len__(self):
        return TCP_OPT_WSCALE_LEN


# TCP option - Sack Permit (4)

TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2


class TcpOptSackPerm:
    """TCP option - Sack Permit (4)"""

    @property
    def raw_option(self):
        return struct.pack("! BB", TCP_OPT_SACKPERM, TCP_OPT_SACKPERM_LEN)

    def __str__(self):
        return "sack_perm"

    def __len__(self):
        return TCP_OPT_SACKPERM_LEN


# TCP option - Timestamp

TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10


class TcpOptTimestamp:
    """TCP option - Timestamp (8)"""

    def __init__(self, tsval, tsecr):
        self.tsval = tsval
        self.tsecr = tsecr

    @property
    def raw_option(self):
        return struct.pack("! BB LL", TCP_OPT_TIMESTAMP, TCP_OPT_TIMESTAMP_LEN, self.tsval, self.tsecr)

    def __str__(self):
        return f"ts {self.tsval}/{self.tsecr}"

    def __len__(self):
        return TCP_OPT_TIMESTAMP_LEN
