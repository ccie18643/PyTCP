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
# tcp/ps.py - protocol support for TCP
#


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


HEADER_LEN = 20


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


#
# TCP options
#


# TCP option - End of Option List (0)

OPT_EOL = 0
OPT_EOL_LEN = 1


class OptEol:
    """TCP option - End of Option List (0)"""

    def __str__(self) -> str:
        """Option log string"""

        return "eol"

    def __len__(self) -> int:
        """Option length"""

        return OPT_EOL_LEN


# TCP option - No Operation (1)

OPT_NOP = 1
OPT_NOP_LEN = 1


class OptNop:
    """TCP option - No Operation (1)"""

    def __str__(self) -> str:
        """Option log string"""

        return "nop"

    def __len__(self) -> int:
        """Option length"""

        return OPT_NOP_LEN


# TCP option - Maximum Segment Size (2)

OPT_MSS = 2
OPT_MSS_LEN = 4


class OptMss:
    """TCP option - Maximum Segment Size (2)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.mss = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"mss {self.mss}"

    def __len__(self) -> int:
        """Option length"""

        return OPT_MSS_LEN


# TCP option - Window Scale (3)

OPT_WSCALE = 3
OPT_WSCALE_LEN = 3


class OptWscale:
    """TCP option - Window Scale (3)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.wscale = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"wscale {self.wscale}"

    def __len__(self) -> int:
        """Option length"""

        return OPT_WSCALE_LEN


# TCP option - Sack Permit (4)

OPT_SACKPERM = 4
OPT_SACKPERM_LEN = 2


class OptSackPerm:
    """TCP option - Sack Permit (4)"""

    def __str__(self) -> str:
        """Option log string"""

        return "sack_perm"

    def __len__(self) -> int:
        """Option length"""

        return OPT_SACKPERM_LEN


# TCP option - Timestamp

OPT_TIMESTAMP = 8
OPT_TIMESTAMP_LEN = 10


class OptTimestamp:
    """TCP option - Timestamp (8)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.tsval = -1
        self.tsecr = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"ts {self.tsval}/{self.tsecr}"

    def __len__(self) -> int:
        """Option length"""

        return OPT_TIMESTAMP_LEN


# TCP unknown option


class OptUnk:
    """TCP option not supported by this stack"""

    def __init__(self) -> None:
        """Class constructor"""

        self.kind = -1
        self.len = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"unk-{self.kind}-{self.len}"
