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
Module contains packet structure information for the ICMPv6 protccol.

pytcp/protocols/icmp6/ps.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.enum import ProtoEnum
from pytcp.lib.ip6_address import Ip6Address, Ip6Network
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import Proto
from pytcp.protocols.ip6.ps import IP6_HEADER_LEN, IP6_MIN_MTU

# Destination Unreachable message (1/[0-6])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Packet Too Big message (2/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             MTU                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Time Exceeded (3/[0-1])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Unused                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Parameter Problem message (4/[0-2])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Pointer                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Echo Request message (128/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Reply message (129/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# MLDv2 - Multicast Listener Query message (130/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Maximum Response Code      |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               *
# |                                                               |
# +                       Multicast Address                       *
# |                                                               |
# +                                                               *
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Router Solicitation message (133/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Reserved                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Router Advertisement message (134/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hop Limit   |M|O|H|PRF|P|0|0|        Router Lifetime        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Reachable Time                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Retrans Timer                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Solicitation message (135/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Advertisement message (136/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |R|S|O|                     Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-

# TODO: Add ICMPv6 Redirect Message. (137/0)
# TODO: Add ICMPv6 Router Renumbering Message. (138/[0, 1, 255])

# MLDv2 - Multicast Listener Report message (143/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |Nr of Mcast Address Records (M)|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [1]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [2]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [M]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Each Multicast Address Record has the following internal format:

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Multicast Address                       +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                         Auxiliary Data                        ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


#
#   ICMPv6 Neighbor Discovery options
#


# ICMPv6 ND option - Source Link Layer Address (1)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# ICMPv6 ND option - Target Link Layer Address (2)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# ICMPv6 ND option - Prefix Information (3)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     | Prefix Length |L|A|R|   Res1  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Valid Lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Preferred Lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved2                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Prefix                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# TODO: Add ICMPv6 Redirected Header Option (4).
# TODO: Add ICMPv6 MTU Option (5).

ICMP6_HEADER_LEN = 4

ICMP6_MESSAGE_LEN__UNREACHABLE = 8
ICMP6_MESSAGE_LEN__PACKET_TOO_BIG = 8
ICMP6_MESSAGE_LEN__TIME_EXCEEDED = 8
ICMP6_MESSAGE_LEN__PARAMETER_PROBLEM = 8
ICMP6_MESSAGE_LEN__ECHO_REQUEST = 8
ICMP6_MESSAGE_LEN__ECHO_REPLY = 8
ICMP6_MESSAGE_LEN__MLD2_QUERY = 28
ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION = 8
ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT = 16
ICMP6_MESSAGE_LEN__ND_NEIGHBOR_SOLICITATION = 24
ICMP6_MESSAGE_LEN__ND_NEIGHBOR_ADVERTISEMENT = 24
ICMP6_MESSAGE_LEN__MLD2_REPORT = 4

ICMP6_ND_OPT_LEN__SLLA = 8
ICMP6_ND_OPT_LEN__TLLA = 8
ICMP6_ND_OPT_LEN__PI = 32

ICMP6_MLD2_RECORD_LEN = 20

ICMP6_UNREACHABLE_ORIGINAL_DATAGRAM_LEN = (
    IP6_MIN_MTU - IP6_HEADER_LEN - ICMP6_MESSAGE_LEN__UNREACHABLE
)


class Icmp6Mld2RecordType(ProtoEnum):
    MODE_IS_INCLUDE = 1
    MODE_IS_EXCLUDE = 2
    CHANGE_TO_INCLUDE = 3
    CHANGE_TO_EXCLUDE = 4
    ALLOW_NEW_SOURCES = 5
    BLOCK_OLD_SOURCES = 6


class Icmp6NdOptCode(ProtoEnum):
    SLLA = 1
    TLLA = 2
    PI = 3

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[0])


class Icmp6Type(ProtoEnum):
    UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    MLD2_QUERY = 130
    ND_ROUTER_SOLICITATION = 133
    ND_ROUTER_ADVERTISEMENT = 134
    ND_NEIGHBOR_SOLICITATION = 135
    ND_NEIGHBOR_ADVERTISEMENT = 136
    MLD2_REPORT = 143

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[0])


class Icmp6Code(ProtoEnum):
    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[1])


class Icmp6UnreachableCode(Icmp6Code):
    NO_ROUTE = 0
    PROHIBITED = 1
    SCOPE = 2
    ADDRESS = 3
    PORT = 4
    FAILED_POLICY = 5
    REJECT_ROUTE = 6


class Icmp6PacketTooBigCode(Icmp6Code):
    DEFAULT = 0


class Icmp6TimeExceededCode(Icmp6Code):
    HOP_LIMIT_EXCEEDED = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1


class Icmp6ParameterProblemCode(Icmp6Code):
    ERRONEOUS_HEADER_FIELD = 0
    UNRECOGNIZED_NEXT_HEADER_TYPE = 1
    UNRECOGNIZED_IPV6_OPTION = 2


class Icmp6EchoRequestCode(Icmp6Code):
    DEFAULT = 0


class Icmp6EchoReplyCode(Icmp6Code):
    DEFAULT = 0


class Icmp6Mld2QueryCode(Icmp6Code):
    DEFAULT = 0


class Icmp6NdRouterSolicitationCode(Icmp6Code):
    DEFAULT = 0


class Icmp6NdRouterAdvertisementCode(Icmp6Code):
    DEFAULT = 0


class Icmp6NdNeighborSolicitationCode(Icmp6Code):
    DEFAULT = 0


class Icmp6NdNeighborAdvertisementCode(Icmp6Code):
    DEFAULT = 0


class Icmp6Mld2ReportCode(Icmp6Code):
    DEFAULT = 0


class Icmp6(Proto):
    """
    Base class for ICMPv6 packet parser and assembler classes.
    """

    _message: Icmp6Message

    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        return str(self._message)

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return repr(self._message)

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return bytes(self._message)

    @property
    def type(self) -> Icmp6Type:
        """
        Get the '_type' property.
        """

        return self._message.type

    @property
    def code(self) -> Icmp6Code:
        """
        Get the '_code' property.
        """

        return self._message.code

    @property
    def message(
        self,
    ) -> Icmp6Message:
        """
        Get the '_message' property.
        """

        return self._message


#
#  The ICMPv6 message classes.
#


class Icmp6Message(Proto):
    """
    Base class for ICMPv6 message.
    """

    _type: Icmp6Type
    _code: Icmp6Code
    _cksum: int

    @property
    def type(self) -> Icmp6Type:
        """
        Get the '_type' property.
        """

        return self._type

    @property
    def code(self) -> Icmp6Code:
        """
        Get the '_code' property.
        """

        return self._code

    @property
    def cksum(self) -> int:
        """
        Get the '_cksum' property.
        """

        return self._cksum


class Icmp6NdMessage(Icmp6Message):
    """
    Base class for ICMPv6 Neighbor Discovery message.
    """

    _type: Icmp6Type
    _nd_options: list[Icmp6NdOpt]

    @property
    def _raw_nd_options(self) -> bytes:
        """
        Get the ND options in raw format.
        """

        return b"".join(bytes(nd_option) for nd_option in self._nd_options)

    @property
    def nd_options(self) -> list[Icmp6NdOpt]:
        """
        Get the '_nd_options' property.
        """

        return self._nd_options

    @property
    def opt_slla(self) -> MacAddress | None:
        """
        Get the Source Link Layer Address option.
        """

        # TODO: Option getters should be redone to get list of
        # the requested options to be further processed
        # by the caller.

        for option in self._nd_options:
            if isinstance(option, Icmp6NdOptSlla):
                return option.slla

        return None

    @property
    def opt_tlla(self) -> MacAddress | None:
        """
        Get the Target Link Layer Address option.
        """

        # TODO: Option getters should be redone to get list of
        # the requested options to be further processed
        # by the caller.

        for option in self._nd_options:
            if isinstance(option, Icmp6NdOptTlla):
                return option.tlla

        return None

    @property
    def opt_pi(self) -> list[Ip6Network]:
        """
        Get the Prefix Information option.
        """

        # TODO: Option getters should be redone to get list of
        # the requested options to be further processed
        # by the caller.

        prefixes = []

        for option in self._nd_options:
            if isinstance(option, Icmp6NdOptPi):
                prefixes.append(option.prefix)

        return prefixes


class Icmp6UnreachableMessage(Icmp6Message):
    """
    Base class for the ICMPv6 Unreachable messages.
    """

    _type = Icmp6Type.UNREACHABLE
    _code: Icmp6UnreachableCode

    _reserved = 0
    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__UNREACHABLE + len(self._data)

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH L {len(self._data)}s",
            int(self._type),
            int(self._code),
            0,
            self._reserved,
            bytes(self._data),
        )

    @property
    def data(self) -> bytes:
        """
        Getter for the '_data' property.
        """

        return self._data


class Icmp6PortUnreachableMessage(Icmp6UnreachableMessage):
    """
    Base class for the ICMPv6 Port Unreachable message.
    """

    _type = Icmp6Type.UNREACHABLE
    _code = Icmp6UnreachableCode.PORT

    _reserved = 0
    _data: bytes

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return f"ICMPv6 Port Unreachable, dlen {len(self._data)}"

    def __repr__(self) -> str:
        """
        Get the message representation string.
        """

        return f"Icmp6PortUnreachableMessage(data={repr(self._data)})"


class Icmp6EchoRequestMessage(Icmp6Message):
    """
    Base class for ICMPv6 Echo Request message.
    """

    _type = Icmp6Type.ECHO_REQUEST
    _code = Icmp6EchoRequestCode.DEFAULT

    _id: int
    _seq: int
    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__ECHO_REQUEST + len(self._data)

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            f"ICMPv6 Echo Request, id {self._id}, "
            f"seq {self._seq}, dlen {len(self._data)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6EchoRequestMessage("
            f"id={repr(self._id)}, "
            f"seq={repr(self._seq)}, "
            f"data={repr(self._data)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH HH {len(self._data)}s",
            int(self._type),
            int(self._code),
            0,
            self._id,
            self._seq,
            bytes(self._data),
        )

    @property
    def id(self) -> int:
        """
        Get the '_id' property.
        """

        return self._id

    @property
    def seq(self) -> int:
        """
        Get the '_seq' property.
        """

        return self._seq

    @property
    def data(self) -> bytes:
        """
        Get the '_data' property.
        """

        return self._data


class Icmp6EchoReplyMessage(Icmp6Message):
    """
    Base class for ICMPv6 Echo Reply message.
    """

    _type = Icmp6Type.ECHO_REPLY
    _code = Icmp6EchoReplyCode.DEFAULT

    _id: int
    _seq: int
    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__ECHO_REPLY + len(self._data)

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            f"ICMPv6 Echo Reply, id {self._id}, seq {self._seq}, "
            f"dlen {len(self._data)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6EchoReplyMessage("
            f"id={repr(self._id)}, "
            f"seq={repr(self._seq)}, "
            f"data={repr(self._data)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH HH {len(self._data)}s",
            int(self._type),
            int(self._code),
            0,
            self._id,
            self._seq,
            bytes(self._data),
        )

    @property
    def id(self) -> int:
        """
        Get the '_id' property.
        """

        return self._id

    @property
    def seq(self) -> int:
        """
        Get the '_seq' property.
        """

        return self._seq

    @property
    def data(self) -> bytes:
        """
        Get the '_data' property.
        """

        return self._data


class Icmp6NdRouterSolicitationMessage(Icmp6NdMessage):
    """
    Base class for ICMPv6 ND Router Solicitation message.
    """

    _type = Icmp6Type.ND_ROUTER_SOLICITATION
    _code = Icmp6NdRouterSolicitationCode.DEFAULT

    _reserved: int
    _nd_options: list[Icmp6NdOpt]

    def __len__(self) -> int:
        """
        Get the messeage length.
        """

        return ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION + sum(
            len(option) for option in self._nd_options
        )

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            f"ICMPv6 ND Router Solicitation, "
            f"{', '.join(str(nd_option) for nd_option in self._nd_options)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6NdRouterSolicitationMessage("
            f"{', '.join(repr(nd_option) for nd_option in self._nd_options)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH L {len(self._raw_nd_options)}s",
            int(self._type),
            int(self._code),
            0,
            self._reserved,
            self._raw_nd_options,
        )


class Icmp6NdRouterAdvertisementMessage(Icmp6NdMessage):
    """
    Base class for ICMPv6 ND Router Advertisement message.
    """

    _type = Icmp6Type.ND_ROUTER_ADVERTISEMENT
    _code = Icmp6NdRouterAdvertisementCode.DEFAULT

    _hop: int
    _flag_m: bool
    _flag_o: bool
    _router_lifetime: int
    _reachable_time: int
    _retrans_timer: int
    _nd_options: list[Icmp6NdOpt]

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT + sum(
            len(option) for option in self._nd_options
        )

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            "ICMPv6 ND Router Advertisement, "
            f"hop {self._hop}, "
            "flags "
            f"{'M' if self._flag_m else '-'}"
            f"{'O' if self._flag_o else '-'}, "
            f"rlft {self._router_lifetime}, "
            f"reacht {self._reachable_time}, "
            f"retrt {self._retrans_timer}, "
            f"{', '.join(str(nd_option) for nd_option in self._nd_options)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6NdRouterAdvertisementMessage("
            f"hop={repr(self._hop)}, "
            f"flag_m={repr(self._flag_m)}, "
            f"flag_o={repr(self._flag_o)}, "
            f"rlft={repr(self._router_lifetime)}, "
            f"reacht={repr(self._reachable_time)}, "
            f"retrt={repr(self._retrans_timer)}, "
            f"{', '.join(repr(nd_option) for nd_option in self._nd_options)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH BBH L L {len(self._raw_nd_options)}s",
            int(self._type),
            int(self._code),
            0,
            self._hop,
            (self._flag_m << 7) | (self._flag_o << 6),
            self._router_lifetime,
            self._reachable_time,
            self._retrans_timer,
            self._raw_nd_options,
        )

    @property
    def hop(self) -> int:
        """
        Get the '_hop' property.
        """

        return self._hop

    @property
    def flag_m(self) -> bool:
        """
        Get the '_flag_m' property.
        """

        return self._flag_m

    @property
    def flag_o(self) -> bool:
        """
        Get the '_flag_o' property.
        """

        return self._flag_o

    @property
    def router_lifetime(self) -> int:
        """
        Get the '_router_lifetime' property.
        """

        return self._router_lifetime

    @property
    def reachable_time(self) -> int:
        """
        Get the '_reachable_time' property.
        """

        return self._reachable_time

    @property
    def retrans_timer(self) -> int:
        """
        Get the '_retrans_timer' property.
        """

        return self._retrans_timer


class Icmp6NdNeighborSolicitationMessage(Icmp6NdMessage):
    """
    Base class for ICMPv6 ND Neighbor Solicitation message.
    """

    _type = Icmp6Type.ND_NEIGHBOR_SOLICITATION
    _code = Icmp6NdNeighborSolicitationCode.DEFAULT

    _reserved: int
    _target_address: Ip6Address
    _nd_options: list[Icmp6NdOpt]

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__ND_NEIGHBOR_SOLICITATION + sum(
            len(option) for option in self._nd_options
        )

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            f"ICMP6 ND Neighbor Solicitation, "
            f"target {self._target_address}, "
            f"{', '.join(str(nd_option) for nd_option in self._nd_options)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6NdNeighborSolicitationMessage("
            f"target {repr(self._target_address)}, "
            f"{', '.join(repr(nd_option) for nd_option in self._nd_options)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH L 16s {len(self._raw_nd_options)}s",
            int(self._type),
            int(self._code),
            0,
            self._reserved,
            bytes(self._target_address),
            self._raw_nd_options,
        )

    @property
    def target_address(self) -> Ip6Address:
        """
        Get the target address.
        """

        return self._target_address


class Icmp6NdNeighborAdvertisementMessage(Icmp6NdMessage):
    """
    Base class for ICMPv6 ND Neighbor Advertisement message.
    """

    _type = Icmp6Type.ND_NEIGHBOR_ADVERTISEMENT
    _code = Icmp6NdNeighborAdvertisementCode.DEFAULT

    _reserved: int
    _flag_r: bool
    _flag_s: bool
    _flag_o: bool
    _target_address: Ip6Address
    _nd_options: list[Icmp6NdOpt]

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__ND_NEIGHBOR_ADVERTISEMENT + sum(
            len(option) for option in self._nd_options
        )

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return (
            "ICMPv6 ND Neighbor Advertisement, "
            "flags "
            f"{'R' if self._flag_r else '-'}"
            f"{'S' if self._flag_s else '-'}"
            f"{'O' if self._flag_o else '-'}, "
            f"target {self._target_address}, "
            f"{', '.join(str(nd_option) for nd_option in self._nd_options)}"
        )

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6NdNeighborAdvertisementMessage("
            f"flag_r={repr(self._flag_r)}, "
            f"flag_s={repr(self._flag_s)}, "
            f"flag_o={repr(self._flag_o)}, "
            f"target={repr(self._target_address)}, "
            f"{', '.join(repr(nd_option) for nd_option in self._nd_options)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH L 16s {len(self._raw_nd_options)}s",
            int(self._type),
            int(self._code),
            0,
            (self._flag_r << 31)
            | (self._flag_s << 30)
            | (self._flag_o << 29)
            | (self._reserved & 0b00011111_11111111_11111111_11111111),
            bytes(self._target_address),
            self._raw_nd_options,
        )

    @property
    def flag_r(self) -> bool:
        """
        Get the '_flag_r' property.
        """

        return self._flag_r

    @property
    def flag_s(self) -> bool:
        """
        Get the '_flag_s' property.
        """

        return self._flag_s

    @property
    def flag_o(self) -> bool:
        """
        Get the '_flag_o' property.
        """

        return self._flag_o

    @property
    def target_address(self) -> Ip6Address:
        """
        Get the '_target_address' property.
        """

        return self._target_address


class Icmp6Mld2ReportMessage(Icmp6Message):
    """
    Base class for ICMPv6 ND MLD2 Report message.
    """

    _type = Icmp6Type.MLD2_REPORT
    _code = Icmp6Mld2ReportCode.DEFAULT

    _reserved: int
    _nor: int
    _records: list[Icmp6Mld2AddressRecord]

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP6_MESSAGE_LEN__MLD2_REPORT + sum(
            len(record) for record in self._records
        )

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        # TODO: Could perhaps put some more info here.

        return "ICMPv6 MLD2 Report"

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6Mld2ReportMessage("
            f"{', '.join(repr(record) for record in self._records)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        return struct.pack(
            f"! BBH HH {sum((len(record) for record in self._records))}s",
            int(self._type),
            int(self._code),
            0,
            self._reserved,
            len(self._records),
            b"".join([bytes(record) for record in self._records]),
        )

    @property
    def records(self) -> list[Icmp6Mld2AddressRecord]:
        """
        Get the '_records' property.
        """

        return self._records


class Icmp6UnknownMessage(Icmp6Message):
    """
    Base class for ICMPv6 unknown message.
    """

    _type: Icmp6Type
    _code: Icmp6Code

    def __len__(self) -> int:
        """
        Get the message length.
        """

        raise NotImplementedError

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return f"ICMPv6 Unknown Message, type {self._type}, code {self._code}"

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp6UnknownMessage("
            f"type={repr(self._type)}, "
            f"code={repr(self._code)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        raise NotImplementedError


#
#   ICMPv6 Neighbor Discovery options.
#


class Icmp6NdOpt(Proto):
    """
    Base class for ICMPv6 ND option.
    """

    _code: Icmp6NdOptCode
    _len: int

    def __len__(self) -> int:
        """
        Get the option length.
        """

        return self._len

    @property
    def code(self) -> Icmp6NdOptCode:
        """
        Get the '_code' property.
        """

        return self._code

    @property
    def len(self) -> int:
        """
        Get the '_len' property.
        """

        return self._len


class Icmp6NdOptSlla(Icmp6NdOpt):
    """
    The ICMPv6 ND option - Source Link Layer Address (1).
    """

    _code = Icmp6NdOptCode.SLLA
    _len = ICMP6_ND_OPT_LEN__SLLA

    _slla: MacAddress

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return f"slla {self._slla}"

    def __repr__(self) -> str:
        """
        Get the option representation.
        """

        return f"Icmp6NdOptSlla(slla={repr(self._slla)})"

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack(
            "! BB 6s",
            int(self._code),
            self._len >> 3,
            bytes(self._slla),
        )

    @property
    def slla(self) -> MacAddress:
        """
        Get the '_slla' property.
        """

        return self._slla


class Icmp6NdOptTlla(Icmp6NdOpt):
    """
    Class for the ICMPv6 ND option - Target Link Layer Address (2).
    """

    _code = Icmp6NdOptCode.TLLA
    _len = ICMP6_ND_OPT_LEN__TLLA

    _tlla: MacAddress

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return f"tlla {self._tlla}"

    def __repr__(self) -> str:
        """
        Get the option representation.
        """

        return f"Icmp6NdOptTlla(tlla={repr(self._tlla)})"

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack(
            "! BB 6s",
            int(self._code),
            self._len >> 3,
            bytes(self._tlla),
        )

    @property
    def tlla(self) -> MacAddress:
        """
        Get the '_tlla' property.
        """

        return self._tlla


class Icmp6NdOptPi(Icmp6NdOpt):
    """
    Class for the ICMPv6 ND option - Prefix Information (3).
    """

    _code = Icmp6NdOptCode.PI
    _len = ICMP6_ND_OPT_LEN__PI

    _flag_l: bool
    _flag_a: bool
    _flag_r: bool
    _reserved_1: int
    _valid_lifetime: int
    _preferred_lifetime: int
    _reserved_2: int
    _prefix: Ip6Network

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        # TODO: Update the option string to show all data.

        return f"prefix_info {self._prefix}"

    def __repr__(self) -> str:
        """
        Get the ption representation.
        """

        return (
            f"Icmp6NdOptIp("
            f"flag_l={repr(self._flag_l)}, "
            f"flag_a={repr(self._flag_a)}, "
            f"flag_r={repr(self._flag_r)}, "
            f"valid_lifetime={repr(self._valid_lifetime)}, "
            f"prefer_lifetime={repr(self._preferred_lifetime)}, "
            f"prefix={repr(self._prefix)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack(
            "! BB BB L L L 16s",
            int(self._code),
            self._len >> 3,
            len(self._prefix.mask),
            (self._flag_l << 7)
            | (self._flag_a << 6)
            | (self._flag_r << 6)
            | (self._reserved_1 & 0b00011111),
            self._valid_lifetime,
            self._preferred_lifetime,
            self._reserved_2,
            bytes(self._prefix.address),
        )

    @property
    def flag_l(self) -> bool:
        """
        Get the '_flag_l' property.
        """

        return self._flag_l

    @property
    def flag_a(self) -> bool:
        """
        Get the '_flag_a' property.
        """

        return self._flag_a

    @property
    def flag_r(self) -> bool:
        """
        Get the '_flag_r' property.
        """

        return self._flag_r

    @property
    def valid_lifetime(self) -> int:
        """
        Get the '_valid_lifetime' property.
        """

        return self._valid_lifetime

    @property
    def preferred_lifetime(self) -> int:
        """
        Get the '_preferred_lifetime' property.
        """

        return self._preferred_lifetime

    @property
    def prefix(self) -> Ip6Network:
        """
        Get the '_prefix' property.
        """

        return self._prefix


class Icmp6NdOptUnk(Icmp6NdOpt):
    """
    Class for the ICMPv6 ND unknown option.
    """

    _code: Icmp6NdOptCode
    _len: int

    _data: bytes

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return f"unk-{self._code}-{self._len}"

    def __repr__(self) -> str:
        """
        Get the option representation.
        """

        return (
            f"Icmp6NdOptUnk("
            f"code={repr(self._code)}, "
            f"len={repr(self._len)}, "
            f"data={repr(self._data)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack(
            f"! BB {len(self._data)}s",
            self._code,
            self._len >> 3,
            bytes(self._data),
        )

    @property
    def data(self) -> bytes:
        """
        Get the '_data' property.
        """

        return self._data


#
#   ICMPv6 Multicast support classes
#


class Icmp6Mld2AddressRecord(Proto):
    """
    Multicast Address Record used by MLDv2 Report message.
    """

    _record_type: Icmp6Mld2RecordType
    _aux_data: bytes
    _aux_data_len: int
    _number_of_sources: int
    _multicast_address: Ip6Address
    _source_addresses: list[Ip6Address]

    def __len__(self) -> int:
        """
        Get the length of record.
        """

        return 4 + 32 + 32 * self._number_of_sources + self._aux_data_len

    def __str__(self) -> str:
        """
        Get the record log string.
        """

        # TODO: Implement this method.

        raise NotImplementedError

    def __repr__(self) -> str:
        """
        Get the record representation.
        """

        return (
            f"Icmp6MulticastAddressRecord("
            f"record_type={repr(self._record_type)}, "
            f"multicast_address={repr(self._multicast_address)}, "
            f"source_addresses={repr(self._source_addresses)}, "
            f"aux_data={repr(self._aux_data)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the record in raw format.
        """

        return (
            struct.pack(
                "! BBH 16s",
                int(self._record_type),
                self._aux_data_len,
                self._number_of_sources,
                bytes(self._multicast_address),
            )
            + b"".join(
                [
                    bytes(source_address)
                    for source_address in self._source_addresses
                ]
            )
            + self._aux_data
        )

    @property
    def multicast_address(self) -> Ip6Address:
        """
        Get the '_multicast_address' attribute.
        """

        return self._multicast_address
