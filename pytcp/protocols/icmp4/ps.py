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
Module contains packet structure information for the ICMPv4 protccol.

pytcp/protocols/icmp4/ps.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.enum import ProtoEnum
from pytcp.lib.proto import Proto
from pytcp.protocols.ip4.ps import IP4_HEADER_LEN, IP4_MIN_MTU, Ip4Proto

# Echo reply message (0/0).

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP4_HEADER_LEN = 4

ICMP4_MESSAGE_LEN__ECHO_REPLY = 8
ICMP4_MESSAGE_LEN__UNREACHABLE = 8
ICMP4_MESSAGE_LEN__ECHO_REQUEST = 8

ICMP4_UNREACHABLE_ORIGINAL_DATAGRAM_LEN = (
    IP4_MIN_MTU - IP4_HEADER_LEN - ICMP4_MESSAGE_LEN__UNREACHABLE
)


class Icmp4Type(ProtoEnum):
    """
    ICMPv4 packet type enum.
    """

    ECHO_REPLY = 0
    UNREACHABLE = 3
    ECHO_REQUEST = 8

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[0])


class Icmp4Code(ProtoEnum):
    """
    ICMPv4 packet code enum.
    """

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[1])


class Icmp4EchoReplyCode(Icmp4Code):
    """
    ICMPv4 Echo Reply code enum.
    """

    DEFAULT = 0


class Icmp4UnreachableCode(Icmp4Code):
    """
    ICMPv4 Destination Unreachable code enum.
    """

    PORT = 3


class Icmp4EchoRequestCode(Icmp4Code):
    """
    ICMPv4 Echo Request code enum.

    """

    DEFAULT = 0


class Icmp4(Proto):
    """
    Base class for ICMPv4 packet parser and assembler classes.
    """

    _ip4_proto = Ip4Proto.ICMP4

    _message: Icmp4Message

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
    def ip4_proto(self) -> Ip4Proto:
        """
        Get the '_ip4_proto' attribute.
        """

        return self._ip4_proto

    @property
    def type(self) -> Icmp4Type:
        """
        Get the '_type' attribute.
        """

        return self._message.type

    @property
    def code(self) -> Icmp4Code:
        """
        Get the '_code' attribute.
        """

        return self._message.code

    @property
    def cksum(self) -> int:
        """
        Get the '_cksum' attribute.
        """

        return self._message.cksum

    @property
    def message(
        self,
    ) -> Icmp4Message:
        """
        Get the '_message' attribute.
        """

        return self._message


#
#  The ICMPv4 message classes.
#


class Icmp4Message(Proto):
    """
    Base class for the ICMPv4 message.
    """

    _type: Icmp4Type
    _code: Icmp4Code
    _cksum: int

    @property
    def type(self) -> Icmp4Type:
        """
        Get the '_type' property.
        """

        return self._type

    @property
    def code(self) -> Icmp4Code:
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


class Icmp4EchoReplyMessage(Icmp4Message):
    """
    Base class for the ICMPv4 Echo Reply message.
    """

    _type = Icmp4Type.ECHO_REPLY
    _code = Icmp4EchoReplyCode.DEFAULT

    _id: int
    _seq: int
    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP4_MESSAGE_LEN__ECHO_REPLY + len(self._data)

    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        return (
            f"ICMPv4 Echo Reply, id {self._id}, seq {self._seq}, "
            f"dlen {len(self._data)}"
        )

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return (
            "Icmp4EchoReplyMessage("
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


class Icmp4UnreachableMessage(Icmp4Message):
    """
    Base class for ICMPv4 Unreachable messages.
    """

    _type = Icmp4Type.UNREACHABLE
    _code: Icmp4UnreachableCode

    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP4_MESSAGE_LEN__UNREACHABLE + len(self._data)

    @property
    def data(self) -> bytes:
        """
        Getter for the '_data' property.
        """

        return self._data


class Icmp4PortUnreachableMessage(Icmp4UnreachableMessage):
    """
    Base class for ICMPv4 Port Unreachable message.
    """

    _type = Icmp4Type.UNREACHABLE
    _code = Icmp4UnreachableCode.PORT

    _reserved = 0
    _data: bytes

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return f"ICMPv4 Port Unreachable, dlen {len(self._data)}"

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return f"Icmp4PortUnreachableMessage(data={repr(self._data)})"

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


class Icmp4EchoRequestMessage(Icmp4Message):
    """
    Message base class for ICMPv4 Echo Request packet.
    """

    _type = Icmp4Type.ECHO_REQUEST
    _code = Icmp4EchoRequestCode.DEFAULT

    _id: int
    _seq: int
    _data: bytes

    def __len__(self) -> int:
        """
        Get the message length.
        """

        return ICMP4_MESSAGE_LEN__ECHO_REQUEST + len(self._data)

    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        return (
            f"ICMPv4 Echo Request, id {self._id}, "
            f"seq {self._seq}, dlen {len(self._data)}"
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

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return (
            "Icmp4EchoRequestMessage("
            f"id={repr(self._id)}, "
            f"seq={repr(self._seq)}, "
            f"data={repr(self._data)})"
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


class Icmp4UnknownMessage(Icmp4Message):
    """
    Base class for ICMPv4 unknown message.
    """

    _type: Icmp4Type
    _code: Icmp4Code

    def __len__(self) -> int:
        """
        Get the message length.
        """

        raise NotImplementedError

    def __str__(self) -> str:
        """
        Get the message log string.
        """

        return f"ICMPv4 Unknown Message, type {self._type}, code {self._code}"

    def __repr__(self) -> str:
        """
        Get the message representation.
        """

        return (
            "Icmp4UnknownMessage("
            f"type={repr(self._type)}, "
            f"code={repr(self._code)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the message in raw form.
        """

        raise NotImplementedError
