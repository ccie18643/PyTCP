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
Module contains packet structure information for the ARP protccol.

pytcp/protocols/arp/ps.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.enum import ProtoEnum
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import Proto
from pytcp.protocols.ethernet.ps import EthernetType

# ARP packet header (IPv4 stack version only).

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Hardware type         |         Protocol type         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hard length  |  Proto length |           Operation           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +        Sender MAC address     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |       Sender IP address       >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Target MAC address      |
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Target IP address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ARP_HEADER_LEN = 28


class ArpHardwareType(ProtoEnum):
    """
    ARP hardware type enum.
    """

    ETHERNET = 0x0001

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(struct.unpack("! H", frame[0:2])[0])


class ArpProtocolType(ProtoEnum):
    """
    ARP protocol type enum.
    """

    IP4 = 0x0800

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(struct.unpack("! H", frame[2:4])[0])


class ArpHardwareLength(ProtoEnum):
    """
    ARP hardware address length enum.
    """

    ETHERNET = 6

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[4])


class ArpProtocolLength(ProtoEnum):
    """
    ARP protocol address length enum.
    """

    IP4 = 4

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(frame[5])


class ArpOperation(ProtoEnum):
    """
    ARP operation enum.
    """

    REQUEST = 1
    REPLY = 2

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(struct.unpack("! H", frame[6:8])[0])


class Arp(Proto):
    """
    Base class for ARP packet parser and assembler.
    """

    _ethernet_type = EthernetType.ARP

    _hrtype: ArpHardwareType
    _prtype: ArpProtocolType
    _hrlen: ArpHardwareLength
    _prlen: ArpProtocolLength
    _oper: ArpOperation
    _sha: MacAddress
    _spa: Ip4Address
    _tha: MacAddress
    _tpa: Ip4Address

    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        return (
            f"ARP {self._oper} {self._spa} / {self._sha}"
            f" > {self.tpa} / {self.tha}"
        )

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return (
            "Arp("
            f"hrtype={self._hrtype!r}, "
            f"prtype={self._prtype!r}, "
            f"hrlen={self._hrlen!r}, "
            f"prlen={self._prlen!r}, "
            f"oper={self._oper!r}, "
            f"sha={self._sha!r}, "
            f"spa={self._spa!r}, "
            f"tha={self._tha!r}, "
            f"tpa={self._tpa!r})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the packet in raw form.
        """

        return struct.pack(
            "! HH BBH 6s 4s 6s 4s",
            int(self._hrtype),
            int(self._prtype),
            int(self._hrlen),
            int(self._prlen),
            int(self._oper),
            bytes(self._sha),
            bytes(self._spa),
            bytes(self._tha),
            bytes(self._tpa),
        )

    @property
    def ethernet_type(self) -> EthernetType:
        """
        Get the '_ethernet_type' attribute.
        """

        return self._ethernet_type

    @property
    def hrtype(self) -> ArpHardwareType:
        """
        Get the '_hrtype' attribute.
        """

        return self._hrtype

    @property
    def prtype(self) -> ArpProtocolType:
        """
        Get the '_prtype' attribute.
        """

        return self._prtype

    @property
    def hrlen(self) -> ArpHardwareLength:
        """
        Get the '_hrlen' attribute.
        """

        return self._hrlen

    @property
    def prlen(self) -> ArpProtocolLength:
        """
        Get the '_prlen' attribute.
        """

        return self._prlen

    @property
    def oper(self) -> ArpOperation:
        """
        Get the '_oper' attribute.
        """

        return self._oper

    @property
    def sha(self) -> MacAddress:
        """
        Get the '_sha' attribute.
        """

        return self._sha

    @property
    def spa(self) -> Ip4Address:
        """
        Get the '_spa' attribute.
        """

        return self._spa

    @property
    def tha(self) -> MacAddress:
        """
        Get the '_tha' attribute.
        """

        return self._tha

    @property
    def tpa(self) -> Ip4Address:
        """
        Get the '_tpa' attribute.
        """

        return self._tpa
