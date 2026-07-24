################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the IGMP message base class.

net_proto/protocols/igmp/message/igmp__message.py

ver 3.0.9
"""

from abc import abstractmethod
from dataclasses import dataclass
from enum import IntEnum

from net_addr import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_struct import ProtoStruct

# The IGMP message common header [RFC 3376 §4 / RFC 2236 §2].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     | Max Resp Code |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Every IGMP message starts with the 1-byte Type, a second byte whose
# meaning is type-specific (Max Resp Code in a Query, Reserved in a v3
# Report, Max Resp Time = 0 in the legacy v1/v2 forms), and the 2-byte
# Checksum computed over the whole IGMP message. The shortest IGMP
# message (the legacy v1/v2 Query / Report / Leave and the v3 Report
# header) is 8 octets; the v3 Query is at least 12 octets.

# The byte offset of the Checksum field, common to every IGMP message.
IGMP__CKSUM__OFFSET = 2

# The shortest legal IGMP message (RFC 2236 §2 simple form / RFC 3376
# §4.2 v3 Report header). The parser rejects any frame shorter than this.
IGMP__MESSAGE__MIN_LEN = 8


class IgmpVersion(IntEnum):
    """
    The IGMP protocol version a host runs / a Query advertises.

    Not a wire field — derived from a Query's message length and
    Max Resp Code per RFC 3376 §7.1, and used by the host
    querier-version state machine and the 'igmp.version' policy knob.
    """

    V1 = 1  # RFC 1112: IGMPv1.
    V2 = 2  # RFC 2236: IGMPv2.
    V3 = 3  # RFC 3376: IGMPv3.


class IgmpType(ProtoEnumByte):
    """
    The IGMP message 'type' field values.
    """

    MEMBERSHIP_QUERY = 0x11  # RFC 3376 §4.1 / RFC 2236 §2.1: Membership Query (v1/v2/v3).
    V1_MEMBERSHIP_REPORT = 0x12  # RFC 1112 §6: Version 1 Membership Report.
    V2_MEMBERSHIP_REPORT = 0x16  # RFC 2236 §2.1: Version 2 Membership Report.
    V2_LEAVE_GROUP = 0x17  # RFC 2236 §2.1: Version 2 Leave Group.
    V3_MEMBERSHIP_REPORT = 0x22  # RFC 3376 §4.2: Version 3 Membership Report.


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessage(ProtoStruct):
    """
    The IGMP message base.
    """

    type: IgmpType
    cksum: int

    @abstractmethod
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMP message.
        """

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the IGMP message.
        """

        raise NotImplementedError

    @abstractmethod
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMP message.
        """

        raise NotImplementedError
