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
This module contains tests for carrying an IGMP message as an IPv4
payload (the IpProto.IGMP wire integration).

net_proto/tests/unit/protocols/igmp/test__igmp__ip4_payload.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Buffer, Ip4Address
from net_proto.protocols.igmp.igmp__assembler import IgmpAssembler
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3GroupRecord,
    IgmpV3RecordType,
)
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler


class TestIgmpIp4Payload(TestCase):
    """
    The IGMP-as-IPv4-payload wire-integration tests.
    """

    def test__igmp__ip4_payload__proto_is_igmp(self) -> None:
        """
        Ensure an IGMP message carried as an IPv4 payload sets the IPv4
        Protocol field to 2 (IGMP), proving IpProto.from_proto resolves
        the IGMP assembler.

        Reference: RFC 1112 §7.2 (IGMP is IP protocol 2).
        Reference: RFC 3376 §4 (IGMP messages carried in IPv4).
        """

        igmp = IgmpAssembler(
            igmp__message=IgmpMessageV3Report(
                records=[
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip4Address("239.1.1.1"),
                    )
                ]
            )
        )
        ip4 = Ip4Assembler(
            ip4__src=Ip4Address("10.0.0.1"),
            ip4__dst=Ip4Address("224.0.0.22"),
            ip4__payload=igmp,
        )

        buffers: list[Buffer] = []
        ip4.assemble(buffers)
        frame = b"".join(bytes(buf) for buf in buffers)

        # IPv4 Protocol field is at byte offset 9.
        self.assertEqual(
            frame[9],
            2,
            msg="The IPv4 Protocol field must be 2 (IGMP) for an IGMP payload.",
        )

    def test__igmp__ip4_payload__igmp_bytes_follow_header(self) -> None:
        """
        Ensure the assembled IGMP message bytes follow the 20-byte IPv4
        header intact (the IGMP report is carried verbatim as payload).

        Reference: RFC 3376 §4 (IGMP messages carried in IPv4).
        """

        igmp = IgmpAssembler(
            igmp__message=IgmpMessageV3Report(
                records=[
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip4Address("239.1.1.1"),
                    )
                ]
            )
        )
        ip4 = Ip4Assembler(
            ip4__src=Ip4Address("10.0.0.1"),
            ip4__dst=Ip4Address("224.0.0.22"),
            ip4__payload=igmp,
        )

        buffers: list[Buffer] = []
        ip4.assemble(buffers)
        frame = b"".join(bytes(buf) for buf in buffers)

        # The IGMP message (V3 Report header + one 8-byte group record)
        # is 16 octets and begins right after the 20-byte IPv4 header.
        self.assertEqual(
            frame[20],
            0x22,
            msg="The first IGMP byte must be the V3 Membership Report type 0x22.",
        )
        self.assertEqual(
            len(frame),
            20 + 16,
            msg="The frame must be the 20-byte IPv4 header plus the 16-byte IGMP report.",
        )
