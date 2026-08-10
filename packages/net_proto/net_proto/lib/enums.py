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
This module contains the shared protocol enums.

net_proto/lib/enums.py

ver 3.0.9
"""

from typing import override

from net_proto.lib.proto import Proto
from net_proto.lib.proto_enum import ProtoEnumByte, ProtoEnumWord


class EtherType(ProtoEnumWord):
    """
    The EtherType values.
    """

    ARP = 0x0806  # RFC 826: Address Resolution Protocol.
    IP4 = 0x0800  # RFC 894: IPv4 over Ethernet (IANA EtherType assignment).
    IP6 = 0x86DD  # RFC 2464: IPv6 over Ethernet (IANA EtherType assignment).
    RAW = 0xFFFF  # IANA "Reserved" — PyTCP-internal sentinel for raw-payload passthrough.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case EtherType.ARP:
                name = "ARP"
            case EtherType.IP4:
                name = "IPv4"
            case EtherType.IP6:
                name = "IPv6"
            case EtherType.RAW:
                name = "Raw"
            case _:
                name = f"0x{self.value:0>4x}"

        return name

    @staticmethod
    def from_proto(proto: Proto) -> EtherType:
        """
        Get the EtherType enum from a protocol object.
        """

        from net_proto.protocols.arp.arp__base import Arp
        from net_proto.protocols.ip4.ip4__base import Ip4
        from net_proto.protocols.ip6.ip6__base import Ip6
        from net_proto.protocols.raw.raw__base import Raw

        if isinstance(proto, Ip6):
            return EtherType.IP6

        if isinstance(proto, Ip4):
            return EtherType.IP4

        if isinstance(proto, Arp):
            return EtherType.ARP

        if isinstance(proto, Raw):
            return proto.ether_type

        assert False, f"Unknown protocol: {type(proto)}"


class IpProto(ProtoEnumByte):
    """
    The IpProto values.
    """

    IP6_HBH = 0  # RFC 8200 §4.3: Hop-by-Hop Options extension header.
    ICMP4 = 1  # RFC 792: Internet Control Message Protocol (ICMPv4).
    IGMP = 2  # RFC 1112 / 2236 / 3376: Internet Group Management Protocol.
    IP4 = 4  # RFC 2003 §1: IPv4 encapsulated in IP (IP-in-IP).
    TCP = 6  # RFC 9293 §3.1: Transmission Control Protocol header.
    UDP = 17  # RFC 768: User Datagram Protocol header.
    IP6 = 41  # RFC 2473 §3: IPv6-in-IPv6 tunneling (next header is an IPv6 header).
    IP6_ROUTING = 43  # RFC 8200 §4.4: Routing Header extension header.
    IP6_FRAG = 44  # RFC 8200 §4.5: Fragment Header extension header.
    ICMP6 = 58  # RFC 4443: Internet Control Message Protocol for IPv6.
    IP6_NO_NEXT_HEADER = 59  # RFC 8200 §4.7: No Next Header (chain terminator).
    IP6_DEST_OPTS = 60  # RFC 8200 §4.6: Destination Options extension header.
    RAW = 255  # IANA "Reserved" — PyTCP-internal sentinel for raw-protocol passthrough.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case IpProto.IP6_HBH:
                name = "IPv6_HBH"
            case IpProto.ICMP4:
                name = "ICMPv4"
            case IpProto.IGMP:
                name = "IGMP"
            case IpProto.IP4:
                name = "IPv4"
            case IpProto.TCP:
                name = "TCP"
            case IpProto.UDP:
                name = "UDP"
            case IpProto.IP6:
                name = "IPv6"
            case IpProto.IP6_ROUTING:
                name = "IPv6_Routing"
            case IpProto.IP6_FRAG:
                name = "IPv6_Frag"
            case IpProto.ICMP6:
                name = "ICMPv6"
            case IpProto.IP6_NO_NEXT_HEADER:
                name = "IPv6_NoNextHeader"
            case IpProto.IP6_DEST_OPTS:
                name = "IPv6_DestOpts"
            case IpProto.RAW:
                name = "Raw"
            case _:
                name = f"{self.value}"

        return name

    @staticmethod
    def from_proto(proto: Proto) -> IpProto:
        """
        Get the IpProto enum from a protocol object.
        """

        from net_proto.protocols.icmp4.icmp4__base import Icmp4
        from net_proto.protocols.icmp6.icmp6__base import Icmp6
        from net_proto.protocols.igmp.igmp__base import Igmp
        from net_proto.protocols.ip4.ip4__base import Ip4
        from net_proto.protocols.ip6.ip6__base import Ip6
        from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__base import Ip6DestOpts
        from net_proto.protocols.ip6_frag.ip6_frag__base import Ip6Frag
        from net_proto.protocols.ip6_hbh.ip6_hbh__base import Ip6Hbh
        from net_proto.protocols.ip6_routing.ip6_routing__base import Ip6Routing
        from net_proto.protocols.raw.raw__base import Raw
        from net_proto.protocols.tcp.tcp__base import Tcp
        from net_proto.protocols.udp.udp__base import Udp

        if isinstance(proto, Ip4):
            return IpProto.IP4

        if isinstance(proto, Icmp4):
            return IpProto.ICMP4

        if isinstance(proto, Igmp):
            return IpProto.IGMP

        if isinstance(proto, Tcp):
            return IpProto.TCP

        if isinstance(proto, Udp):
            return IpProto.UDP

        if isinstance(proto, Ip6):
            return IpProto.IP6

        if isinstance(proto, Ip6Hbh):
            return IpProto.IP6_HBH

        if isinstance(proto, Ip6Routing):
            return IpProto.IP6_ROUTING

        if isinstance(proto, Ip6Frag):
            return IpProto.IP6_FRAG

        if isinstance(proto, Ip6DestOpts):
            return IpProto.IP6_DEST_OPTS

        if isinstance(proto, Icmp6):
            return IpProto.ICMP6

        if isinstance(proto, Raw):
            return proto.ip_proto

        assert False, f"Unknown protocol: {type(proto)}"
