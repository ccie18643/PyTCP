#!/usr/bin/env python3

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
This package contains classes representing network protocols.

net_proto/__init__.py

ver 3.0.4
"""

from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.errors import PacketValidationError
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.int_checks import (
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_4__MAX,
    UINT_4__MIN,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_20__MAX,
    UINT_20__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.tracker import Tracker
from net_proto.protocols.arp.arp__assembler import ArpAssembler
from net_proto.protocols.arp.arp__enums import ArpHardwareType, ArpOperation
from net_proto.protocols.arp.arp__errors import (
    ArpIntegrityError,
    ArpSanityError,
)
from net_proto.protocols.arp.arp__header import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__HEADER__LEN,
    ARP__PROTOCOL_LEN__IP4,
    ArpHeader,
)
from net_proto.protocols.arp.arp__parser import ArpParser
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4Operation
from net_proto.protocols.dhcp4.dhcp4__errors import (
    Dhcp4IntegrityError,
    Dhcp4SanityError,
)
from net_proto.protocols.dhcp4.dhcp4__header import (
    DHCP4__HEADER__FILE__MAX_LEN,
    DHCP4__HEADER__SNAME__MAX_LEN,
    Dhcp4Header,
)
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__end import (
    DHCP4__OPTION__END__LEN,
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__message_type import (
    Dhcp4MessageType,
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__pad import (
    DHCP4__OPTION__PAD__LEN,
    Dhcp4OptionPad,
)
from net_proto.protocols.dhcp4.options.dhcp4_option__unknown import (
    Dhcp4OptionUnknown,
)
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__base import EthernetPayload
from net_proto.protocols.ethernet.ethernet__errors import (
    EthernetIntegrityError,
    EthernetSanityError,
)
from net_proto.protocols.ethernet.ethernet__header import (
    ETHERNET__HEADER__LEN,
    EthernetHeader,
)
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ethernet_802_3.ethernet_802_3__assembler import (
    Ethernet8023Assembler,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__base import (
    Ethernet8023Payload,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__errors import (
    Ethernet8023IntegrityError,
    Ethernet8023SanityError,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PACKET__MAX_LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__parser import (
    Ethernet8023Parser,
)
from net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from net_proto.protocols.icmp4.icmp4__errors import (
    Icmp4IntegrityError,
    Icmp4SanityError,
)
from net_proto.protocols.icmp4.icmp4__parser import Icmp4Parser
from net_proto.protocols.icmp4.message.icmp4_message import (
    Icmp4Code,
    Icmp4Message,
    Icmp4Type,
)
from net_proto.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    ICMP4__DESTINATION_UNREACHABLE__LEN,
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)
from net_proto.protocols.icmp4.message.icmp4_message__echo_reply import (
    ICMP4__ECHO_REPLY__LEN,
    Icmp4EchoReplyCode,
    Icmp4EchoReplyMessage,
)
from net_proto.protocols.icmp4.message.icmp4_message__echo_request import (
    ICMP4__ECHO_REQUEST__LEN,
    Icmp4EchoRequestCode,
    Icmp4EchoRequestMessage,
)
from net_proto.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)
from net_proto.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from net_proto.protocols.icmp6.icmp6__base import Icmp6
from net_proto.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
    Icmp6SanityError,
)
from net_proto.protocols.icmp6.icmp6__parser import Icmp6Parser
from net_proto.protocols.icmp6.message.icmp6_message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    ICMP6__DESTINATION_UNREACHABLE__LEN,
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)
from net_proto.protocols.icmp6.message.icmp6_message__echo_reply import (
    ICMP6__ECHO_REPLY__LEN,
    Icmp6EchoReplyCode,
    Icmp6EchoReplyMessage,
)
from net_proto.protocols.icmp6.message.icmp6_message__echo_request import (
    ICMP6__ECHO_REQUEST__LEN,
    Icmp6EchoRequestCode,
    Icmp6EchoRequestMessage,
)
from net_proto.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)
from net_proto.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from net_proto.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    ICMP6__MLD2__REPORT__LEN,
    Icmp6Mld2ReportCode,
    Icmp6Mld2ReportMessage,
)
from net_proto.protocols.icmp6.message.nd.icmp6_nd_message import Icmp6NdMessage
from net_proto.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_advertisement import (
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdNeighborAdvertisementMessage,
)
from net_proto.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_solicitation import (
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdNeighborSolicitationMessage,
)
from net_proto.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementCode,
    Icmp6NdRouterAdvertisementMessage,
)
from net_proto.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationCode,
    Icmp6NdRouterSolicitationMessage,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option__pi import (
    Icmp6NdOptionPi,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option__tlla import (
    Icmp6NdOptionTlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option__unknown import (
    Icmp6NdOptionUnknown,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)
from net_proto.protocols.ip4.ip4__assembler import (
    Ip4Assembler,
    Ip4FragAssembler,
)
from net_proto.protocols.ip4.ip4__base import Ip4Payload
from net_proto.protocols.ip4.ip4__defaults import (
    IP4__DEFAULT_TTL,
    IP4__MIN_MTU,
)
from net_proto.protocols.ip4.ip4__errors import (
    Ip4IntegrityError,
    Ip4SanityError,
)
from net_proto.protocols.ip4.ip4__header import (
    IP4__HEADER__LEN,
    IP4__PAYLOAD__MAX_LEN,
    Ip4Header,
)
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip4.options.ip4_option import (
    Ip4Option,
    Ip4OptionType,
)
from net_proto.protocols.ip4.options.ip4_option__eol import (
    IP4__OPTION__EOL__LEN,
    Ip4OptionEol,
)
from net_proto.protocols.ip4.options.ip4_option__nop import (
    IP4__OPTION__NOP__LEN,
    Ip4OptionNop,
)
from net_proto.protocols.ip4.options.ip4_option__unknown import (
    IP4__OPTION__LEN,
    Ip4OptionUnknown,
)
from net_proto.protocols.ip4.options.ip4_options import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Options,
)
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6.ip6__base import Ip6Payload
from net_proto.protocols.ip6.ip6__errors import (
    Ip6IntegrityError,
    Ip6SanityError,
)
from net_proto.protocols.ip6.ip6__header import (
    IP6__DEFAULT_HOP_LIMIT,
    IP6__HEADER__LEN,
    IP6__MIN_MTU,
    IP6__PAYLOAD__MAX_LEN,
    Ip6Header,
)
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler
from net_proto.protocols.ip6_frag.ip6_frag__errors import (
    Ip6FragIntegrityError,
    Ip6FragSanityError,
)
from net_proto.protocols.ip6_frag.ip6_frag__header import (
    IP6_FRAG__HEADER__LEN,
    Ip6FragHeader,
)
from net_proto.protocols.ip6_frag.ip6_frag__parser import Ip6FragParser
from net_proto.protocols.raw.raw__assembler import RawAssembler
from net_proto.protocols.tcp.options.tcp_option import TCP__OPTION__LEN
from net_proto.protocols.tcp.options.tcp_option__eol import (
    TCP__OPTION__EOL__LEN,
    TcpOptionEol,
)
from net_proto.protocols.tcp.options.tcp_option__mss import (
    TCP__OPTION__MSS__LEN,
    TcpOptionMss,
)
from net_proto.protocols.tcp.options.tcp_option__nop import (
    TCP__OPTION__NOP__LEN,
    TcpOptionNop,
)
from net_proto.protocols.tcp.options.tcp_option__sack import (
    TCP__OPTION__SACK__BLOCK_LEN,
    TCP__OPTION__SACK__LEN,
    TCP__OPTION__SACK__MAX_BLOCK_NUM,
    TcpOptionSack,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp_option__sackperm import (
    TCP__OPTION__SACKPERM__LEN,
    TcpOptionSackperm,
)
from net_proto.protocols.tcp.options.tcp_option__timestamps import (
    TCP__OPTION__TIMESTAMPS__LEN,
    TcpOptionTimestamps,
    TcpTimestamps,
)
from net_proto.protocols.tcp.options.tcp_option__unknown import TcpOptionUnknown
from net_proto.protocols.tcp.options.tcp_option__wscale import (
    TCP__OPTION__WSCALE__LEN,
    TCP__OPTION__WSCALE__MAX_VALUE,
    TcpOptionWscale,
)
from net_proto.protocols.tcp.options.tcp_options import (
    TCP__OPTIONS__MAX_LEN,
    TcpOption,
    TcpOptions,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from net_proto.protocols.tcp.tcp__errors import (
    TcpIntegrityError,
    TcpSanityError,
)
from net_proto.protocols.tcp.tcp__header import TCP__HEADER__LEN, TcpHeader
from net_proto.protocols.tcp.tcp__parser import TcpParser
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from net_proto.protocols.udp.udp__errors import (
    UdpIntegrityError,
    UdpSanityError,
)
from net_proto.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader
from net_proto.protocols.udp.udp__parser import UdpParser

__all__ = [
    "ArpHeader",
    "ArpParser",
    "ArpAssembler",
    "ArpOperation",
    "ArpHardwareType",
    "ArpIntegrityError",
    "ArpSanityError",
    "ARP__HEADER__LEN",
    "ARP__HARDWARE_LEN__ETHERNET",
    "ARP__PROTOCOL_LEN__IP4",
    "EthernetHeader",
    "EthernetParser",
    "EthernetAssembler",
    "EthernetPayload",
    "EthernetIntegrityError",
    "EthernetSanityError",
    "ETHERNET__HEADER__LEN",
    "Ethernet8023Header",
    "Ethernet8023Parser",
    "Ethernet8023Assembler",
    "Ethernet8023Payload",
    "Ethernet8023IntegrityError",
    "Ethernet8023SanityError",
    "ETHERNET_802_3__HEADER__LEN",
    "ETHERNET_802_3__PACKET__MAX_LEN",
    "ETHERNET_802_3__PAYLOAD__MAX_LEN",
    "Dhcp4Header",
    "Dhcp4Operation",
    "Dhcp4MessageType",
    "Dhcp4OptionType",
    "Dhcp4OptionEnd",
    "Dhcp4OptionPad",
    "Dhcp4OptionUnknown",
    "DHCP4__OPTION__PAD__LEN",
    "DHCP4__OPTION__LEN",
    "Dhcp4OptionMessageType",
    "Dhcp4IntegrityError",
    "Dhcp4SanityError",
    "DHCP4__OPTION__END__LEN",
    "DHCP4__HEADER__FILE__MAX_LEN",
    "DHCP4__HEADER__SNAME__MAX_LEN",
    "Icmp4Parser",
    "Icmp4Assembler",
    "Icmp4Message",
    "Icmp4Code",
    "Icmp4DestinationUnreachableMessage",
    "ICMP4__DESTINATION_UNREACHABLE__LEN",
    "Icmp4EchoRequestMessage",
    "Icmp4EchoRequestCode",
    "ICMP4__ECHO_REQUEST__LEN",
    "Icmp4EchoReplyMessage",
    "Icmp4EchoReplyCode",
    "ICMP4__ECHO_REPLY__LEN",
    "Icmp4UnknownMessage",
    "Icmp4Type",
    "Icmp4DestinationUnreachableCode",
    "Icmp4IntegrityError",
    "Icmp4SanityError",
    "Icmp6",
    "Icmp6Type",
    "Icmp6Code",
    "Icmp6Parser",
    "Icmp6Assembler",
    "Icmp6Message",
    "Icmp6DestinationUnreachableMessage",
    "Icmp6EchoRequestMessage",
    "Icmp6EchoRequestCode",
    "Icmp6EchoReplyMessage",
    "Icmp6EchoReplyCode",
    "Icmp6UnknownMessage",
    "Icmp6Mld2MulticastAddressRecord",
    "Icmp6Mld2MulticastAddressRecordType",
    "Icmp6Mld2ReportMessage",
    "Icmp6Mld2ReportCode",
    "ICMP6__MLD2__REPORT__LEN",
    "Icmp6NdMessage",
    "Icmp6NdNeighborAdvertisementMessage",
    "Icmp6NdNeighborAdvertisementCode",
    "Icmp6NdNeighborSolicitationMessage",
    "Icmp6NdNeighborSolicitationCode",
    "Icmp6NdRouterAdvertisementMessage",
    "Icmp6NdRouterAdvertisementCode",
    "Icmp6NdRouterSolicitationMessage",
    "Icmp6NdRouterSolicitationCode",
    "Icmp6DestinationUnreachableCode",
    "Icmp6NdOption",
    "Icmp6NdOptionType",
    "Icmp6NdOptions",
    "Icmp6NdOptionPi",
    "Icmp6NdOptionSlla",
    "Icmp6NdOptionTlla",
    "Icmp6NdOptionUnknown",
    "Icmp6IntegrityError",
    "Icmp6SanityError",
    "ICMP6__ND__OPTION__LEN",
    "ICMP6__DESTINATION_UNREACHABLE__LEN",
    "ICMP6__ECHO_REQUEST__LEN",
    "ICMP6__ECHO_REPLY__LEN",
    "Ip4Header",
    "Ip4Parser",
    "Ip4Assembler",
    "Ip4FragAssembler",
    "Ip4Payload",
    "Ip4OptionEol",
    "Ip4OptionNop",
    "Ip4Options",
    "Ip4Option",
    "Ip4OptionType",
    "Ip4IntegrityError",
    "Ip4SanityError",
    "Ip4OptionUnknown",
    "IP4__OPTIONS__MAX_LEN",
    "IP4__OPTION__LEN",
    "IP4__HEADER__LEN",
    "IP4__DEFAULT_TTL",
    "IP4__MIN_MTU",
    "IP4__PAYLOAD__MAX_LEN",
    "IP4__OPTION__EOL__LEN",
    "IP4__OPTION__NOP__LEN",
    "Ip6Header",
    "Ip6Parser",
    "Ip6Assembler",
    "Ip6Payload",
    "Ip6IntegrityError",
    "Ip6SanityError",
    "IP6__HEADER__LEN",
    "IP6__DEFAULT_HOP_LIMIT",
    "IP6__MIN_MTU",
    "IP6__PAYLOAD__MAX_LEN",
    "Ip6FragHeader",
    "Ip6FragParser",
    "Ip6FragAssembler",
    "Ip6FragIntegrityError",
    "Ip6FragSanityError",
    "IP6_FRAG__HEADER__LEN",
    "RawAssembler",
    "TcpHeader",
    "TcpAssembler",
    "TcpParser",
    "TcpOptions",
    "TcpOption",
    "TcpOptionEol",
    "TcpOptionMss",
    "TcpOptionNop",
    "TcpOptionSack",
    "TcpOptionSackperm",
    "TcpOptionUnknown",
    "TcpOptionWscale",
    "TcpOptionType",
    "TcpIntegrityError",
    "TcpSanityError",
    "TcpSackBlock",
    "TcpOptionTimestamps",
    "TcpTimestamps",
    "TCP__HEADER__LEN",
    "TCP__OPTION__LEN",
    "TCP__OPTIONS__MAX_LEN",
    "TCP__OPTION__WSCALE__LEN",
    "TCP__OPTION__NOP__LEN",
    "TCP__OPTION__TIMESTAMPS__LEN",
    "TCP__OPTION__EOL__LEN",
    "TCP__OPTION__SACKPERM__LEN",
    "TCP__OPTION__SACK__LEN",
    "TCP__OPTION__MSS__LEN",
    "TCP__OPTION__SACK__BLOCK_LEN",
    "TCP__OPTION__SACK__MAX_BLOCK_NUM",
    "TCP__OPTION__WSCALE__MAX_VALUE",
    "UdpHeader",
    "UdpAssembler",
    "UdpParser",
    "UdpIntegrityError",
    "UdpSanityError",
    "UDP__HEADER__LEN",
    "PacketValidationError",
    "Tracker",
    "EtherType",
    "IpProto",
    "PacketRx",
    "inet_cksum",
    "UINT_2__MIN",
    "UINT_2__MAX",
    "UINT_4__MIN",
    "UINT_4__MAX",
    "UINT_6__MIN",
    "UINT_6__MAX",
    "UINT_8__MIN",
    "UINT_8__MAX",
    "UINT_13__MIN",
    "UINT_13__MAX",
    "UINT_16__MIN",
    "UINT_16__MAX",
    "UINT_20__MIN",
    "UINT_20__MAX",
    "UINT_32__MIN",
    "UINT_32__MAX",
]
