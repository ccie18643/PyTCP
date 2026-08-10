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
This module contains the ICMP inbound classifier. It maps the IP-layer
state of an inbound packet into the IcmpErrorContext that gates whether
an outbound ICMP error may be sent in response.

pytcp/protocols/icmp/icmp__inbound_classifier.py

ver 3.0.9
"""

from net_addr import IpVersion
from net_proto.lib.packet_rx import PacketRx
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorContext


def classify_inbound(
    packet_rx: PacketRx,
    /,
    *,
    inbound_was_icmp_error: bool = False,
    is_pmtud_response: bool = False,
    is_param_problem_code_2: bool = False,
) -> IcmpErrorContext:
    """
    Build an IcmpErrorContext from the IP-layer state of packet_rx.
    """

    if packet_rx.ip.ver is IpVersion.IP4:
        ip4 = packet_rx.ip4
        dst_is_broadcast = ip4.dst.is_limited_broadcast
        dst_is_multicast = ip4.dst.is_multicast
        src_invalid = (
            ip4.src.is_unspecified
            or ip4.src.is_loopback
            or ip4.src.is_multicast
            or ip4.src.is_limited_broadcast
            or ip4.src.is_reserved
        )
        non_initial_fragment = ip4.offset != 0
    else:
        ip6 = packet_rx.ip6
        dst_is_broadcast = False
        dst_is_multicast = ip6.dst.is_multicast
        src_invalid = ip6.src.is_unspecified or ip6.src.is_loopback or ip6.src.is_multicast
        non_initial_fragment = False

    return IcmpErrorContext(
        inbound_was_icmp_error=inbound_was_icmp_error,
        inbound_dst_is_broadcast=dst_is_broadcast,
        inbound_dst_is_multicast=dst_is_multicast,
        inbound_src_invalid=src_invalid,
        inbound_non_initial_fragment=non_initial_fragment,
        is_pmtud_response=is_pmtud_response,
        is_param_problem_code_2=is_param_problem_code_2,
    )
