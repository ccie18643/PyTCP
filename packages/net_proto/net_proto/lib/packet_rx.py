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
This module contains the PacketRx class representing a received packet.

net_proto/lib/packet_rx.py

ver 3.0.9
"""

from typing import TYPE_CHECKING

from net_addr import Buffer
from net_proto.lib.tracker import Tracker

if TYPE_CHECKING:
    from net_proto.protocols.arp.arp__parser import ArpParser
    from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
    from net_proto.protocols.ethernet_802_3.ethernet_802_3__parser import (
        Ethernet8023Parser,
    )
    from net_proto.protocols.icmp4.icmp4__parser import Icmp4Parser
    from net_proto.protocols.icmp6.icmp6__parser import Icmp6Parser
    from net_proto.protocols.igmp.igmp__parser import IgmpParser
    from net_proto.protocols.ip4.ip4__parser import Ip4Parser
    from net_proto.protocols.ip6.ip6__parser import Ip6Parser
    from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__parser import (
        Ip6DestOptsParser,
    )
    from net_proto.protocols.ip6_frag.ip6_frag__parser import Ip6FragParser
    from net_proto.protocols.ip6_hbh.ip6_hbh__parser import Ip6HbhParser
    from net_proto.protocols.ip6_routing.ip6_routing__parser import (
        Ip6RoutingParser,
    )
    from net_proto.protocols.llc.llc__parser import LlcParser
    from net_proto.protocols.snap.snap__parser import SnapParser
    from net_proto.protocols.tcp.tcp__parser import TcpParser
    from net_proto.protocols.udp.udp__parser import UdpParser


class PacketRx:
    """
    Class representing the received packet.
    """

    def __init__(self, frame: Buffer, /) -> None:
        """
        Initialize the received-packet container.
        """

        self.frame: Buffer = memoryview(frame)
        self.tracker: Tracker = Tracker(prefix="RX")
        self.parse_failed: str = ""

        # Set to True by the IPv6 frag-RX handler on the
        # reassembled PacketRx it forwards back to the IPv6
        # chain walker. Used by the ICMPv6 RX dispatch to
        # silently drop fragmented ND / SEND messages per
        # RFC 6980 §5.
        self.was_fragmented: bool = False

        # Set to True by the loopback interface's RX consumer on a
        # packet it delivers internally. The IPv4 / IPv6 parsers
        # consult it to skip the RFC 1122 §3.2.1.3(g) loopback-source
        # martian check — a wire-ingress policy that must not apply to
        # traffic looped inside the host (where loopback addresses are
        # the whole point).
        self.from_loopback: bool = False

        self.ethernet: EthernetParser
        self.ethernet_802_3: Ethernet8023Parser
        self.llc: LlcParser
        self.snap: SnapParser
        self.arp: ArpParser
        self.ip: Ip6Parser | Ip4Parser
        self.ip4: Ip4Parser
        self.ip6: Ip6Parser
        self.ip6_dest_opts: Ip6DestOptsParser
        self.ip6_frag: Ip6FragParser
        self.ip6_hbh: Ip6HbhParser
        self.ip6_routing: Ip6RoutingParser
        self.icmp4: Icmp4Parser
        self.icmp6: Icmp6Parser
        self.igmp: IgmpParser
        self.tcp: TcpParser
        self.udp: UdpParser

    def __len__(self) -> int:
        """
        Get the length of the raw frame.
        """

        return len(self.frame)
