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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains integration tests for the IPv4 TX packet-handler path.

pytcp/tests/integration/protocols/ip4/test__ip4__tx.py

ver 3.0.8
"""

from typing import Any, override

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageEchoRequest,
    Ip4OptionLsrr,
    Ip4OptionNop,
    Ip4OptionRr,
    Ip4Options,
    Ip4Parser,
    IpProto,
    PacketRx,
)
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.ip4_testcase import Ip4TestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_C__IP4_ADDRESS,
    IP4__BROADCAST__LIMITED,
    IP4__MULTICAST__ALL_NODES,
    IP4__UNSPECIFIED,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4 - src valid, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Minimal IPv4 header-only datagram sent by the stack host
                #          to host A on the local LAN.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src not owned drop, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": HOST_B__IP4_ADDRESS,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP4__SRC_NOT_OWNED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_not_owned__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src multicast replace, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": IP4__MULTICAST__ALL_NODES,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (multicast source replaced)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7 (multicast replaced)
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Multicast source rewritten to 10.0.1.7 before unicast delivery
                #          of the minimal IPv4 frame to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_multicast__replace=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src multicast drop, dst unicast local network",
            "_clear_ip4_host": True,
            "_kwargs": {
                "ip4__src": IP4__MULTICAST__ALL_NODES,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP4__SRC_MULTICAST,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_multicast__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src limited broadcast replace, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": IP4__BROADCAST__LIMITED,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (limited broadcast replaced)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7 (broadcast replaced)
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Limited broadcast source normalised to 10.0.1.7 before sending
                #          the header-only IPv4 packet toward host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_limited_broadcast__replace=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src limited broadcast drop, dst unicast local network",
            "_clear_ip4_host": True,
            "_kwargs": {
                "ip4__src": IP4__BROADCAST__LIMITED,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP4__SRC_LIMITED_BROADCAST,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_limited_broadcast__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src network broadcast replace, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.network.broadcast,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (network broadcast replaced)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7 (network broadcast replaced)
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Network broadcast source converted to the stack host prior to
                #          emitting the minimal IPv4 datagram to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_broadcast__replace=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src unspecified replace, dst unicast local network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": IP4__UNSPECIFIED,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (unspecified source filled)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7 (unspecified replaced)
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Unspecified source field populated with 10.0.1.7 before
                #          transmitting the minimal IPv4 frame to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_unspecified__replace_local=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src unspecified replace, dst unicast external network",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": IP4__UNSPECIFIED,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:01 (gateway)
                #   Source MAC      : 02:00:00:00:00:07 (unspecified source filled)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0014 (20 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x62b3
                #   Source IP       : 10.0.1.7 (unspecified replaced)
                #   Destination IP  : 10.0.2.50
                #
                # Summary: Header-only IPv4 datagram forwarded toward host C via the
                #          gateway after supplying 10.0.1.7 as the source address.
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x62\xb3\x0a\x00\x01\x07\x0a\x00"
                b"\x02\x32"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_unspecified__replace_external=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src unspecified drop, dst unicast local network",
            "_clear_ip4_host": True,
            "_kwargs": {
                "ip4__src": IP4__UNSPECIFIED,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP4__SRC_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_unspecified__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src valid, dst unspecified drop",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": IP4__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP4__DST_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__dst_unspecified__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - src valid, dst unicast local network, mtu exceed fragmentation",
            "_clear_ip4_host": False,
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "ip4__payload": RawAssembler(raw__payload=b"01234567890ABCDEF" * 400),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 1514 bytes
                #
                # IPv4 (fragment 1)
                #   Total Length    : 0x05dc (1500 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x2000 (MF set, offset 0x000)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x3dc1
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Fragment 1 (bytes 0–1479) begins the reserved-protocol payload
                #          delivery to host A with MF set.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x05\xdc\x00\x01\x20\x00\x40\xff\x3d\xc1\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30",
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 1514 bytes
                #
                # IPv4 (fragment 2)
                #   Total Length    : 0x05dc (1500 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x20b9 (MF set, offset 0x0b9)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x3d08
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Fragment 2 (bytes 1480–2959) continues the reserved-protocol
                #          payload stream toward host A with MF still set.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x05\xdc\x00\x01\x20\xb9\x40\xff\x3d\x08\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31",
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 1514 bytes
                #
                # IPv4 (fragment 3)
                #   Total Length    : 0x05dc (1500 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x2172 (MF set, offset 0x172)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x3c4f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Fragment 3 (bytes 2960–4439) keeps MF asserted while extending
                #          the payload stream destined for host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x05\xdc\x00\x01\x21\x72\x40\xff\x3c\x4f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32",
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 1514 bytes
                #
                # IPv4 (fragment 4)
                #   Total Length    : 0x05dc (1500 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x222b (MF set, offset 0x22b)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x3b96
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Fragment 4 (bytes 4440–5919) transports the penultimate slice
                #          of payload toward host A with MF still set.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x05\xdc\x00\x01\x22\x2b\x40\xff\x3b\x96\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33",
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 914 bytes
                #
                # IPv4 (fragment 5)
                #   Total Length    : 0x0384 (900 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x02e4 (offset 0x2e4, final fragment)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x5d35
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Fragment 5 (bytes 5920–6799) clears MF and delivers the final
                #          portion required for host A to reassemble the payload.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x03\x84\x00\x01\x02\xe4\x40\xff\x5d\x35\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_exceed__frag=1,
                ip4__mtu_exceed__frag__send=5,
                ethernet__pre_assemble=5,
                ethernet__src_unspec__fill=5,
                ethernet__dst_unspec__ip4_lookup=5,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=5,
            ),
        },
    ]
)
class TestIp4Tx(Ip4TestCase):
    """
    The IPv4 TX packet-handler path tests (success path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _clear_ip4_host: bool
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__ip4__tx(self) -> None:
        """
        Ensure the Packet Handler IPv4 TX path produces the expected
        frames, statuses, and statistics for each parametrized case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        if self._clear_ip4_host:
            self._packet_handler._ip4_ifaddr = []

        self.assertEqual(
            self._packet_handler._phtx_ip4(**self._kwargs),
            self._expected__tx_status,
            msg=f"Unexpected TxStatus for case: {self._description}",
        )

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "_phtx_ip4 - ip4__ttl == 0 fails the 0 < ttl < 256 assert",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "ip4__ttl": 0,
            },
            "_expected__error": AssertionError(),
        },
        {
            "_description": "_phtx_ip4 - ip4__ttl == 256 fails the 0 < ttl < 256 assert",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "ip4__ttl": 256,
            },
            "_expected__error": AssertionError(),
        },
    ]
)
class TestIp4TxErrors(Ip4TestCase):
    """
    The IPv4 TX packet-handler path tests (error path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__ip4__tx__error(self) -> None:
        """
        Ensure '_phtx_ip4' raises the expected exception for invalid
        kwargs.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_ip4(**self._kwargs)

        # AssertionError messages depend on '__debug__' and the assert
        # expression text; only assert the exception type is correct.
        self.assertIsInstance(
            error.exception,
            type(self._expected__error),
            msg=f"Unexpected exception type for case: {self._description}",
        )


class TestIp4TxMtuExceedDf(Ip4TestCase):
    """
    The IPv4 TX packet-handler path tests for RFC 791 §3.1 DF
    enforcement: an IPv4 packet whose size exceeds the link MTU and
    whose DF=1 must be dropped — not fragmented.
    """

    def test__ip4__tx__mtu_exceed_df__drops(self) -> None:
        """
        Ensure '_phtx_ip4' returns DROPPED__IP4__MTU_EXCEED_DF and
        emits no frame when the assembled packet exceeds the
        interface MTU and the caller asked for DF=1.

        Reference: RFC 791 §3.1 (Don't Fragment flag semantics).
        """

        big_payload = bytes(2000)
        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__flag_df=True,
            ip4__payload=Icmp4Assembler(
                icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=big_payload),
            ),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__MTU_EXCEED_DF,
            msg="_phtx_ip4 with DF=1 + len > MTU must return DROPPED__IP4__MTU_EXCEED_DF.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when DF=1 + len > MTU.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ip4__mtu_exceed__df_set__drop,
            1,
            msg="ip4__mtu_exceed__df_set__drop counter must bump.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ip4__mtu_exceed__frag,
            0,
            msg="With DF=1, the fragment-path counter must NOT bump.",
        )

    def test__ip4__tx__mtu_exceed_no_df__fragments(self) -> None:
        """
        Ensure '_phtx_ip4' still fragments when the packet exceeds
        the MTU and DF=0 — the legacy default. Verifies the DF
        gate is the sole guardrail and the legacy fragmentation
        path is intact.

        Reference: RFC 791 §2.3 (in-network fragmentation).
        """

        big_payload = bytes(2000)
        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=Icmp4Assembler(
                icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=big_payload),
            ),
        )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="_phtx_ip4 with DF=0 + len > MTU must fragment and forward.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ip4__mtu_exceed__frag,
            1,
            msg="ip4__mtu_exceed__frag must bump on the DF=0 oversized path.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ip4__mtu_exceed__df_set__drop,
            0,
            msg="With DF=0, the DF-drop counter must NOT bump.",
        )


class TestIp4TxNoIp4Support(Ip4TestCase):
    """
    The IPv4 TX packet-handler path tests for when IPv4 protocol support is
    disabled — '_phtx_ip4' must short-circuit before assembly.
    """

    @override
    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv4 protocol
        support on the packet handler.
        """

        super().setUp()
        self._packet_handler._ip4_support = False

    def test__ip4__tx__no_ip4_support(self) -> None:
        """
        Ensure '_phtx_ip4' returns 'DROPPED__IP4__NO_PROTOCOL_SUPPORT'
        and bumps 'ip4__no_proto_support__drop' without emitting any
        frame when IPv4 support is disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__NO_PROTOCOL_SUPPORT,
            msg="_phtx_ip4 must return DROPPED__IP4__NO_PROTOCOL_SUPPORT when IPv4 disabled.",
        )

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv4 protocol support is disabled.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__no_proto_support__drop=1,
            ),
            msg="Only ip4__pre_assemble and ip4__no_proto_support__drop must bump.",
        )


class TestIp4TxSendIp4Packet(Ip4TestCase):
    """
    Test the public 'send_ip4_packet' wrapper, which forwards into
    '_phtx_ip4' wrapping the user payload as a 'RawAssembler' and
    renaming the addressing kwargs.
    """

    def test__ip4__tx__send_ip4_packet(self) -> None:
        """
        Ensure 'send_ip4_packet' wraps the call to '_phtx_ip4' with
        a 'RawAssembler' payload using the supplied 'ip4__proto' and
        the renamed addressing kwargs, producing a successful frame
        and matching stats.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler.send_ip4_packet(
            ip4__local_address=STACK__IP4_HOST.address,
            ip4__remote_address=HOST_A__IP4_ADDRESS,
            ip4__proto=IpProto.from_int(99),
            ip4__payload=b"\x00\x00\x00\x00",
        )

        # 'send_ip4_packet' is fire-and-forget (Phase 4b) — no
        # TxStatus return; assert on the emitted frame and stats.
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="send_ip4_packet must emit exactly one frame for a small RAW payload.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            msg="send_ip4_packet stats must match a direct _phtx_ip4 RAW-payload call.",
        )


# IPv4 header lives at Ethernet offset 14. Within the IPv4 header,
# byte 4-5 is Identification and byte 8 is Time-to-Live.
_IP4__OFFSET_IN_ETH_FRAME = 14
_IP4__ID_OFFSET = _IP4__OFFSET_IN_ETH_FRAME + 4
_IP4__TTL_OFFSET = _IP4__OFFSET_IN_ETH_FRAME + 8


class TestIp4TxRfc1112MulticastTtl(Ip4TestCase):
    """
    The RFC 1112 §6.1 multicast outbound TTL default tests.

    Outbound IPv4 datagrams with a multicast destination MUST
    default to TTL=1 so multicast traffic does not leak past the
    local link unless the caller explicitly raises the TTL.
    """

    def test__ip4__tx__multicast_dst_no_caller_ttl__defaults_to_1(self) -> None:
        """
        Ensure outbound IPv4 datagrams with a multicast
        destination ship with TTL=1 when the caller does not
        specify 'ip4__ttl' — multicast traffic is local-link by
        default and only escapes when the operator explicitly
        opts in.

        Reference: RFC 1112 §6.1 (default to 1 for all multicast
        IP datagrams so explicit choice is required to multicast
        beyond a single network).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=IP4__MULTICAST__ALL_NODES,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Multicast outbound must emit exactly one frame.",
        )
        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            1,
            msg="Multicast outbound datagrams must default to TTL=1.",
        )

    def test__ip4__tx__multicast_dst_caller_overrides_ttl__preserved(self) -> None:
        """
        Ensure a caller-supplied 'ip4__ttl' overrides the
        multicast-default of 1 — the operator can choose to
        multicast beyond the local link by raising the TTL.

        Reference: RFC 1112 §6.1 (explicit choice required to
        multicast beyond a single network).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=IP4__MULTICAST__ALL_NODES,
            ip4__ttl=64,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            64,
            msg="Caller-supplied multicast TTL must be preserved verbatim.",
        )

    def test__ip4__tx__unicast_dst_no_caller_ttl__defaults_to_64(self) -> None:
        """
        Ensure outbound IPv4 datagrams with a unicast destination
        retain the legacy IP4__DEFAULT_TTL=64 default — regression
        net for the multicast carve-out so the unicast common
        path keeps working.

        Reference: PyTCP test infrastructure (no RFC clause; this
        is the regression net for the §6.1 carve-out).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            64,
            msg="Unicast outbound datagrams must keep the IP4__DEFAULT_TTL=64 default.",
        )


class TestIp4TxRfc791OptionCopyFlagOnFragmentation(Ip4TestCase):
    """
    The RFC 791 §3.1 option-copy-flag fragmentation tests.

    Each IPv4 option carries a 'copy on fragmentation' flag in
    bit 7 of the option-type byte. When the TX path fragments
    an oversized datagram, options with copy_flag=True
    propagate onto every fragment; options with
    copy_flag=False appear only on the first fragment.
    """

    def _make_lsrr_rr_options(self) -> Ip4Options:
        """
        Build an Ip4Options containing one LSRR (copy=True) + one
        RR (copy=False), padded to 4 bytes via two NOP options.
        Total length: 7 + 7 + 1 + 1 = 16 bytes.
        """

        return Ip4Options(
            Ip4OptionLsrr(pointer=4, route=[Ip4Address("10.0.0.1")]),
            Ip4OptionRr(pointer=4, route=[Ip4Address("0.0.0.0")]),
            Ip4OptionNop(),
            Ip4OptionNop(),
        )

    def test__ip4__tx__fragmentation_preserves_copy_flag_options(self) -> None:
        """
        Ensure a fragmented datagram with mixed copy-flag
        options ships the **full** option set on the first
        fragment and the **copy_flag=True subset** (padded to
        4 bytes) on every subsequent fragment.

        Reference: RFC 791 §3.1 (option-type copy flag = bit 0
        of the option-type byte; copy=1 propagates to every
        fragment, copy=0 stays on first only).
        """

        # Force 2 fragments: payload_mtu = (1500 - (20+16)) & ~7
        # = 1464; payload 1500 bytes splits into 1464 + 36.
        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__options=self._make_lsrr_rr_options(),
            ip4__payload=RawAssembler(
                raw__payload=b"X" * 1500,
                ip_proto=IpProto.from_int(99),
            ),
        )

        self.assertEqual(
            len(self._frames_tx),
            2,
            msg="Oversized payload with options must produce exactly 2 fragments.",
        )

        # Parse each fragment's IPv4 header. Ethernet header is
        # 14 bytes; skip it to feed the IPv4 portion to Ip4Parser.
        first_frame = self._frames_tx[0][14:]
        second_frame = self._frames_tx[1][14:]

        first_parser = Ip4Parser(PacketRx(first_frame))
        second_parser = Ip4Parser(PacketRx(second_frame))

        # First fragment: full option set (LSRR + RR + 2 NOPs).
        # Use option-type tuples to compare the option sequence
        # without depending on per-option __eq__ semantics for
        # NOPs.
        self.assertEqual(
            [int(o.type) for o in first_parser.options],
            [131, 7, 1, 1],  # LSRR, RR, NOP, NOP
            msg="First fragment must carry the full original option set.",
        )

        # Second fragment: only copy_flag=True options (LSRR)
        # plus NOP padding for 4-byte alignment.
        self.assertEqual(
            [int(o.type) for o in second_parser.options],
            [131, 1],  # LSRR + 1 NOP padding (7+1=8 bytes)
            msg="Subsequent fragment must carry only copy_flag=1 options + NOP padding.",
        )

        # Both fragments must have the same source / dst / id /
        # proto — basic fragmentation sanity.
        self.assertEqual(
            first_parser.id,
            second_parser.id,
            msg="Both fragments must share the same Identification value.",
        )
        self.assertTrue(
            first_parser.flag_mf,
            msg="Non-final fragment must have MF=1.",
        )
        self.assertFalse(
            second_parser.flag_mf,
            msg="Final fragment must have MF=0.",
        )

    def test__ip4__tx__fragmentation_with_only_copy_false_options(self) -> None:
        """
        Ensure a fragmented datagram with only copy_flag=False
        options ships those options on the first fragment and
        an empty options set on subsequent fragments.

        Reference: RFC 791 §3.1 (copy_flag=0 → first fragment only).
        """

        # Only RR (copy=False) + NOP padding = 8 bytes.
        options = Ip4Options(
            Ip4OptionRr(pointer=4, route=[Ip4Address("0.0.0.0")]),
            Ip4OptionNop(),
        )

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__options=options,
            ip4__payload=RawAssembler(
                raw__payload=b"X" * 1500,
                ip_proto=IpProto.from_int(99),
            ),
        )

        first_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        second_parser = Ip4Parser(PacketRx(self._frames_tx[1][14:]))

        self.assertEqual(
            [int(o.type) for o in first_parser.options],
            [7, 1],  # RR + NOP
            msg="First fragment must carry the copy_flag=False option set.",
        )
        self.assertEqual(
            list(second_parser.options),
            [],
            msg="Subsequent fragments must carry no options when all originals are copy_flag=False.",
        )

    def test__ip4__tx__fragmentation_with_no_options_unchanged(self) -> None:
        """
        Ensure a fragmented datagram with no options ships no
        options on either fragment — regression net for the
        common case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(
                raw__payload=b"X" * 1500,
                ip_proto=IpProto.from_int(99),
            ),
        )

        for index, frame in enumerate(self._frames_tx):
            parser = Ip4Parser(PacketRx(frame[14:]))
            self.assertEqual(
                list(parser.options),
                [],
                msg=f"Fragment #{index} of a no-options datagram must carry no options.",
            )


class TestIp4TxRfc6864AtomicId(Ip4TestCase):
    """
    The RFC 6864 §4.1 atomic-datagram Identification tests.

    Atomic datagrams (DF=1 || (MF=0 && offset=0) by RFC 6864
    definition) MAY set the Identification field to any value;
    PyTCP follows the Linux-canonical choice of 0.
    """

    def test__ip4__tx__atomic_datagram__ip4_id_is_zero(self) -> None:
        """
        Ensure outbound IPv4 datagrams that are not fragmented
        carry Identification = 0 — the spec permits any value,
        and PyTCP follows the Linux-canonical choice of 0 (Linux
        'net/ipv4/ip_output.c::ip_select_ident' returns 0 for
        atomic datagrams).

        Reference: RFC 6864 §4.1 (atomic datagram ID may be any
        value; Linux uses 0).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Atomic outbound must emit exactly one frame.",
        )
        self.assertEqual(
            int.from_bytes(self._frames_tx[0][_IP4__ID_OFFSET : _IP4__ID_OFFSET + 2]),
            0,
            msg="Atomic outbound IPv4 datagrams must carry Identification = 0.",
        )


class TestIp4TxRfc1122DefaultTtlSysctl(Ip4TestCase):
    """
    The RFC 1122 §3.2.1.7 'ip4.default_ttl' sysctl override tests.

    The host default TTL is configurable through the
    'ip4.default_ttl' sysctl. Outbound unicast datagrams with no
    caller-supplied TTL pick up the live sysctl value at TX time
    so an operator override is observable on the wire without
    restarting the stack.
    """

    def test__ip4__tx__unicast_dst_sysctl_override__honoured_on_wire(self) -> None:
        """
        Ensure that overriding 'ip4.default_ttl' at runtime
        changes the TTL of subsequent outbound unicast
        datagrams that did not specify a caller TTL — the
        qualified-module read in the TX path must re-resolve
        the live sysctl value on every emission rather than
        capturing it at import time.

        Reference: RFC 1122 §3.2.1.7 (MUST be configurable).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("ip4.default_ttl", 32):
            self._packet_handler._phtx_ip4(
                ip4__src=STACK__IP4_HOST.address,
                ip4__dst=HOST_A__IP4_ADDRESS,
                ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
            )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Unicast outbound must emit exactly one frame.",
        )
        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            32,
            msg="Unicast outbound TTL must reflect the live ip4.default_ttl sysctl value.",
        )

    def test__ip4__tx__unicast_dst_sysctl_default__matches_baseline(self) -> None:
        """
        Ensure the live sysctl value at boot equals 64 — the
        baseline configurable default — so a stack started with
        no overrides keeps the historical TTL=64 unicast
        behaviour.

        Reference: RFC 1122 §3.2.1.7 (TTL default and configurability).
        """

        self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            64,
            msg="Default unicast TTL must equal 64 with no sysctl override.",
        )

    def test__ip4__tx__multicast_dst_unaffected_by_sysctl(self) -> None:
        """
        Ensure that an operator override of 'ip4.default_ttl'
        does NOT affect multicast destinations — the multicast
        TTL default is pinned at 1 regardless of the host
        unicast default, so the multicast carve-out survives
        any unicast-default tuning.

        Reference: RFC 1112 §6.1 (multicast TTL default = 1, independent of unicast default).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("ip4.default_ttl", 200):
            self._packet_handler._phtx_ip4(
                ip4__src=STACK__IP4_HOST.address,
                ip4__dst=IP4__MULTICAST__ALL_NODES,
                ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
            )

        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            1,
            msg="Multicast outbound TTL must remain 1 regardless of ip4.default_ttl sysctl.",
        )


class TestIp4TxRfc919AllowBroadcast(Ip4TestCase):
    """
    The 'ip4.allow_broadcast' policy gate tests.

    Outbound broadcast emission is gated by 'ip4.allow_broadcast'
    so a future broadcast-capable consumer must opt in explicitly
    — mirrors the Linux per-socket SO_BROADCAST default-off
    discipline. The DHCP-client RFC 2131 §3.1 path (src=0.0.0.0,
    UDP sport=68/dport=67) bypasses the gate because the client
    cannot complete a lease without broadcasting.
    """

    def test__ip4__tx__limited_broadcast_dst_default_deny__dropped(self) -> None:
        """
        Ensure that with 'ip4.allow_broadcast' at its default
        value (0) an outbound datagram to 255.255.255.255 with
        a non-DHCP payload is silently dropped, the
        'DROPPED__IP4__DST_BROADCAST_DISALLOWED' TxStatus is
        returned, and the
        'ip4__dst_broadcast_disallowed__drop' counter bumps.

        Reference: RFC 919 §1 (broadcast emission requires explicit opt-in policy).
        """

        prior = self._packet_handler._packet_stats_tx.ip4__dst_broadcast_disallowed__drop

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=IP4__BROADCAST__LIMITED,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__DST_BROADCAST_DISALLOWED,
            msg="Default-deny must return DROPPED__IP4__DST_BROADCAST_DISALLOWED for 255.255.255.255.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="Default-deny broadcast must not emit any frame.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_tx.ip4__dst_broadcast_disallowed__drop,
            prior + 1,
            msg="ip4__dst_broadcast_disallowed__drop counter must bump on the drop.",
        )

    def test__ip4__tx__limited_broadcast_dst_sysctl_allow__permitted(self) -> None:
        """
        Ensure that flipping 'ip4.allow_broadcast' to 1 allows
        the same outbound datagram through to the wire — the
        gate is the only barrier, and the operator override
        unblocks downstream consumers.

        Reference: RFC 919 §1 (broadcast emission permitted under explicit policy).
        """

        from pytcp.stack import sysctl as sysctl_module

        with sysctl_module.override("ip4.default.allow_broadcast", 1):
            tx_status = self._packet_handler._phtx_ip4(
                ip4__src=STACK__IP4_HOST.address,
                ip4__dst=IP4__BROADCAST__LIMITED,
                ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
            )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Allow-broadcast must let the datagram through to the TX ring.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Allow-broadcast must emit exactly one frame.",
        )

    def test__ip4__tx__network_broadcast_dst_default_deny__dropped(self) -> None:
        """
        Ensure that the gate also drops outbound datagrams to a
        subnet-directed broadcast (e.g. 10.0.1.255 for the
        10.0.1.0/24 stack subnet) — the network-broadcast
        emission path is symmetric with the limited-broadcast
        path under the same policy.

        Reference: RFC 922 §3 (subnet-directed broadcast policy).
        """

        # The stack host is 10.0.1.7/24, so 10.0.1.255 is the
        # subnet-directed broadcast for the stack's network.
        network_broadcast = Ip4Address("10.0.1.255")

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=network_broadcast,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__DST_BROADCAST_DISALLOWED,
            msg="Default-deny must drop subnet-directed broadcast destinations.",
        )

    def test__ip4__tx__dhcp_client_path_bypasses_gate(self) -> None:
        """
        Ensure the DHCP-client outbound path (src=0.0.0.0, UDP
        sport=68, dport=67, dst=255.255.255.255) bypasses the
        'ip4.allow_broadcast' gate so a freshly-booted host
        can broadcast DHCPDISCOVER without the operator pre-
        flipping the sysctl.

        Reference: RFC 2131 §3.1 (DHCPDISCOVER MUST broadcast pre-bind).
        """

        from net_proto import UdpAssembler

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=IP4__BROADCAST__LIMITED,
            ip4__payload=UdpAssembler(udp__sport=68, udp__dport=67, udp__payload=b"\x00" * 8),
        )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="DHCP-client outbound path must bypass the broadcast gate.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="DHCP-client outbound must emit exactly one frame.",
        )

    def test__ip4__tx__unicast_dst_unaffected_by_gate(self) -> None:
        """
        Ensure unicast destinations are unaffected by the gate
        — the policy applies only to limited or subnet-directed
        broadcast addresses; the common unicast path stays
        unconditional.

        Reference: PyTCP test infrastructure (regression net for
        the broadcast gate carve-out).
        """

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Unicast outbound must succeed regardless of broadcast gate.",
        )


class TestIp4TxRfc3927ScopeGate(Ip4TestCase):
    """
    The RFC 3927 §2.6 source/destination link-local scope-
    mismatch gate tests.

    A host MUST NOT send packets that mix a link-local source
    with a non-link-local destination or a link-local
    destination with a non-link-local source. The two halves of
    the rule are symmetric — link-local addressing is local-
    only, so any scope mix is rejected at TX time.
    """

    _link_local_host_address = Ip4Address("169.254.42.42")
    _link_local_dst_address = Ip4Address("169.254.99.99")

    @override
    def setUp(self) -> None:
        """
        Add a 169.254/16 link-local host alongside the standard
        global host so the source-address-validation step
        accepts 169.254.42.42 as an owned source. Future link-
        local autoconfig will populate this list the same way.
        Extend the harness' ARP-cache mock to admit the
        link-local destination address as a cache miss so the
        downstream Ethernet TX path can resolve it without
        tripping the mock's 'Unexpected find_entry call'
        assertion.
        """

        super().setUp()
        from net_addr import Ip4IfAddr

        self._packet_handler._ip4_ifaddr.append(Ip4IfAddr("169.254.42.42/16"))

        # 'self._arp_cache' is autospec'd from 'ArpCache' so
        # mypy sees the real method type — but at runtime each
        # method is a Mock with the usual 'side_effect'
        # attribute (the harness '_arp_cache' handle is typed 'Any').
        find_entry_mock = self._arp_cache.find_entry
        original_side_effect = find_entry_mock.side_effect

        def _lookup_with_link_local(*, ip4_address: Ip4Address) -> Any:
            """Return None for the link-local dst; delegate otherwise."""
            if ip4_address == self._link_local_dst_address:
                return None
            return original_side_effect(ip4_address=ip4_address)

        find_entry_mock.side_effect = _lookup_with_link_local
        self.addCleanup(
            lambda: setattr(find_entry_mock, "side_effect", original_side_effect),
        )

    def test__ip4__tx__link_local_src__global_dst__dropped(self) -> None:
        """
        Ensure an outbound datagram with a link-local source
        and a non-link-local destination is dropped with the
        new TxStatus and the
        'ip4__link_local_scope_mismatch__drop' counter bumps.

        Reference: RFC 3927 §2.6 (link-local source MUST NOT be used with non-link-local destination).
        """

        prior = self._packet_handler._packet_stats_tx.ip4__link_local_scope_mismatch__drop

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=self._link_local_host_address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH,
            msg="Link-local src + global dst must drop with the scope-mismatch TxStatus.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="Scope-mismatch drop must not emit any frame.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_tx.ip4__link_local_scope_mismatch__drop,
            prior + 1,
            msg="ip4__link_local_scope_mismatch__drop counter must bump on the drop.",
        )

    def test__ip4__tx__global_src__link_local_dst__dropped(self) -> None:
        """
        Ensure the symmetric direction is also dropped — a
        non-link-local source MUST NOT be used to address a
        link-local destination.

        Reference: RFC 3927 §2.6 (link-local destination MUST NOT be addressed from non-link-local source).
        """

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=self._link_local_dst_address,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH,
            msg="Global src + link-local dst must drop with the scope-mismatch TxStatus.",
        )

    def test__ip4__tx__link_local_src__link_local_dst__allowed(self) -> None:
        """
        Ensure two link-local addresses (matching scope on
        both sides) are not gated — matching link-local
        scope is the only legitimate link-local addressing
        per the rule.

        Reference: RFC 3927 §2.6 (matching link-local scope is the only legitimate link-local addressing).
        """

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=self._link_local_host_address,
            ip4__dst=self._link_local_dst_address,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        # The downstream Ethernet TX path will then attempt to
        # ARP-resolve the link-local destination. With the
        # fixture's empty ARP cache for 169.254.99.99 the
        # outcome is DROPPED__ETHERNET__DST_ARP_CACHE_MISS,
        # NOT a scope-mismatch — the IPv4-layer gate let it
        # through.
        self.assertNotEqual(
            tx_status,
            TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH,
            msg="Link-local src + link-local dst must not trip the §2.6 scope gate.",
        )

    def test__ip4__tx__global_src__global_dst__unaffected(self) -> None:
        """
        Ensure the common global-to-global path is unaffected
        — the gate fires only when one of src/dst is link-
        local. Regression net so a future tightening doesn't
        silently start gating normal unicast traffic.

        Reference: PyTCP test infrastructure (regression net
        for the §2.6 gate carve-out).
        """

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            ip4__payload=RawAssembler(raw__payload=b"\x00", ip_proto=IpProto.from_int(99)),
        )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Global src + global dst must succeed unaffected by the §2.6 gate.",
        )

    def test__ip4__tx__dhcp_path_unaffected_by_gate(self) -> None:
        """
        Ensure the DHCP-client outbound path (src=0.0.0.0,
        UDP sport=68/dport=67, dst=255.255.255.255) does not
        trip the scope-mismatch gate — neither address is
        link-local, so the rule does not apply.

        Reference: RFC 2131 §3.1 (DHCPDISCOVER carries src=0.0.0.0, dst=255.255.255.255).
        """

        from net_proto import UdpAssembler

        tx_status = self._packet_handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=IP4__BROADCAST__LIMITED,
            ip4__payload=UdpAssembler(udp__sport=68, udp__dport=67, udp__payload=b"\x00" * 8),
        )

        self.assertNotEqual(
            tx_status,
            TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH,
            msg="DHCP outbound path must not trip the §2.6 scope gate.",
        )
