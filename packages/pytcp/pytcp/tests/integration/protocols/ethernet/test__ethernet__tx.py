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
This module contains integration tests for the Packet Handler Ethernet TX operations.

pytcp/tests/integration/protocols/ethernet/test__ethernet__tx.py

ver 3.0.8
"""

from typing import Any, Literal, override

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Address, Ip6IfAddr, Ip6Network
from net_proto import Ip4Assembler, Ip4FragAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.tests.lib.ethernet_testcase import EthernetTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_B__IP6_ADDRESS,
    HOST_C__IP4_ADDRESS,
    HOST_C__IP6_ADDRESS,
    IP4__BROADCAST__LIMITED,
    IP4__MULTICAST__ALL_NODES,
    IP6__MULTICAST__ALL_NODES,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.parameterized import parameterized_class

# Due to heavy dependency of IPv4/IPv6 protocols on Ethernet mechanisms
# the Ethernet tests are mostly executed using IPv4/IPv6 packets.

# Gateway-state discriminator for the per-test host configuration:
#   "set"   - gateway assigned to the real stack gateway address (default)
#   "unset" - gateway is None  (exercises 'no_gw__drop' branches)
#   "miss"  - gateway points at a host whose MAC is not in the cache
#             (exercises 'gw_*_cache_miss__drop' branches)
_GatewayState = Literal["set", "unset", "miss"]

# Foreign source addresses used to exercise the "source IP is not any of
# our configured hosts" fall-through in '_phtx_ethernet' (both for loops
# skip their bodies, control falls through to the local cache lookup).
_IP4__FOREIGN_SRC = Ip4Address("192.168.99.1")
_IP6__FOREIGN_SRC = Ip6Address("2001:db8:99::1")


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4 - dst unicast address on local network",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
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
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Minimal IPv4 header-only packet to host A resolved via ARP cache hit on the local LAN.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b",
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
            "_description": "Ethernet/IPv4 - dst multicast address",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": IP4__MULTICAST__ALL_NODES,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 01:00:5e:00:00:01 (IPv4 multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 1 (RFC 1112 §6.1 multicast default)
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0xcde3
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 224.0.0.1
                #
                # Summary: IPv4 header-only multicast packet mapped to the all-nodes MAC address.
                b"\x01\x00\x5e\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x01\xff\xcd\xe3\x0a\x00\x01\x07\xe0\x00"
                b"\x00\x01",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__multicast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst limited broadcast address",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": IP4__BROADCAST__LIMITED,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x6ee5
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 255.255.255.255
                #
                # Summary: IPv4 limited broadcast emitted with Ethernet broadcast destination.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x6e\xe5\x0a\x00\x01\x07\xff\xff"
                b"\xff\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__limited_broadcast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst local network broadcast address",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": STACK__IP4_HOST.network.broadcast,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x62e6
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.255
                #
                # Summary: IPv4 subnet broadcast mapped to Ethernet broadcast for the local LAN.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x62\xe6\x0a\x00\x01\x07\x0a\x00"
                b"\x01\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst local network address",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": STACK__IP4_HOST.network.address,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x63e5
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.0
                #
                # Summary: IPv4 packet aimed at the subnet network address, emitted as an Ethernet
                #          broadcast per stack rules.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\xe5\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst unicast address on local network, ARP cache miss",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_B__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_ARP_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst unicast address on external network",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "set",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:01 (default gateway)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 20 bytes
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x62b3
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.2.50
                #
                # Summary: IPv4 packet for an external host forwarded to the gateway MAC from cache.
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x62\xb3\x0a\x00\x01\x07\x0a\x00"
                b"\x02\x32",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst unicast address on external network, no gateway",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "unset",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4 - dst unicast address on external network, gateway ARP cache miss",
            "_method_name": "_phtx_ip4",
            "_gateway_state": "miss",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst unicast address on local network",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "set",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0 bytes
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # Summary: Minimal IPv6 packet to a local host delivered via ND cache hit.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst multicast address",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "set",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__MULTICAST__ALL_NODES,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:01 (IPv6 multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0 bytes
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : ff02::1
                #
                # Summary: IPv6 all-nodes multicast mapped to the corresponding Ethernet multicast MAC.
                b"\x33\x33\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x01",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst unicast address on local network, ND cache miss",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "set",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_B__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst unicast address on external network",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "set",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:01 (IPv6 gateway)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0 bytes
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:2::50
                #
                # Summary: IPv6 packet for an external peer, forwarded to the gateway MAC cached in ND.
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x50",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst unicast address on external network, no gateway",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "unset",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - dst unicast address on external network, gateway ND cache miss",
            "_method_name": "_phtx_ip6",
            "_gateway_state": "miss",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop=1,
            ),
        },
        {
            "_description": "Ethernet - src specified MAC address",
            "_method_name": "_phtx_ethernet",
            "_gateway_state": "set",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0xffff (experimental)
                #   Frame length    : 14 bytes
                #
                # Payload
                #   Bytes           : none (header-only frame used for the test)
                #
                # Summary: Raw Ethernet frame with caller-provided MAC addresses forwarded unchanged.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xff\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet - src unspecified MAC address",
            "_method_name": "_phtx_ethernet",
            "_gateway_state": "set",
            "_kwargs": {
                "ethernet__src": MAC__UNSPECIFIED,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (stack filled)
                #   Ethertype       : 0xffff (experimental)
                #   Frame length    : 14 bytes
                #
                # Payload
                #   Bytes           : none (header-only frame used for the test)
                #
                # Summary: Raw Ethernet frame with unspecified source automatically filled in before transmit.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xff\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet - dst unspecified MAC address",
            "_method_name": "_phtx_ethernet",
            "_gateway_state": "set",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_unspec__drop=1,
            ),
        },
        {
            # Direct '_phtx_ethernet' call with an 'Ip4FragAssembler' payload so
            # the isinstance branch at source line 184 (which accepts both
            # 'Ip4Assembler' and 'Ip4FragAssembler') is exercised for the frag
            # variant too — guards against silent drift between the two types'
            # '.src' / '.dst' surfaces.
            "_description": "Ethernet - Ip4FragAssembler payload, dst unicast on local network",
            "_method_name": "_phtx_ethernet",
            "_gateway_state": "set",
            "_kwargs": {
                "ethernet__payload": Ip4FragAssembler(
                    ip4_frag__src=STACK__IP4_HOST.address,
                    ip4_frag__dst=HOST_A__IP4_ADDRESS,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91 (resolved via ARP cache hit)
                #   Source MAC      : 02:00:00:00:00:07 (stack filled)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4 fragment
                #   Version / IHL   : 4 / 5
                #   Total Length    : 20 bytes (header-only fragment)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x638a
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # Summary: Ip4FragAssembler payload drives the same IP4-lookup branch as
                #          Ip4Assembler; ARP cache hit on the local LAN resolves the dst MAC.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            # Foreign IPv4 src. The two host-matching 'for' loops both skip
            # their bodies (no configured host matches), so control falls
            # through to the local ARP cache lookup for the dst.
            "_description": "Ethernet/IPv4 - foreign src IP, dst resolved via local ARP cache hit",
            "_method_name": "_phtx_ethernet",
            "_gateway_state": "set",
            "_kwargs": {
                "ethernet__payload": Ip4Assembler(
                    ip4__src=_IP4__FOREIGN_SRC,
                    ip4__dst=HOST_A__IP4_ADDRESS,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91 (resolved via ARP cache hit)
                #   Source MAC      : 02:00:00:00:00:07 (stack filled)
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 34 bytes
                #
                # IPv4
                #   Version / IHL   : 4 / 5
                #   Total Length    : 20 bytes (header-only)
                #   TTL             : 64
                #   Protocol        : 255 (Reserved)
                #   Header Checksum : 0x4ae7
                #   Source IP       : 192.168.99.1 (foreign — not any of our hosts)
                #   Destination IP  : 10.0.1.91
                #
                # Summary: IPv4 packet with a source address outside our configured hosts.
                #          Both host-matching for loops skip; fall-through hits the ARP cache.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x4a\xe7\xc0\xa8\x63\x01\x0a\x00"
                b"\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
    ]
)
class TestPacketHandlerEthernetTx(EthernetTestCase):
    """
    Test the Packet Handler Ethernet TX operations.
    """

    _description: str
    _method_name: Literal["_phtx_ip4", "_phtx_ip6", "_phtx_ethernet"]
    _gateway_state: _GatewayState
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    @override
    def setUp(self) -> None:
        """
        Build fresh per-test 'Ip4IfAddr' and 'Ip6IfAddr' instances so gateway
        mutations do not leak into the module-level 'STACK__IP*_HOST'
        objects shared across tests. Configure each host's gateway per
        '_gateway_state' and install the pair on the packet handler.
        Two of the parametrized cases exercise IPv4 broadcast
        destinations, which the 'ip4.allow_broadcast' policy gate
        (default 0) would otherwise drop; opt the suite in via a
        sysctl override that 'tearDown' restores. The non-broadcast
        cases are unaffected because their paths never consult the
        sysctl.
        """

        super().setUp()

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.set("ip4.default.allow_broadcast", 1)
        self.addCleanup(sysctl_module.reset_to_defaults)

        ip4_host = Ip4IfAddr("10.0.1.7/24")
        ip6_host = Ip6IfAddr("2001:db8:0:1::7/64")
        self._packet_handler._ip4_ifaddr = [ip4_host]
        self._packet_handler._ip6_ifaddr = [ip6_host]

        # Post-Phase-2 the Ethernet-TX next hop is decided by the
        # FIB, not 'IfAddr.gateway'. The harness 'super().setUp()'
        # already installed the fixture default routes (0.0.0.0/0
        # via STACK__IP4_GATEWAY, ::/0 via STACK__IP6_GATEWAY) into
        # fresh per-test FIBs, so '_gateway_state' now drives the
        # FIB. The expected statuses / counters / frames are
        # unchanged — only the control knob moved.
        default4 = Ip4Network("0.0.0.0/0")
        default6 = Ip6Network("::/0")
        match self._gateway_state:
            case "set":
                # Keep the harness-installed default routes.
                pass
            case "unset":
                # Remove the default routes so off-link
                # destinations have no route — the 'no_gw__drop'
                # branch (now "no route to host").
                stack.ip4_fib.remove(destination=default4)
                stack.ip6_fib.remove(destination=default6)
            case "miss":
                # Repoint the default routes at hosts whose MACs
                # are unresolved in the cache mocks (HOST_B is the
                # canonical "cache-miss" fixture).
                stack.ip4_fib.remove(destination=default4)
                stack.ip6_fib.remove(destination=default6)
                stack.ip4_fib.add(
                    route=Route(
                        destination=default4,
                        gateway=HOST_B__IP4_ADDRESS,
                        protocol=RouteProtocol.BOOT,
                    )
                )
                stack.ip6_fib.add(
                    route=Route(
                        destination=default6,
                        gateway=HOST_B__IP6_ADDRESS,
                        protocol=RouteProtocol.BOOT,
                    )
                )

    def test__packet_handler__ethernet__tx(self) -> None:
        """
        Ensure the Packet Handler Ethernet TX path produces the
        expected frames, statuses, and statistics for each
        parametrized case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tx_handler = getattr(self._packet_handler, self._method_name)

        self.assertEqual(
            tx_handler(**self._kwargs),
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
