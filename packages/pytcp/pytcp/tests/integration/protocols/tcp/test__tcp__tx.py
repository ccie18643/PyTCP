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
This module contains integration tests for the TCP TX packet-handler path.

pytcp/tests/integration/protocols/tcp/test__tcp__tx.py

ver 3.0.10
"""

from typing import Any

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.parameterized import parameterized_class
from pytcp.tests.lib.tcp_testcase import TcpTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/TCP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x8dcb
                #   Urgent Pointer  : 0
                #
                # Summary: Bare TCP segment with no flags or payload emitted from
                #          10.0.1.7:1000 toward 10.0.1.91:2000.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x8d\xcb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - seq",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__seq": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00003039 (12345)
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x5d92
                #   Urgent Pointer  : 0
                #
                # Summary: Same minimal TCP header but with the initial sequence number
                #          preloaded to 12345 before transmitting to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x30\x39\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - ack",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__ack": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00003039 (12345)
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x5d92
                #   Urgent Pointer  : 0
                #
                # Summary: TCP header with an acknowledgement value of 12345 but no
                #          control flags asserted, sent to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x30\x39\x50\x00"
                b"\x00\x00\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ns",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ns": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : NS
                #   Window          : 0x0000
                #   Checksum        : 0x8ccb
                #   Urgent Pointer  : 0
                #
                # Summary: Demonstrates the TCP NS flag being set on the otherwise
                #          empty segment bound for 10.0.1.91:2000.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00"
                b"\x00\x00\x8c\xcb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag cwr",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_cwr": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : CWR
                #   Window          : 0x0000
                #   Checksum        : 0x8d4b
                #   Urgent Pointer  : 0
                #
                # Summary: TCP segment with the Congestion Window Reduced flag asserted,
                #          otherwise mirroring the default empty template.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x80"
                b"\x00\x00\x8d\x4b\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ece",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ece": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : ECE
                #   Window          : 0x0000
                #   Checksum        : 0x8d8b
                #   Urgent Pointer  : 0
                #
                # Summary: Sends a TCP header with the ECN-Echo flag asserted to
                #          demonstrate ECN handling in the transmit path.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x40"
                b"\x00\x00\x8d\x8b\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag urg",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_urg": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : URG
                #   Window          : 0x0000
                #   Checksum        : 0x8dab
                #   Urgent Pointer  : 0
                #
                # Summary: URG flag asserted without urgent data, producing a control
                #          segment from 10.0.1.7:1000 to host A's port 2000.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x20"
                b"\x00\x00\x8d\xab\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ack",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ack": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : ACK
                #   Window          : 0x0000
                #   Checksum        : 0x8dbb
                #   Urgent Pointer  : 0
                #
                # Summary: ACK-only control segment emitted from 10.0.1.7:1000 with no
                #          payload or acknowledgement data.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x10"
                b"\x00\x00\x8d\xbb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag psh",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_psh": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : PSH
                #   Window          : 0x0000
                #   Checksum        : 0x8dc3
                #   Urgent Pointer  : 0
                #
                # Summary: Push flag set to illustrate how the stack constructs a
                #          PSH-only TCP segment with no payload.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x08"
                b"\x00\x00\x8d\xc3\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag rst",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_rst": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : RST
                #   Window          : 0x0000
                #   Checksum        : 0x8dc7
                #   Urgent Pointer  : 0
                #
                # Summary: Reset-only probe constructed by the TX path to test RST flag
                #          serialization toward 10.0.1.91:2000.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x04"
                b"\x00\x00\x8d\xc7\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag syn",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_syn": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : SYN
                #   Window          : 0x0000
                #   Checksum        : 0x8dc9
                #   Urgent Pointer  : 0
                #
                # Summary: SYN-only probe used to validate outbound connection setup
                #          handling on the IPv4 path.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02"
                b"\x00\x00\x8d\xc9\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag fin",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_fin": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : FIN
                #   Window          : 0x0000
                #   Checksum        : 0x8dca
                #   Urgent Pointer  : 0
                #
                # Summary: FIN control bit exercised while keeping the rest of the TCP
                #          header at its baseline values.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x01"
                b"\x00\x00\x8d\xca\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_fin=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - win",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__win": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x3039 (12345)
                #   Checksum        : 0x5d92
                #   Urgent Pointer  : 0
                #
                # Summary: Example showing a non-zero advertised window (12345) on an
                #          otherwise empty TCP header.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x30\x39\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - urg",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x5d92
                #   Urgent Pointer  : 0x3039 (12345)
                #
                # Summary: Exercises the urgent pointer field (set to 12345) without
                #          raising the URG control bit.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x5d\x92\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - data",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 904 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x037a (890 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x611d
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0xa897
                #   Urgent Pointer  : 0
                #   Payload         : 850 bytes (ASCII sequence "01234567890ABCDEF" repeated)
                #
                # Summary: Large TCP payload example pushing 850 bytes of repeating ASCII
                #          data from 10.0.1.7:1000 toward host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x03\x7a\x00\x00\x40\x00\x40\x06\x21\x1d\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\xa8\x97\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
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
                b"\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - option mss",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__mss": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 58 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x002c (44 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646b
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x4b8a
                #   Urgent Pointer  : 0
                #   Options         : MSS (kind 2, len 4, value 12345)
                #
                # Summary: Advertises an MSS of 12345 through the TCP options field while
                #          keeping the payload empty.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x2c\x00\x00\x40\x00\x40\x06\x24\x6b\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x4b\x8a\x00\x00\x02\x04\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_mss=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - option wscale",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__wscale": 14,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 58 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x002c (44 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646b
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x79b6
                #   Urgent Pointer  : 0
                #   Options         : NOP, Window Scale (value 14)
                #
                # Summary: 4-byte TCP options block demonstrating Window Scale 14 with a
                #          leading NOP pad.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x2c\x00\x00\x40\x00\x40\x06\x24\x6b\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x79\xb6\x00\x00\x01\x03\x03\x0e"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_wscale=1,
                tcp__opt_nop=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x4821
                #   Urgent Pointer  : 0
                #
                # Summary: Baseline IPv6 TCP segment with empty payload transmitted from
                #          the stack host to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x48\x21\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - seq",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__seq": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00003039 (12345)
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x17e8
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 variant of the minimal TCP header with a preset sequence
                #          number of 12345.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x30\x39\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - ack",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__ack": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00003039 (12345)
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x17e8
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 TCP segment demonstrating a non-zero acknowledgement value
                #          with all control flags cleared.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x30\x39\x50\x00\x00\x00\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag ns",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ns": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : NS
                #   Window          : 0x0000
                #   Checksum        : 0x4721
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 control segment with the TCP NS flag asserted.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x51\x00\x00\x00\x47\x21\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag cwr",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_cwr": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : CWR
                #   Window          : 0x0000
                #   Checksum        : 0x47a1
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 test frame toggling the Congestion Window Reduced flag.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x80\x00\x00\x47\xa1\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag ece",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ece": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : ECE
                #   Window          : 0x0000
                #   Checksum        : 0x47e1
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 TCP header with the ECN Echo flag asserted.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x40\x00\x00\x47\xe1\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag urg",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_urg": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : URG
                #   Window          : 0x0000
                #   Checksum        : 0x4801
                #   Urgent Pointer  : 0
                #
                # Summary: URG flag set on the IPv6 path without accompanying urgent
                #          data.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x20\x00\x00\x48\x01\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag ack",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ack": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : ACK
                #   Window          : 0x0000
                #   Checksum        : 0x4811
                #   Urgent Pointer  : 0
                #
                # Summary: ACK control bit toggled on the IPv6 transmit path.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x10\x00\x00\x48\x11\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag psh",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_psh": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : PSH
                #   Window          : 0x0000
                #   Checksum        : 0x4819
                #   Urgent Pointer  : 0
                #
                # Summary: Push flag engaged for IPv6 testing with no accompanying data.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x08\x00\x00\x48\x19\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag rst",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_rst": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : RST
                #   Window          : 0x0000
                #   Checksum        : 0x481d
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 reset segment used to verify outbound RST handling.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x04\x00\x00\x48\x1d\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag syn",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_syn": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : SYN
                #   Window          : 0x0000
                #   Checksum        : 0x481f
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 SYN probe equivalent to the IPv4 case above.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x02\x00\x00\x48\x1f\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - flag fin",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_fin": True,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : FIN
                #   Window          : 0x0000
                #   Checksum        : 0x4820
                #   Urgent Pointer  : 0
                #
                # Summary: FIN flag example for IPv6 mirroring the earlier IPv4 scenario.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x01\x00\x00\x48\x20\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_fin=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - win",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__win": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x3039 (12345)
                #   Checksum        : 0x17e8
                #   Urgent Pointer  : 0
                #
                # Summary: IPv6 TCP header advertising a receive window of 12345.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x30\x39\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - urg",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x17e8
                #   Urgent Pointer  : 0x3039 (12345)
                #
                # Summary: Populates the urgent pointer field in an IPv6 TCP header while
                #          leaving the URG flag clear.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x17\xe8\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - data",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 924 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0366 (870 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x62ed
                #   Urgent Pointer  : 0
                #   Payload         : 850 bytes ("01234567890ABCDEF" repeated)
                #
                # Summary: High-volume IPv6 TCP payload example mirroring the IPv4 case.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x03\x66\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x62\xed\x00\x00\x30\x31\x32\x33\x34\x35"
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
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - option mss",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__mss": 12345,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 78 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x05e0
                #   Urgent Pointer  : 0
                #   Options         : MSS (kind 2, len 4, value 12345)
                #
                # Summary: IPv6 counterpart illustrating MSS negotiation via TCP options.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x60\x00\x00\x00\x05\xe0\x00\x00\x02\x04\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_mss=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - option wscale",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__wscale": 14,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 78 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x00000000
                #   Flags           : none set
                #   Window          : 0x0000
                #   Checksum        : 0x340c
                #   Urgent Pointer  : 0
                #   Options         : NOP, Window Scale (value 14)
                #
                # Summary: Demonstrates IPv6 TCP option encoding for window scaling.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x60\x00\x00\x00\x34\x0c\x00\x00\x01\x03\x03\x0e"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_wscale=1,
                tcp__opt_nop=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
    ]
)
class TestTcpTx(TcpTestCase):
    """
    The TCP TX packet-handler path tests (success path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__tcp__tx(self) -> None:
        """
        Ensure the Packet Handler TCP TX path produces the expected
        frames, statuses, and statistics for each parametrized case.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        self.assertEqual(
            self._packet_handler._phtx_tcp(**self._kwargs),
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
            "_description": "TCP - IPv4/IPv6 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__error": ValueError("Invalid IP address version combination: 10.0.1.7 -> 2001:db8:0:1::91"),
        },
        {
            "_description": "TCP - IPv6/IPv4 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__error": ValueError("Invalid IP address version combination: 2001:db8:0:1::7 -> 10.0.1.91"),
        },
    ]
)
class TestTcpTxErrors(TcpTestCase):
    """
    The TCP TX packet-handler path tests (error path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__tcp__tx__error(self) -> None:
        """
        Ensure '_phtx_tcp' raises the expected exception for invalid
        IP address version combinations.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_tcp(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            str(self._expected__error),
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestTcpTxSendTcpPacket(TcpTestCase):
    """
    Test the public 'send_tcp_packet' wrapper, which forwards into
    '_phtx_tcp' renaming the addressing and port kwargs.
    """

    def test__tcp__tx__send_tcp_packet(self) -> None:
        """
        Ensure 'send_tcp_packet' renames its kwargs ('ip__local_address'
        / 'ip__remote_address' → 'ip__src' / 'ip__dst', 'tcp__local_port'
        / 'tcp__remote_port' → 'tcp__sport' / 'tcp__dport') and forwards
        to '_phtx_tcp', producing the same frame and stats as a direct
        '_phtx_tcp' call would.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        tx_status = self._packet_handler.send_tcp_packet(
            ip__local_address=STACK__IP4_HOST.address,
            ip__remote_address=HOST_A__IP4_ADDRESS,
            tcp__local_port=1000,
            tcp__remote_port=2000,
            tcp__flag_syn=True,
            tcp__seq=0x4D2,
            tcp__win=0x2000,
        )

        self.assertEqual(
            tx_status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="send_tcp_packet must propagate the underlying _phtx_tcp TxStatus.",
        )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="send_tcp_packet must emit exactly one frame for a SYN.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            msg="send_tcp_packet stats must match a direct _phtx_tcp SYN call.",
        )
