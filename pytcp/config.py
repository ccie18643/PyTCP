#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# config.py - module contains global configuration parameters
#

from sys import version_info
from typing import Optional

assert version_info >= (3, 9), "PyTCP requires Python version 3.9 or higher"

# TAP interface name stack should bind itself to
TAP_INTERFACE = b"tap7"

# Support for IPv6 and IPv4, at least one should be anabled
IP6_SUPPORT = True
IP4_SUPPORT = True

# Logger configuration - LOG_CHANEL sets which subsystems of stack log to console, LOG_DEBUG adds info about class/method caller
# Following subsystems are supported:
# stack, timer, rx-ring, tx-ring, arp-c, nd-c, ether, arp, ip4, ip6, icmp4, icmp6, udp, tcp, socket, tcp-ss, service
LOG_CHANEL = {
    "stack",
    #    "timer",
    "rx-ring",
    "tx-ring",
    "arp-c",
    "nd-c",
    "ether",
    "arp",
    "ip4",
    "ip6",
    "icmp4",
    "icmp6",
    "udp",
    "tcp",
    "socket",
    "tcp-ss",
    "service",
    "client",
}
LOG_DEBUG = False

# Packet integrity sanity check, if enabled it protects the protocol parsers from being exposed to malformed or malicious packets
# that could cause them to crash during packet parsing. It progessively check appropriate length fields and ensure they are set within sane boundaries.
# It also checks packet's actual header/options/data lengths against above values and default minimum/maximum lengths for given protocol.
# Also packet options (if any) are checked in similar fashion to ensure they will not exploit or crash parser.
PACKET_INTEGRITY_CHECK = True

# Packet sanity check, if enabled it validates packet's fields to detect invalid values or invalid combinations of values
# For example in TCP/UDP it drops packets with port set to 0, in TCP it drop packet with SYN and FIN flags set simultaneously,
# for ICMPv6 it provides very detailed check of messages integrity
PACKET_SANITY_CHECK = True

# Drop IPv4 packets containing options - this seems to be widely adopted security feature. Stack parses but doesn't support IPv4 options
# as they are mostly useless anyway.
IP4_OPTION_PACKET_DROP = False

# Unicast MAC addresses assigned to stack, currently there is not any kind of duplicate MAC detection performed
MAC_ADDRESS = "02:00:00:77:77:77"

# IPv6 address auto configuration is implemented using EUI64 addressing and ICMPv6 Router Advertisement messages
IP6_LLA_AUTOCONFIG = True
IP6_GUA_AUTOCONFIG = True

# IPv6 default Hop Limit value
IP6_DEFAULT_HOP = 64

# IPv4 default TTL value
IP4_DEFAULT_TTL = 64

# IPv4 and IPv6 fragmnt flow expiration time, determines for how many seconds fragment flow is considered valid
# Fragemnt flows are being cleaned up prior of handling every fragmented packet
IP4_FRAG_FLOW_TIMEOUT = 5
IP6_FRAG_FLOW_TIMEOUT = 5

# Static IPv6 adrsses may to be configured here (they will still be subject to CICMPv6 ND DAD  mechanism)
# Each entry is a tuple interface address/prefix length and second is default gateway for this subnet
# Basic routing is implemented and each subnet can have its own gateway
# Link local addresses should have default gateway set to 'None'
IP6_HOST_CANDIDATE: list[tuple[str, Optional[str]]] = [
    ("FE80::7/64", None),
    # ("2007::7/64", "FE80::1"),
]

# IPv4 DHCP based address configuration
IP4_HOST_DHCP = True

# Static IPv4 adrsses may to be configured here (they will still be subject to ARP Probe/Announcement mechanism)
# Each entry is a tuple interface address/prefix length and second is default gateway for this subnet
# Basic routing is implemented and each subnet can have its own gateway
IP4_HOST_CANDIDATE: list[tuple[str, Optional[str]]] = [
    ("192.168.9.7/24", "192.168.9.1"),
    # ("192.168.9.77/24", "192.168.9.1"),
    # ("172.16.17.7/24", "172.16.17.1"),
    # ("10.10.10.7/24", "10.10.10.1"),
]

# ARP cache configuration
ARP_CACHE_ENTRY_MAX_AGE = 3600
ARP_CACHE_ENTRY_REFRESH_TIME = 300
ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = True
ARP_CACHE_UPDATE_FROM_GRATUITIOUS_REPLY = True

# ICMPv6 ND cache configuration
ND_CACHE_ENTRY_MAX_AGE = 3600
ND_CACHE_ENTRY_REFRESH_TIME = 300

# TCP/UDP ephemeral port range to be used by outbound connections
EPHEMERAL_PORT_RANGE = range(32168, 60700, 2)

# TAP interface MTU, describes how much payload Ethernet packet can carry
TAP_MTU = 1500

# TCP session related settings
LOCAL_TCP_MSS = 1460  # Maximum segment peer can send to us
LOCAL_TCP_WIN = 65535  # Maximum amount of data peer can send to us without confirmation

# Native support for UDP Echo (used for packet flow unit testing only and should always be disabled)
UDP_ECHO_NATIVE_DISABLE = True
