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
Module contains global configuration parameters.

pytcp/config.py

ver 3.0.2
"""


from __future__ import annotations

from sys import version_info

assert version_info >= (3, 12), "PyTCP requires Python version 3.12 or higher."

# TAP interface name stack should bind itself to.
INTERFACE__TAP__NAME = b"tap7"

# TAP interface MTU, describes how much payload Ethernet packet can carry.
INTERFACE__TAP__MTU = 1500


# Support for IPv6 and IPv4, at least one should be anabled.
IP6__SUPPORT_ENABLED = True
IP4__SUPPORT_ENABLED = True

# Logger configuration - LOG__CHANNEL sets which subsystems of stack log to the
# console, LOG__DEBUG adds info about class/method caller.
# Following subsystems are supported:
# stack, timer, rx-ring, tx-ring, arp-c, nd-c, ether, arp, ip4, ip6, icmp4,
# icmp6, udp, tcp, socket, tcp-ss, service.
LOG__CHANNEL = {
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
    "dhcp4",
    "service",
    "client",
}
LOG__DEBUG = False

# Unicast MAC addresses assigned to stack, currently there is not any kind of
# duplicate MAC detection performed. This can be overridden when stack object
# is created.
ETHERNET__MAC_ADDRESS = "02:00:00:77:77:77"

# IPv6 address auto configuration is implemented using EUI64 addressing and
# ICMPv6 Router Advertisement messages.
IP6__LLA_AUTOCONFIG = True
IP6__GUA_AUTOCONFIG = True

# IPv6 default Hop Limit value.
IP6__DEFAULT_HOP_LIMIT = 64

# IPv4/IPv6 minimum MTU values.
IP4__MIN_MTU = 576  # RFC 791
IP6__MIN_MTU = 1280  # RFC 8200

# IPv4 default TTL value.
IP4__DEFAULT_TTL = 64

# IPv4 and IPv6 fragmnt flow expiration time, determines for how many seconds
# fragment flow is considered valid. Fragemnt flows are being cleaned up prior
# of handling every fragmented packet.
IP4__FRAG_FLOW_TIMEOUT = 5
IP6__FRAG_FLOW_TIMEOUT = 5

# IPv4 DHCP based address configuration.
IP4__HOST_DHCP = True

# ARP cache configuration.
ARP__CACHE__ENTRY_MAX_AGE = 3600
ARP__CACHE__ENTRY_REFRESH_TIME = 300
ARP__CACHE__UPDATE_FROM_DIRECT_REQUEST = True
ARP__CACHE__UPDATE_FROM_GRATUITIOUS_REPLY = True

# ICMPv6 ND cache configuration.
ICMP6__ND__CACHE__ENTRY_MAX_AGE = 3600
ICMP6__ND__CACHE__ENTRY_REFRESH_TIME = 300

# TCP/UDP ephemeral port range to be used by outbound connections.
EPHEMERAL_PORT_RANGE = range(32168, 60700, 2)

# TCP session related settings.
TCP__MIN_MSS = (
    536  # The minimum recommended value of the  Maximum Segment Size (RFC 879).
)
TCP__LOCAL_MSS = 1460  # Maximum segment peer can send to us.
TCP__LOCAL_WIN = (
    65535  # Maximum amount of data peer can send to us without confirmation.
)

# Native support for UDP Echo (used for packet flow unit testing only and should
# always be disabled).
UDP__ECHO_NATIVE__DISABLED = True
