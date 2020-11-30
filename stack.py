#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# stack.py - module holds references to the stack components and global configuration parameters
#


from ipaddress import IPv4Interface, IPv6Interface

# TAP interface name stack should bind itself to
interface = b"tap7"

# Support for IPv6 and IPv4, at least one should be anabled
ip6_support = True
ip4_support = True

# Preliminary packet sanity check, if enabled it protects the Protocol Support classes from being exposed to malformed or malicious packets
# that could cause them to crash during packet parsing. It check minimum length and checksum. It doesn't do any deep packet sanity check.
# That is being done by Packet Handler RX function after the packet has been already parsed...
preliminary_packet_sanity_check = True

# Unicast MAC addresses assigned to stack, currently there is not any kind of duplicate MAC detection performed
mac_address_candidate = ["02:00:00:77:77:77"]

# IPv6 address auto configuration is implemented using EUI64 addressing and ICMPv6 Router Advertisement messages
ip6_lla_autoconfig = True
ip6_gua_autoconfig = True

# Static IPv6 adrsses may to be configured here (they will still be subject to CICMPv6 ND DAD  mechanism)
# Each entry is a tuple interface address/prefix length and second is defaut gateway for this subnet
# Basic routing is implmented and each subnet can have its own gateway
# Link local addresses should have default gateway set to 'None'
ip6_address_candidate = [
    ("FE80::7/64", None),
    # ("FE80::77/64", None),
    # ("FE80::7777/64", None),
    # ("FE80::7777/64", None),  # test duplicate address
    # ("FE80::9999/64", "FE80::1"),  # test link local address with default gateway
    # ("2007::1111/64", "DUPA"),  # test link local address with default gateway
    # ("ZHOPA", None),  # test invalid address
    # ("2099::99/64", "2009::99"),  # test invalid gateway
    # ("2007::7/64", "FE80::1"),
    # ("2009::9/64", "2009::1"),
]

# IPv4 DHCP based address configuration
ip4_address_dhcp_config = True

# Static IPv4 adrsses may to be configured here (they will still be subject to ARP Probe/Announcement mechanism)
# Each entry is a tuple interface address/prefix length and second is defaut gateway for this subnet
# Basic routing is implmented and each subnet can have its own gateway
ip4_address_candidate = [
    ("192.168.9.7/24", "192.168.9.1"),
    # ("192.168.9.77/24", "192.168.9.1"),
    # ("224.0.0.1/24", "192.168.9.1"), # test invalid address type
    # ("DUPA", "192.168.9.1"),  # test invalid address format
    # ("192.168.9.99/24", "DUPA"),  # test invalid gateway format
    # ("192.168.9.77/24", "192.168.9.1"),  # test duplicate address
    # ("192.168.9.170/24", "10.0.0.1"),  # test invalid gateway
    # ("192.168.9.171/24", "192.168.9.0"),  # test invalid gateway
    # ("192.168.9.172/24", "192.168.9.172"),  # test invalid gateway
    # ("192.168.9.173/24", "192.168.9.255"),  # test invalid gateway
    # ("192.168.9.0/24", "192.168.9.1"),  # test invalid address
    # ("192.168.9.255/24", "192.168.9.1"),  # test invalid address
    # ("0.0.0.0/0", None),  # test invalid address
    # ("192.168.9.102/24", None),  # test no gateway
    # ("172.16.17.7/24", "172.16.17.1"),
    # ("10.10.10.7/24", "10.10.10.1"),
]

mtu = 1500  # TAP interface MTU

local_tcp_mss = 1460  # Maximum segment peer can send to us
local_tcp_win = 65535  # Maximum amount of data peer can send to us without confirmation

# Test services, for detailed configuation of each reffer to pytcp.py and respective service/client file
# Those are being used for testing various stack components are therefore their 'default' funcionality may be altered fro specific tst needs
# Eg. TCP daytime service generates large amount of text data used to verify TCP protocol funcionality
service_udp_echo = True
service_udp_discard = True
service_udp_daytime = True
service_tcp_echo = True
service_tcp_discard = True
service_tcp_daytime = True

# For using test clients proper IP addressing needs to be set up in file 'pytcp.py'
client_tcp_echo = False
client_icmp_echo = True

# References to stack components
rx_ring = None
tx_ring = None
arp_cache = None
icmp6_nd_cache = None
packet_handler = None
stack_timer = None

# Stack 'global variables'
tcp_sessions = {}
udp_sockets = {}
