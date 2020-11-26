#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_ipv6.py - packet handler for outbound IPv6 packets

"""

from ipaddress import IPv6Address

import ps_ipv6

import stack


def validate_src_ipv6_address(self, ipv6_src):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

    # Check if the the source IP address belongs to this stack or its set to all zeros (for ND DAD)
    if ipv6_src not in {*self.stack_ipv6_unicast, *self.stack_ipv6_multicast, IPv6Address("::")}:
        self.logger.warning(f"Unable to sent out IPv6 packet, stack doesn't own IPv6 address {ipv6_src}")
        return

    # If packet is a response to multicast then replace source IPv6 address with link local IPv6 address of the stack
    if ipv6_src in self.stack_ipv6_multicast:
        if self.stack_ipv6_unicast:
            ipv6_src = self.stack_ipv6_unicast[0]
            self.logger.debug(f"Packet is response to multicast, replaced source with stack link local IPv6 address {ipv6_src}")
        else:
            self.logger.warning("Unable to sent out IPv6 packet, no stack link local unicast IPv6 address available")
            return

    # If packet is a response to All IPv6 Nodes multicast then replace source IPv6 address with link local IPv6 address of the stack
    if ipv6_src == IPv6Address("ff02::1"):
        if self.stack_ipv6_unicast:
            ipv6_src = self.stack_ipv6_unicast[0]
            self.logger.debug(f"Packet is response to All IPv6 Nodes multicast, replaced source with stack link local IPv6 address {ipv6_src}")
        else:
            self.logger.warning("Unable to sent out IPv6 packet, no stack link local unicast IP address available")
            return

    # If packet has all zeros source address set but the link local address is available then replace it
    if ipv6_src == IPv6Address("::") and self.stack_ipv6_unicast:
        ipv6_src = self.stack_ipv6_unicast[0]

    return ipv6_src

def validate_dst_ipv6_address(self, ipv6_dst):
    """ Make sure destination ip address is valid, supplemt with valid one as appropriate """

    # Check if destiantion address is all zeroes, substitute it with All IPv6 Nodes multicast address
    if ipv6_dst == IPv6Address("::"):
        ipv6_dst = IPv6Address("ff02::1")

    return ipv6_dst

def phtx_ipv6(self, child_packet, ipv6_dst, ipv6_src):
    """ Handle outbound IP packets """

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not self.stack_ipv6_support:
        return

    # Validate source address
    ipv6_src = validate_src_ipv6_address(self, ipv6_src)
    if not ipv6_src:
        return

    # Validate destination address
    ipv6_dst = validate_dst_ipv6_address(self, ipv6_dst)
    if not ipv6_dst:
        return

    # Check if IP packet can be sent out without fragmentation, if so send it out
    if ps_ipv6.IPV6_HEADER_LEN + len(child_packet.raw_packet) <= stack.mtu:
        ipv6_packet_tx = ps_ipv6.IPv6Packet(ipv6_src=ipv6_src, ipv6_dst=ipv6_dst, child_packet=child_packet)

        self.logger.debug(f"{ipv6_packet_tx.tracker} - {ipv6_packet_tx}")
        self.phtx_ether(child_packet=ipv6_packet_tx)
        return

    # Fragment packet and send all fragments out *** Need to add this functionality ***
    self.logger.debug("Packet exceedes available MTU, IPv6 fragmentation needed... droping...")
    return
