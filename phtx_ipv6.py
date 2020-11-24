#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_ipv6.py - packet handler for outbound IPv6 packets

"""

import ps_ipv6

import stack


def validate_source_ipv6_address(self, ipv6_src):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

    """
    # Check if the the source IP address belongs to this stack or its set to all zeros (for DHCP client comunication)
    if (
        ipv4_src not in self.stack_ipv4_unicast
        and ipv4_src not in self.stack_ipv4_multicast
        and ipv4_src not in self.stack_ipv4_broadcast
        and ipv4_src != "0.0.0.0"
    ):
        self.logger.warning(f"Unable to sent out IP packet, stack doesn't own IP address {ipv4_src}")
        return

    # If packet is a response to multicast then replace source IP address with primary IP address of the stack
    if ipv4_src in self.stack_ipv4_multicast:
        if self.stack_ipv4_unicast:
            ipv4_src = self.stack_ipv4_unicast[0]
            self.logger.debug(f"Packet is response to multicast, replaced source with stack primary IP address {ipv4_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no stack primary unicast IP address available")
            return

    # If packet is a response to limited broadcast then replace source IP address with primary IP address of the stack
    if ipv4_src == "255.255.255.255":
        if self.stack_ipv4_unicast:
            ipv4_src = self.stack_ipv4_unicast[0]
            self.logger.debug(f"Packet is response to limited broadcast, replaced source with stack primary IP address {ipv4_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no stack primary unicast IP address available")
            return

    # If packet is a response to directed braodcast then replace source IP address with first IP address that belongs to appropriate subnet
    if ipv4_src in self.stack_ipv4_broadcast:
        ipv4_src = [_[0] for _ in self.stack_ipv4_address if _[3] == ipv4_src]
        if ipv4_src:
            ipv4_src = ipv4_src[0]
            self.logger.debug(f"Packet is response to directed broadcast, replaced source with apropriate IP address {ipv4_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no appropriate stack unicast IP address available")
            return
    """
    return ipv6_src


def phtx_ipv6(self, child_packet, ipv6_dst, ipv6_src):
    """ Handle outbound IP packets """

    ipv6_src = validate_source_ipv6_address(self, ipv6_src)
    if not ipv6_src:
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
