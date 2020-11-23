#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_ipv4.py - packet handler for outbound IPv4 packets

"""

import struct
import socket

import ps_ipv4
import ps_ether

import stack


def validate_source_ipv4_address(self, ipv4_src):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

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

    return ipv4_src


def phtx_ipv4(self, child_packet, ipv4_dst, ipv4_src):
    """ Handle outbound IP packets """

    ipv4_src = validate_source_ipv4_address(self, ipv4_src)
    if not ipv4_src:
        return

    # Generate new IP ID
    self.ipv4_packet_id += 1
    if self.ipv4_packet_id > 65535:
        self.ipv4_packet_id = 1

    # Check if IP packet can be sent out without fragmentation, if so send it out
    if ps_ipv4.IPV4_HEADER_LEN + len(child_packet.raw_packet) <= stack.mtu:
        ipv4_packet_tx = ps_ipv4.IPv4Packet(ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, ipv4_packet_id=self.ipv4_packet_id, child_packet=child_packet)

        self.logger.debug(f"{ipv4_packet_tx.tracker} - {ipv4_packet_tx}")
        self.phtx_ether(child_packet=ipv4_packet_tx)
        return

    # Fragment packet and send all fragments out
    self.logger.debug("Packet exceedes available MTU, IP fragmentation needed...")

    if child_packet.protocol == "ICMP":
        ipv4_proto = ps_ipv4.IPV4_PROTO_ICMP
        raw_data = child_packet.get_raw_packet()

    if child_packet.protocol in {"UDP", "TCP"}:
        ipv4_proto = ps_ipv4.IPV4_PROTO_UDP if child_packet.protocol == "UDP" else ps_ipv4.IPV4_PROTO_TCP
        raw_data = child_packet.get_raw_packet(
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(ipv4_src),
                socket.inet_aton(ipv4_dst),
                0,
                ipv4_proto,
                len(child_packet.raw_packet),
            )
        )

    raw_data_mtu = (stack.mtu - ps_ether.ETHER_HEADER_LEN - ps_ipv4.IPV4_HEADER_LEN) & 0b1111111111111000
    raw_data_fragments = [raw_data[_ : raw_data_mtu + _] for _ in range(0, len(raw_data), raw_data_mtu)]

    n = 0
    offset = 0

    for raw_data_fragment in raw_data_fragments:
        ipv4_packet_tx = ps_ipv4.IPv4Packet(
            ipv4_src=ipv4_src,
            ipv4_dst=ipv4_dst,
            ipv4_proto=ipv4_proto,
            ipv4_packet_id=self.ipv4_packet_id,
            ipv4_frag_mf=True if n < len(raw_data_fragments) - 1 else False,
            ipv4_frag_offset=offset,
            raw_data=raw_data_fragment,
            tracker=child_packet.tracker,
        )
        n += 1
        offset += len(raw_data_fragment)

        self.logger.debug(f"{ipv4_packet_tx.tracker} - {ipv4_packet_tx}")
        self.phtx_ether(child_packet=ipv4_packet_tx)

    return
