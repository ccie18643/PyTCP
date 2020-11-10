#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_ip.py - packet handler for outbound IP packets

"""

import struct
import socket

import ps_ip
import ps_ether

import stack


def validate_source_ip_address(self, ip_src):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

    # Check if the the source IP address belongs to this stack or its set to all zeros (for DHCP client comunication)
    if ip_src not in self.stack_ip_unicast and ip_src not in self.stack_ip_multicast and ip_src not in self.stack_ip_broadcast and ip_src != "0.0.0.0":
        self.logger.warning(f"Unable to sent out IP packet, stack doesn't own IP address {ip_src}")
        return

    # If packet is a response to multicast then replace source IP address with primary IP address of the stack
    if ip_src in self.stack_ip_multicast or ip_src == "255.255.255.255":
        if self.stack_ip_unicast:
            ip_src = self.stack_ip_unicast[0]
            self.logger.debug(f"Packet is response to multicast, replaced source with stack primary IP address {ip_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no stack primary unicast IP address available")
            return

    # If packet is a response to limite broadcast then replace source IP address with primary IP address of the stack
    if ip_src == "255.255.255.255":
        if self.stack_ip_unicast:
            ip_src = self.stack_ip_unicast[0]
            self.logger.debug(f"Packet is response to limited broadcast, replaced source with stack primary IP address {ip_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no stack primary unicast IP address available")
            return

    # If packet is a response to directed braodcast then replace source IP address with first IP address that belongs to appropriate subnet
    if ip_src in self.stack_ip_broadcast:
        ip_src = [_[0] for _ in self.stack_ip_address if _[3] == ip_src]
        if ip_src:
            ip_src = ip_src[0]
            self.logger.debug(f"Packet is response to directed broadcast, replaced source with apropriate IP address {ip_src}")
        else:
            self.logger.warning("Unable to sent out IP packet, no appropriate stack unicast IP address available")
            return

    return ip_src


def phtx_ip(self, child_packet, ip_dst, ip_src):
    """ Handle outbound IP packets """

    ip_src = validate_source_ip_address(self, ip_src)
    if not ip_src:
        return

    # Generate new IP ID
    self.ip_id += 1
    if self.ip_id > 65535:
        self.ip_id = 1

    # Check if IP packet can be sent out without fragmentation, if so send it out
    if ps_ip.IP_HEADER_LEN + len(child_packet.raw_packet) <= stack.mtu:
        ip_packet_tx = ps_ip.IpPacket(ip_src=ip_src, ip_dst=ip_dst, ip_id=self.ip_id, child_packet=child_packet)

        self.logger.debug(f"{ip_packet_tx.tracker} - {ip_packet_tx}")
        self.phtx_ether(child_packet=ip_packet_tx)
        return

    # Fragment packet and send all fragments out
    self.logger.debug("Packet exceedes available MTU, IP fragmentation needed...")

    if child_packet.protocol == "ICMP":
        ip_proto = ps_ip.IP_PROTO_ICMP
        raw_data = child_packet.get_raw_packet()

    if child_packet.protocol in {"UDP", "TCP"}:
        ip_proto = ps_ip.IP_PROTO_UDP if child_packet.protocol == "UDP" else ps_ip.IP_PROTO_TCP
        raw_data = child_packet.get_raw_packet(
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(ip_src),
                socket.inet_aton(ip_dst),
                0,
                ip_proto,
                len(child_packet.raw_packet),
            )
        )

    raw_data_mtu = (stack.mtu - ps_ether.ETHER_HEADER_LEN - ps_ip.IP_HEADER_LEN) & 0b1111111111111000
    raw_data_fragments = [raw_data[_ : raw_data_mtu + _] for _ in range(0, len(raw_data), raw_data_mtu)]

    n = 0
    offset = 0

    for raw_data_fragment in raw_data_fragments:
        ip_packet_tx = ps_ip.IpPacket(
            ip_src=ip_src,
            ip_dst=ip_dst,
            ip_proto=ip_proto,
            ip_id=self.ip_id,
            ip_frag_mf=True if n < len(raw_data_fragments) - 1 else False,
            ip_frag_offset=offset,
            raw_data=raw_data_fragment,
            tracker=child_packet.tracker,
        )
        n += 1
        offset += len(raw_data_fragment)

        self.logger.debug(f"{ip_packet_tx.tracker} - {ip_packet_tx}")
        self.phtx_ether(child_packet=ip_packet_tx)

    return
