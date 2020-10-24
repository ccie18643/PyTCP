#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phtx_ether.py - packet handler for outbound Ethernet packets

"""

import ps_ether


def phtx_ether(self, child_packet, ether_src="00:00:00:00:00:00", ether_dst="00:00:00:00:00:00"):
    """ Handle outbound Ethernet packets """

    ether_packet_tx = ps_ether.EtherPacket(hdr_src=ether_src, hdr_dst=ether_dst, child_packet=child_packet)

    self.logger.debug(f"{ether_packet_tx.tracker} - {ether_packet_tx}")
    self.tx_ring.enqueue(ether_packet_tx)
