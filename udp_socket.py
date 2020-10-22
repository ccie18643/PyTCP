#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
udp_socket.py - module contains class supporting TCP and UDP sockets

"""

import loguru
import time
import threading

from dataclasses import dataclass

import ph_ether
import ph_ip
import ph_udp


open_sockets = {}


def socket():
    return UdpSocket()


def __match_listening(local_ip_address, local_port, serial_number_rx):
    """ Return listening socket that matches incoming packet """

    socket_id = f"UDP/{local_ip_address}/{local_port}/0.0.0.0/0"
    socket = open_sockets.get(socket_id, None)
    if socket:
        logger = loguru.logger.bind(object_name="socket.")
        logger.debug(f"{serial_number_rx} - Found matching listening socket {socket_id}")
        return socket


class UdpSocket:
    """ Support for Socket operations """

    def __init__(self):
        """ Class constructor """

        self.data_rx = []
        self.data_ready_rx = threading.Semaphore(0)

        self.logger = loguru.logger.bind(object_name="socket.")

        self.logger.debug("Created new UDP socket")

    def enqueue(self, data_rx, address):
        """ Put data into socket RX queue and release semaphore """

        self.data_rx.append((data_rx, address))
        self.data_ready_rx.release()
  
    def sendto(self, message, address):
        """ Put data into TX ring """

        udp_packet_tx = ph_udp.UdpPacket(hdr_sport=self.address[1], hdr_dport=address[1], raw_data=message)

        ip_packet_tx = ph_ip.IpPacket(hdr_src=self.address[0], hdr_dst=address[0], child_packet=udp_packet_tx)

        ether_packet_tx = ph_ether.EtherPacket(
            hdr_src=stack_mac_address,
            hdr_dst="00:00:00:00:00:00",
            child_packet=ip_packet_tx,
        )

        self.logger.debug(f"{ether_packet_tx.serial_number_tx} - {ether_packet_tx}")
        self.logger.debug(f"{ether_packet_tx.serial_number_tx} - {ip_packet_tx}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx}</magenta> - {udp_packet_tx}")
        tx_ring.enqueue(ether_packet_tx)

    def bind(self, address):
        """ Create new socket """

        self.address = address

        socket_id = f"UDP/{address[0]}/{address[1]}/0.0.0.0/0"

        open_sockets[socket_id] = self
        
        self.logger.debug(f"Socket bound to {socket_id}")

    def recvfrom(self):
        """ Read data from socket """

        # Wait till data is available
        self.data_ready_rx.acquire()

        return self.data_rx.pop(0)
