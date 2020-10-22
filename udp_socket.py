#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
udp_socket.py - module contains class supporting TCP and UDP sockets

"""

import loguru
import threading

import ph_ether
import ph_ip
import ph_udp


class UdpMessage:
    """ Store UDP message in socket """

    def __init__(self, raw_data, remote_ip_address, remote_port, serial_number_rx=None, timestamp_rx=None):
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data
        self.serial_number_rx = serial_number_rx
        self.timestamp_rx = timestamp_rx


class UdpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self, local_ip_address, local_port):
        """ Class constructor """

        self.data_rx = []
        self.data_ready_rx = threading.Semaphore(0)
        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        self.socket_id = f"UDP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0"

        UdpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    def enqueue(self, src_ip_address, src_port, raw_data, serial_number_rx, timestamp_rx):
        """ Put data into socket RX queue and release semaphore """

        self.data_rx.append(UdpMessage(raw_data, src_ip_address, src_port, serial_number_rx, timestamp_rx))
        self.data_ready_rx.release()

    def send(self, udp_message):
        """ Put data into TX ring """

        udp_packet_tx = ph_udp.UdpPacket(hdr_sport=self.local_port, hdr_dport=udp_message.remote_port, raw_data=udp_message.raw_data)
        ip_packet_tx = ph_ip.IpPacket(hdr_src=self.local_ip_address, hdr_dst=udp_message.remote_ip_address, child_packet=udp_packet_tx)
        ether_packet_tx = ph_ether.EtherPacket(child_packet=ip_packet_tx)

        # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
        ether_packet_tx.timestamp_rx = udp_message.timestamp_rx
        ether_packet_tx.serial_number_rx = udp_message.serial_number_rx

        self.logger.debug(f"{ether_packet_tx.serial_number_tx} - {ether_packet_tx}")
        self.logger.debug(f"{ether_packet_tx.serial_number_tx} - {ip_packet_tx}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx}</magenta> - {udp_packet_tx}")
        UdpSocket.tx_ring.enqueue(ether_packet_tx)

    def receive(self):
        """ Read data from socket """

        # Wait till data is available
        self.data_ready_rx.acquire()

        return self.data_rx.pop(0)

    def close(self):
        """ Close socket """

        UdpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    @staticmethod
    def set_tx_ring(tx_ring):
        """ Class method - Sets TX ring object to be available for sockets """

        UdpSocket.tx_ring = tx_ring

    @staticmethod
    def match_listening(local_ip_address, local_port, serial_number_rx):
        """ Class method - Return listening socket that matches incoming packet """

        socket_id = f"UDP/{local_ip_address}/{local_port}/0.0.0.0/0"
        socket = UdpSocket.open_sockets.get(socket_id, None)
        if socket:
            logger = loguru.logger.bind(object_name="socket.")
            logger.debug(f"{serial_number_rx} - Found matching listening socket {socket_id}")
            return socket
