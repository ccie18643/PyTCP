#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
socket_support.py - module contains class supporting TCP and UDP sockets

"""

import loguru
import time
import threading

from dataclasses import dataclass


class Socket:
    """ Support for Socket operations """

    class __SocketData:
        """ Socket data """

        def __init__(self):
            self_data_rx = []
            self.data_ready_rx = threading.Semaphore(0)
            self.creation_time = time.time()
            self.last_read_time = None
            self.last_write_time = None

    def __init__(self, stack_mac_address, stack_ip_address):
        """ Class constructor """

        self.open_sockets = {}
        self.logger = loguru.logger.bind(object_name="socket.")

        threading.Thread(target=self.__maintain).start()

    def __maintain(self):
        """ Thread responsible for maintaining ARP entries """

        time.sleep(1)

    def rx_feed(self, socket_id, data_rx):
        """ Put data into socket RX queue and release semaphore """

        self.open_sockets[socket_id].data_rx.append(data_rx)
        self.open_sockets[socket_id].data_ready_rx.release()

    def open_socket(self, protocol, src_ip_address, src_port, dst_ip_address, dst_port):
        """ Create new socket """

        socket_id = "{protocol}/{src_ip_address}/{src_port}/{dst_ip_address}/{dst_port}"

        self.open_seockets[socket_id] = __SocketData()

        return socket_id

    def read_socket(self, socket_id):
        """ Read data from socket """

        # Wait till data is available
        self.open_sockets[socket_id].data_ready_rx.acquire()

        return self.open_sockts[socket_id].data_rx.pop(0)
