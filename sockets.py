#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
socket_support.py - module contains class supporting TCP and UDP sockets

"""

import loguru
import time
import threading

from dataclasses import dataclass


class Sockets:
    """ Support for Socket operations """

    class __SocketData:
        """ Socket data """

        def __init__(self):
            self.data_rx = []
            self.data_tx = []
            self.data_ready_rx = threading.Semaphore(0)
            self.data_ready_tx = threading.Semaphore(0)
            self.creation_time = time.time()

    def __init__(self, stack_mac_address, stack_ip_address):
        """ Class constructor """

        self.stack_mac_address = stack_mac_address
        self.stack_ip_address = stack_ip_address

        self.sockets = {}
        self.logger = loguru.logger.bind(object_name="sockets.")

        threading.Thread(target=self.__maintain).start()
        self.logger.debug("Started sockets")

    def __maintain(self):
        """ Thread responsible for maintaining Socket entries """

        while True:
            time.sleep(1)

    def enqueue(self, socket_id, data_rx):
        """ Put data into socket RX queue and release semaphore """

        self.sockets[socket_id].data_rx.append(data_rx)
        self.sockets[socket_id].data_ready_rx.release()

    def enqueue_tx(self, socket_id, data_rt):
        """ Put data into socket TX queue and release semaphore """

        self.sockets[socket_id].data_tx.append(data_tx)
        self.sockets[socket_id].data_ready_tx.release()

    def match_established(self, protocol, local_ip_address, local_port, remote_ip_address, remote_port, serial_number_rx):
        """ Return established socket that matches incoming packet """

        socket_id = f"{protocol}/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}"
        socket = self.sockets.get(socket_id, None)
        if socket:
            self.logger.debug(f"{serial_number_rx} - Found matching established socket {socket_id}")
            return socket_id

    def match_listening(self, protocol, local_ip_address, local_port, serial_number_rx):
        """ Return listening socket that matches incoming packet """

        socket_id = f"{protocol}/{local_ip_address}/{local_port}/0.0.0.0/0"
        socket = self.sockets.get(socket_id, None)
        if socket:
            self.logger.debug(f"{serial_number_rx} - Found matching listening socket {socket_id}")
            return socket_id

    def open(self, protocol, local_port, remote_ip_address="0.0.0.0", remote_port=0):
        """ Create new socket """

        local_ip_address = self.stack_ip_address

        socket_id = f"{protocol}/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}"

        self.sockets[socket_id] = self.__SocketData()

        return socket_id

    def read(self, socket_id):
        """ Read data from socket """

        # Wait till data is available
        self.sockets[socket_id].data_ready_rx.acquire()

        return self.sockets[socket_id].data_rx.pop(0)

    def write(self, socket_id):
        """ Write data to socket """

        pass
