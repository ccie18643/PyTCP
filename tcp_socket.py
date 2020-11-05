#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading
import random


class TcpPacketMetadata:
    """ Store TCP metadata """

    def __init__(
        self, local_ip_address, local_port, remote_ip_address, remote_port, flag_syn, flag_ack, flag_fin, flag_rst, seq_num, ack_num, win, raw_data, tracker
    ):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.flag_syn = flag_syn
        self.flag_ack = flag_ack
        self.flag_fin = flag_fin
        self.flag_rst = flag_rst
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.win = win
        self.raw_data = raw_data
        self.tracker = tracker

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def listening_socket_ids(self):
        """ Session ID """

        return [
            f"TCP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0",
            f"TCP/0.0.0.0/{self.local_port}/0.0.0.0/0",
        ]


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, metadata, socket, state="CLOSED"):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.local_ip_address = metadata.local_ip_address
        self.local_port = metadata.local_port
        self.remote_ip_address = metadata.remote_ip_address
        self.remote_port = metadata.remote_port
        self.seq_num = random.randint(0, 0xFFFFFFFF)
        self.ack_num = 0
        self.win = 1024
        self.state = state
        self.socket = socket
        self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>CLOSED -> {self.state}</>")

        self.data_rx = []
        self.data_rx_ready = threading.Semaphore(0)

    def __str__(self):
        """ String representation """

        return self.session_id

    def __send(self, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b"", tracker=None):
        """ Send out TCP packet """

        TcpSocket.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_seq_num=self.seq_num,
            tcp_ack_num=self.ack_num,
            tcp_flag_syn=flag_syn,
            tcp_flag_ack=flag_ack,
            tcp_flag_fin=flag_fin,
            tcp_flag_rst=flag_rst,
            tcp_win=self.win,
            raw_data=raw_data,
            echo_tracker=tracker,
        )

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def send(self, raw_data):
        """ Send out raw_data passed from socket """

        self.__send(flag_ack=True, raw_data=raw_data)
        self.seq_num += len(raw_data)

    def close(self):
        """ Close session """

        self.__send(flag_fin=True, flag_ack=True)
        self.seq_num += 1
        self.state = "LAST_ACK"
        self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>CLOSE_WAIT -> LAST_ACK</>")

    def process(self, metadata):
        """ Process metadata of incoming TCP packet """

        # In LISTEN state and got SYN packet -> Change state to SYC_RCVD and send out SYN/ACK
        if self.state == "LISTEN" and all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            self.state = "SYN_RCVD"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>LISTEN -> SYN_RCVD</>")
            self.ack_num = metadata.seq_num + 1
            self.__send(flag_syn=True, flag_ack=True, tracker=metadata.tracker)
            self.seq_num += 1
            return

        # In SYN_RCVD state and got ACK packet -> Change state to ESTABLISHED
        if self.state == "SYN_RCVD" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            self.state = "ESTABLISHED"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>SYN_RCVD -> ESTABLISHED</>")
            self.socket.tcp_session_established.release()
            return

        # In ESTABLISHED state and got ACK packet -> Send ACK packet
        if self.state == "ESTABLISHED" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):

            # Check if we are missing any data due to lost packet, if so drop the packet so need of retansmission of lost data is signalized to the peer
            if metadata.seq_num > self.ack_num:
                self.logger.warning(f"TCP packet has higher sequence number ({metadata.seq_num}) than expected ({metadata.ack_num}), droping packet")
                return

            # If packet's sequence number matches what we are expecting and if packet contains any data, if so pass the data to socket and send out ACK for it
            if metadata.seq_num == self.ack_num and len(metadata.raw_data) > 0:
                self.ack_num = metadata.seq_num + len(metadata.raw_data)
                self.data_rx.append(metadata.raw_data)
                self.data_rx_ready.release()
                self.__send(flag_ack=True, tracker=metadata.tracker)
                return

        # In ESTABLISHED state and got FIN/ACK packet -> Send ACK and change state to CLOSE_WAIT, then wait for aplication to close socket
        if self.state == "ESTABLISHED" and all({metadata.flag_fin, metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_rst}):

            self.ack_num = metadata.seq_num + 1
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.state = "CLOSE_WAIT"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>ESTABLISHED -> CLOSE_WAIT</>")

            # Let application know that remote end closed connection
            self.data_rx.append(None)
            self.data_rx_ready.release()
            return

        # In LAST_ACK state and got ACK packet -> Change state to CLOSED and rmove socket
        if self.state == "LAST_ACK" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            self.remote_seq_num = metadata.seq_num
            self.remote_ack_num = metadata.ack_num
            self.state = "CLOSED"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>LAST_ACK -> CLOSED</>")

            TcpSocket.open_sockets.pop(self.session_id)
            self.logger.debug(f"Deleted socket {self.session_id}")
            return

        # *** Need to handle situation when we get some kind of bogus packet, send RST in response perhaps ?


class TcpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    packet_handler = None

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address="0.0.0.0", remote_port=0, tcp_session=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        if tcp_session:
            self.local_ip_address = tcp_session.local_ip_address
            self.local_port = tcp_session.local_port
            self.remote_ip_address = tcp_session.remote_ip_address
            self.remote_port = tcp_session.remote_port
            self.tcp_session = tcp_session

        else:
            self.tcp_sessions = {}
            self.local_ip_address = local_ip_address
            self.local_port = local_port
            self.remote_ip_address = remote_ip_address
            self.remote_port = remote_port

        self.tcp_session_established = threading.Semaphore(0)
        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        TcpSocket.open_sockets[self.socket_id] = self
        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def send(self, raw_data):
        """ Pass raw_data to TCP session """

        self.tcp_session.send(raw_data)

    def receive(self, timeout=None):
        """ Read data from established socket and return raw_data """

        if self.tcp_session.data_rx_ready.acquire(timeout=timeout):
            return self.tcp_session.data_rx.pop(0)

    def listen(self, timeout=None):
        """ Wait till there is session established on listening socket """

        self.logger.debug(f"Waiting till we have established TCP connection in listening socket {self.socket_id}")

        return self.tcp_session_established.acquire(timeout=timeout)

    def accept(self):
        """ Pick up established session from listening socket and create new established socket for it """

        for session_id, session in self.tcp_sessions.items():
            if session.state == "ESTABLISHED":
                return TcpSocket(tcp_session=self.tcp_sessions.pop(session_id))

    def close(self):
        """ Close session """

        if hasattr(self, "tcp_session"):
            self.tcp_session.close()

        if hasattr(self, "tcp_sessions"):
            self.tcp_sessions.clear()
            TcpSocket.open_sockets.pop(self.socket_id)

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        TcpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(metadata):
        """ Class method - Try to match incoming packet with either established or listening socket """

        # Check if incoming packet matches any established socket
        socket = TcpSocket.open_sockets.get(metadata.session_id, None)
        if socket:
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of established sessin {metadata.session_id}")
            socket.tcp_session.process(metadata)
            return True

        # Check if incoming packet is an initial SYN packet and matches any listening socket, if so create new session and assign it to that socket
        if all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            for socket_id in metadata.listening_socket_ids:
                socket = TcpSocket.open_sockets.get(socket_id, None)
                if socket:
                    session = TcpSession(metadata, socket, state="LISTEN")
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet with SYN flag, created new session {session}")
                    socket.tcp_sessions[session.session_id] = session
                    session.process(metadata)
                    return True

        # Check if incoming packet matches any listening socket
        for socket_id in metadata.listening_socket_ids:
            socket = TcpSocket.open_sockets.get(socket_id, None)
            if socket:
                session = socket.tcp_sessions.get(metadata.session_id, None)
                if session:
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of existing session {session}")
                    session.process(metadata)
                    return True
