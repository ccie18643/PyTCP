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

    def __init__(self, metadata, state="CLOSED"):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.local_ip_address = metadata.local_ip_address
        self.local_port = metadata.local_port
        self.local_seq_num = random.randint(0, 0xFFFFFFFF)
        self.local_ack_num = 0

        self.remote_ip_address = metadata.remote_ip_address
        self.remote_port = metadata.remote_port
        self.remote_seq_num = None
        self.remote_ack_num = None

        self.win = 1200

        self.state = state
        self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>CLOSED -> {self.state}</>")

    def __str__(self):
        """ String representation """

        return self.session_id

    def __send(self, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, tracker=None):
        """ Send out TCP packet """

        TcpSocket.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_seq_num=self.local_seq_num,
            tcp_ack_num=self.local_ack_num,
            tcp_flag_syn=flag_syn,
            tcp_flag_ack=flag_ack,
            tcp_flag_fin=flag_fin,
            tcp_flag_rst=flag_rst,
            tcp_win=self.win,
            echo_tracker=tracker,
        )

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def process(self, metadata):
        """ Process metadata of incoming TCP packet """

        # Check if we not missing any data, due to lost packets

        #self.local_ack_num = metadata.seq_num + metadata.flag_syn + metadata.flag_fin + len(metadata.raw_data)

        # In LISTEN state and got SYN packet -> Change state to SYC_RCVD and send out SYN/ACK
        if self.state == "LISTEN" and all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            self.state = "SYN_RCVD"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>LISTEN -> SYN_RCVD</>")
            self.local_ack_num = metadata.seq_num + 1
            self.__send(flag_syn=True, flag_ack=True, tracker=metadata.tracker)
            self.local_seq_num += 1
            return

        # In SYN_RCVD state and got ACK packet -> Change state to ESTABLISED
        if (self.state == "SYN_RCVD" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst})):
            self.state = "ESTABLISHED"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>SYN_RCVD -> ESTABLISHED</>")
            return

        # In ESTABLISHED state and got ACK packet -> Send ACK packet
        if self.state == "ESTABLISHED" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):

            if metadata.seq_num > self.local_ack_num:
                self.logger.warning(f"TCP packet has higher sequence number ({metadata.seq_num}) than expected ({metadata.ack_num}), droping packet")
                return

            if metadata.seq_num + len(metadata.raw_data) > self.local_ack_num:
                self.local_ack_num = metadata.seq_num + len(metadata.raw_data)
                self.__send(flag_ack=True, tracker=metadata.tracker)
                return

        # In ESTABLISHED state and got FIN/ACK packet -> Send ACK and change state to CLOSE_WAIT, then wait for aplication to close socket
        if self.state == "ESTABLISHED" and all({metadata.flag_fin, metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_rst}):
            
            self.local_ack_num = metadata.seq_num + 1
            self.__send(flag_ack=True, tracker=metadata.tracker) 
            self.state = "CLOSE_WAIT"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>ESTABLISHED -> CLOSE_WAIT</>")

            # Need to comunicate to socket that the session got closed

            self.__send(flag_fin=True, flag_ack=True, tracker=metadata.tracker) 
            self.local_seq_num += 1
            self.state = "LAST_ACK"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>CLOSE_WAIT -> LAST_ACK</>")
            return

        # In LAST_ACK state and got ACK packet -> Change state to CLOSED and delete session
        if self.state == "LAST_ACK" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            self.remote_seq_num = metadata.seq_num
            self.remote_ack_num = metadata.ack_num
            self.state = "CLOSED"
            self.logger.opt(ansi=True).info(f"{self.session_id} - State change: <yellow>LAST_ACK -> CLOSED</>")
            TcpSocket.tcp_sessions.pop(self.session_id)
            return


class TcpSocket:
    """ Support for Socket operations """

    tcp_sessions = {}
    open_sockets = {}

    packet_handler = None

    def __init__(self, local_ip_address, local_port, remote_ip_address="0.0.0.0", remote_port=0):
        """ Class constructor """

        self.messages = []
        self.messages_ready = threading.Semaphore(0)
        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        TcpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def send(self, raw_data):
        """ Put raw_data into TX ring """

        pass

    def receive(self):
        """ Read data from established socket and return raw_data """

        pass

    def listen(self):
        """ Wait till there is session established on listening socket """

        pass

    def accept(self):
        """ Pick up established session from listening socket and create new established socket for it """

        pass

    def close(self):
        """ Close socket """

        pass

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        TcpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(metadata):
        """ Class method - Try to match incoming packet with either established or listening socket """

        # Check if incoming packet is part of existing session
        session = TcpSocket.tcp_sessions.get(metadata.session_id, None)

        if session:
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of existing session {session}")
            session.process(metadata)
            return True

        # Check if incoming packet contains intial SYN and there is listening socket that matches it, if so create new session
        if metadata.flag_syn and any(_ in metadata.listening_socket_ids for _ in TcpSocket.open_sockets):
            session = TcpSocket.tcp_sessions[metadata.session_id] = TcpSession(metadata, state="LISTEN")
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet with SYN flag, created new session {session}")
            session.process(metadata)
            return True
