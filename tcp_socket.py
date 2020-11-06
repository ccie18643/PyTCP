#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading
import time
import random

from tracker import Tracker


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

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, metadata=None, socket=None, state="CLOSED"):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.syn_sent_event = threading.Semaphore(0)

        # Initialize session based on incoming packet metadata
        if metadata:
            self.local_ip_address = metadata.local_ip_address
            self.local_port = metadata.local_port
            self.remote_ip_address = metadata.remote_ip_address
            self.remote_port = metadata.remote_port

        # Initialize session manualy
        else:
            self.local_ip_address = local_ip_address
            self.local_port = local_port
            self.remote_ip_address = remote_ip_address
            self.remote_port = remote_port

        self.local_seq_num = random.randint(0, 0xFFFFFFFF)
        self.local_ack_num = 0
        self.remote_ack_num = 0
        self.last_sent_local_ack_num = 0
        self.win = 1024
        self.socket = socket
        self.state = "CLOSED"
        self.__change_state(state)

        self.data_rx = []
        self.data_rx_ready = threading.Semaphore(0)

        self.run_thread_delayed_ack = None

    def __str__(self):
        """ String representation """

        return self.session_id

    def __send(self, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b"", tracker=None, echo_tracker=None):
        """ Send out TCP packet """

        self.last_sent_local_ack_num = self.local_ack_num

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
            raw_data=raw_data,
            tracker=tracker,
            echo_tracker=echo_tracker,
        )

        self.local_seq_num += len(raw_data) + flag_syn + flag_fin

    def __thread_delayed_ack(self):
        """ Thread supporting the Delayed ACK mechanism """

        self.logger.debug("Started the Delayed ACK thread")

        self.run_thread_delayed_ack = True

        while self.run_thread_delayed_ack:
            from time import sleep

            sleep(0.2)
            if self.local_ack_num > self.last_sent_local_ack_num:
                self.__send(flag_ack=True)
                self.logger.debug(f"{self.session_id} - Sent out delayed ACK ({self.local_ack_num})")

        self.logger.debug("Terminated the Delayed ACK thread")

    def __change_state(self, state):
        """ Change the state of TCP finite state machine """

        if state != self.state:
            old_state = self.state
            self.state = state
            self.logger.opt(ansi=True).info(f"{self.session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def connect(self):
        """ Send initial SYN packet, repeat it till we get SYN + ACK """

        # In CLOSED state / got Connect call -> send SYN packet, change state to SYN_SENT
        if self.state == "CLOSED":
            attempt = 0
            self.__change_state("SYN_SENT")
            while (attempt := attempt + 1) <= 5:
                self.__send(flag_syn=True)
                self.logger.debug(f"{self.session_id} - Sent initial SYN packet, attempt {attempt}")
                if not self.syn_sent_event.acquire(timeout=1 << attempt):
                    continue

                if self.state == "ESTABLISHED":
                    return True

                if self.state == "CLOSED":
                    return False

    def send(self, raw_data):
        """ Send out raw_data passed from socket """

        self.__send(flag_ack=True, raw_data=raw_data)

    def close(self):
        """ Close session """

        # In ESTABLISHED state / got Close call -> Send FIN, change state to FIN_WAIT_1
        if self.state == "ESTABLISHED":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

        # In CLOSE_WAIT state / got Close call -> Send FIN, change state to LAST_ACK
        if self.state == "CLOSE_WAIT":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("LAST_ACK")
            return

    def process_tcp_packet(self, metadata):
        """ Process incoming TCP packet """

        # Make note of remote ACK number that indcates how much of data we sent was received
        self.remote_ack_num = metadata.ack_num

        # In SYN_SENT state / got SYN + ACK packet -> Send ACK and change state to ESTABLISHED
        if self.state == "SYN_SENT" and all({metadata.flag_syn, metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.local_ack_num = metadata.seq_num + metadata.flag_syn
                self.__change_state("ESTABLISHED")
                self.__send(flag_ack=True, tracker=metadata.tracker)
                # Notify connect method that the connection related event happened
                self.syn_sent_event.release()
                # Start thread supporting Delayed ACK mechanism
                threading.Thread(target=self.__thread_delayed_ack).start()
                return

        # In SYN_SENT state / got RST + ACK packet -> Send change state to CLOSED
        if self.state == "SYN_SENT" and all({metadata.flag_rst, metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_syn}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("CLOSED")
                # Notify connect method that the connection related event happened
                self.syn_sent_event.release()
                return

        # In LISTEN state / got SYN packet -> Change state to SYN_RCVD and send out SYN + ACK
        if self.state == "LISTEN" and all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_syn
            self.__change_state("SYN_RCVD")
            self.__send(flag_syn=True, flag_ack=True, tracker=metadata.tracker)
            return

        # In SYN_RCVD state / got ACK packet -> Change state to ESTABLISHED
        if self.state == "SYN_RCVD" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("ESTABLISHED")
                # Inform socket that session has been established
                self.socket.tcp_session_established.release()
                # Start thread supporting Delayed ACK mechanism
                threading.Thread(target=self.__thread_delayed_ack).start()
                return

        # In ESTABLISHED state / got ACK packet
        if self.state == "ESTABLISHED" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):

            # Check if we are missing any data due to lost packet, if so drop the packet so need of retansmission of lost data is signalized to the peer
            if metadata.seq_num > self.local_ack_num:
                self.logger.warning(f"TCP packet has higher sequence number ({metadata.seq_num}) than expected ({metadata.ack_num}), droping packet")
                return

            # Respond to TCP Keep-Alive packet
            if metadata.seq_num == self.local_ack_num - 1:
                self.logger.debug(f"{metadata.tracker} - Received TCP Keep-Alive packet")
                tracker = Tracker("TX", metadata.tracker)
                self.__send(flag_ack=True, tracker=tracker)
                self.logger.debug(f"{tracker} - Sent TCP Keep-Alive ACK packet")
                return

            # If packet's sequence number matches what we are expecting and if packet contains any data then pass the data to socket and send out ACK for it
            if metadata.seq_num == self.local_ack_num and len(metadata.raw_data) > 0:
                self.local_ack_num = metadata.seq_num + len(metadata.raw_data)
                self.data_rx.append(metadata.raw_data)
                self.data_rx_ready.release()
                # self.__send(flag_ack=True, tracker=metadata.tracker)
                return

        # In ESTABLISHED state / got FIN packet -> Send ACK and change state to CLOSE_WAIT, notifiy application that peer closed connection
        if self.state == "ESTABLISHED" and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("CLOSE_WAIT")
            # Shut down thread supporting Delayed ACK mechanism
            self.run_thread_delayed_ack = False
            # Let application know that remote end closed connection
            self.data_rx.append(None)
            self.data_rx_ready.release()
            return

        # In FIN_WAIT_1 state / got ACK -> Change state to FIN_WAIT_2
        if self.state == "FIN_WAIT_1" and all({metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("FIN_WAIT_2")
                return

        # In FIN_WAIT_1 state / got FIN + ACK -> Send ACK for peer's FIN and change state to TIME_WAIT
        if self.state == "FIN_WAIT_1" and all({metadata.flag_fin, metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.local_ack_num = metadata.seq_num + metadata.flag_fin
                self.__send(flag_ack=True, tracker=metadata.tracker)
                self.__change_state("TIME_WAIT")
                self.__change_state("CLOSED")
                return

        # In FIN_WAIT_1 state / got FIN -> Send ACK for peer's FIN and change state to CLOSING
        if self.state == "FIN_WAIT_1" and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("CLOSING")
            return

        # In CLOSING state / got ACK -> Change state to TIME_WAIT
        if self.state == "CLOSING" and all({metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("TIME_WAIT")
                self.__change_state("CLOSED")
                return

        # In FIN_WAIT_2 state / got FIN -> Change state to TIME_WAIT
        if self.state == "FIN_WAIT_2" and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("TIME_WAIT")
            self.__change_state("CLOSED")
            return

        # In LAST_ACK state and got ACK packet -> Change state to CLOSED and remove socket
        if self.state == "LAST_ACK" and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            self.remote_seq_num = metadata.seq_num
            self.remote_ack_num = metadata.ack_num
            self.__change_state("CLOSED")
            TcpSocket.open_sockets.pop(self.session_id)
            self.logger.debug(f"Deleted socket {self.session_id}")
            return

        # *** Need to handle situation when we get some kind of bogus packet, send RST in response perhaps ?


class TcpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    packet_handler = None

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, tcp_session=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        self.tcp_session_established = threading.Semaphore(0)

        # Create established socket based on established TCP session, used by listening sockets only
        if tcp_session:
            self.tcp_session = tcp_session
            self.tcp_session_established.release()
            self.local_ip_address = tcp_session.local_ip_address
            self.local_port = tcp_session.local_port
            self.remote_ip_address = tcp_session.remote_ip_address
            self.remote_port = tcp_session.remote_port

        # Create established socket and start new TCP session
        elif all((local_ip_address, remote_ip_address, remote_port)):
            self.tcp_session = None
            self.local_ip_address = local_ip_address
            self.local_port = self.__pick_random_local_port()
            self.remote_ip_address = remote_ip_address
            self.remote_port = remote_port

        # Create listening socket
        else:
            self.tcp_sessions = {}
            self.local_ip_address = local_ip_address
            self.local_port = local_port
            self.remote_ip_address = "0.0.0.0"
            self.remote_port = 0

        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"
        TcpSocket.open_sockets[self.socket_id] = self
        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def connect(self, timeout=None):
        """ Attempt to establish TCP connection """

        self.tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port,
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )

        return self.tcp_session.connect()

    def __pick_random_local_port(self):
        """ Pick random local port, making sure it is not already being used by any socket """

        used_ports = {int(_.split("/")[2]) for _ in TcpSocket.open_sockets if _.split("/")[1] in {"0.0.0.0", self.local_ip_address}}

        while (port := random.randint(1024, 65535)) not in used_ports:
            return port

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
            socket.tcp_session.process_tcp_packet(metadata)
            return True

        # Check if incoming packet is an initial SYN packet and matches any listening socket, if so create new session and assign it to that socket
        if all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            for socket_id in metadata.listening_socket_ids:
                socket = TcpSocket.open_sockets.get(socket_id, None)
                if socket:
                    session = TcpSession(metadata=metadata, socket=socket, state="LISTEN")
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet with SYN flag, created new session {session}")
                    socket.tcp_sessions[session.session_id] = session
                    session.process_tcp_packet(metadata)
                    return True

        # Check if incoming packet matches any listening socket
        for socket_id in metadata.listening_socket_ids:
            socket = TcpSocket.open_sockets.get(socket_id, None)
            if socket:
                session = socket.tcp_sessions.get(metadata.session_id, None)
                if session:
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of existing session {session}")
                    session.process_tcp_packet(metadata)
                    return True
