#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading
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

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, metadata=None, socket=None):
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

        self.local_seq_num = random.randint(0, 0xffffffff)
        self.local_ack_num = 0
        self.remote_ack_num = 0
        self.last_sent_local_ack_num = 0
        self.win = 1024
        self.socket = socket
        self.state = "CLOSED"

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

    def listen(self):
        """ LISTEN syscall """

        self.logger.debug(f"State {self.state} - got LISTEN syscall")
        return self.tcp_fsm(syscall="LISTEN")

    def connect(self):
        """ CONNECT syscall """

        self.logger.debug(f"State {self.state} - got CONNECT syscall")
        return self.tcp_fsm(syscall="CONNECT")

    def send(self, raw_data):
        """ Send out raw_data passed from socket """

        self.__send(flag_ack=True, raw_data=raw_data)

    def close(self):
        """ Close syscall """

        self.logger.debug(f"State {self.state} - got CLOSE syscall")
        return self.tcp_fsm(syscall="CLOSE")

    def __tcp_fsm_closed(self, metadata=None, syscall=None):
        """ TCP FSM CLOSED state handler """

        # Got CONNECT syscall -> Send SYN packet, change state to SYN_SENT
        if syscall == "CONNECT":
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

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall == "LISTEN":
            self.__change_state("LISTEN")

    def __tcp_fsm_listen(self, metadata=None, syscall=None):
        """ TCP FSM LISTEN state handler """

        # Got SYN packet -> Change state to SYN_RCVD / send out SYN + ACK
        if metadata and all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_syn
            self.__change_state("SYN_RCVD")
            self.__send(flag_syn=True, flag_ack=True, tracker=metadata.tracker)
            return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

        # Got SEND syscall -> Send SYN packet, change state to SYS_SENT
        if syscall == "SEND":

            # *** Further research and possible implementation needed ***

            return

    def __tcp_fsm_syn_sent(self, metadata=None, syscall=None):
        """ TCP FSM SYN_SENT state handler """

        # Got SYN + ACK packet -> Change state to ESTABLISHED / send ACK
        if metadata and all({metadata.flag_syn, metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.local_ack_num = metadata.seq_num + metadata.flag_syn
                self.__change_state("ESTABLISHED")
                self.__send(flag_ack=True, tracker=metadata.tracker)
                # Notify connect method that the connection related event happened
                self.syn_sent_event.release()
                # Start thread supporting Delayed ACK mechanism
                threading.Thread(target=self.__thread_delayed_ack).start()
                return

        # Got RST -> Change state to CLOSED
        if metadata and all({metadata.flag_rst}) and not any({metadata.flag_fin, metadata.flag_syn}):
            self.__change_state("CLOSED")
            # Notify connect method that the connection related event happened
            self.syn_sent_event.release()
            return

        # Got SYN packet -> Change state to SYN_RCVD / send SYN + ACK
        if metadata and all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_syn}):
            self.__change_state("SYN_RCVD")
            self.__send(flag_syn=True, flag_ack=True, tracker=metadata.tracker)
            return

        # Got CLOSE syscall -> Change state to CLOSE
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_rcvd(self, metadata=None, syscall=None):
        """ TCP FSM ESTABLISHED state handler """

        # Got ACK packet -> Change state to ESTABLISHED
        if metadata and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("ESTABLISHED")
                # Inform socket that session has been established
                self.socket.tcp_session_established.release()
                # Start thread supporting Delayed ACK mechanism
                threading.Thread(target=self.__thread_delayed_ack).start()
                return

        # Got RST packet -> Change state to LISTEN
        if metadata and all({metadata.flag_rst}) and not any({metadata.flag_syn, metadata.flag_fin}):
            self.__change_state("LISTEN")
            return

        # Got CLOSE sycall -> Send FIN, change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_established(self, metadata=None, syscall=None):
        """ TCP FSM ESTABLISHED state handler """

        # got ACK packet
        if metadata and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):

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

        # Got FIN packet -> Send ACK and change state to CLOSE_WAIT, notifiy application that peer closed connection
        if metadata and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("CLOSE_WAIT")
            # Shut down thread supporting Delayed ACK mechanism
            self.run_thread_delayed_ack = False
            # Let application know that remote end closed connection
            self.data_rx.append(None)
            self.data_rx_ready.release()
            return

        # Got CLOSE syscall -> Send FIN, change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_fin_wait_1(self, metadata=None, syscall=None):
        """ TCP FSM FIN_WAIT_1 state handler """

        # *** In this state we should still be able to receive data from peer - needs to be investigated and possibly implemented ***

        # Got ACK packet -> Change state to FIN_WAIT_2
        if metadata and all({metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("FIN_WAIT_2")
                return

        # Got FIN + ACK packet -> Send ACK for peer's FIN and change state to TIME_WAIT
        if metadata and all({metadata.flag_fin, metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.local_ack_num = metadata.seq_num + metadata.flag_fin
                self.__send(flag_ack=True, tracker=metadata.tracker)
                self.__change_state("TIME_WAIT")
                self.__change_state("CLOSED")
                return

        # Got FIN packet -> Send ACK for peer's FIN and change state to CLOSING
        if metadata and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("CLOSING")
            return

    def __tcp_fsm_fin_wait_2(self, metadata=None, syscall=None):
        """ TCP FSM FIN_WAIT_2 state handler """

        # Got FIN packet -> Change state to TIME_WAIT
        if metadata and all({metadata.flag_fin}) and not any({metadata.flag_syn, metadata.flag_rst}):
            self.local_ack_num = metadata.seq_num + metadata.flag_fin
            self.__send(flag_ack=True, tracker=metadata.tracker)
            self.__change_state("TIME_WAIT")
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_closing(self, metadata=None, syscall=None):
        """ TCP FSM CLOSING state handler """

        # Got ACK packet -> Change state to TIME_WAIT
        if metadata and all({metadata.flag_ack}) and not any({metadata.flag_fin, metadata.flag_syn, metadata.flag_rst}):
            if metadata.ack_num == self.local_seq_num:
                self.__change_state("TIME_WAIT")
                self.__change_state("CLOSED")
                return

    def __tcp_fsm_close_wait(self, metadata=None, syscall=None):
        """ TCP FSM CLOSE_WAIT state handler """

        # Got CLOSE syscall -> Send FIN, change state to LAST_ACK
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("LAST_ACK")
            return

    def __tcp_fsm_last_ack(self, metadata=None, syscall=None):
        """ TCP FSM LAST_ACK state handler """

        # Got ACK packet -> Change state to CLOSED
        if metadata and all({metadata.flag_ack}) and not any({metadata.flag_syn, metadata.flag_fin, metadata.flag_rst}):
            self.remote_seq_num = metadata.seq_num
            self.remote_ack_num = metadata.ack_num
            self.__change_state("CLOSED")
            # Remove socket
            TcpSocket.open_sockets.pop(self.session_id)
            self.logger.debug(f"Deleted socket {self.session_id}")
            return

    def __tcp_fsm_time_wait(self, metadata=None, syscall=None):
        """ TCP FSM TIME_WAIT state handler """

        # *** Threaded timer implementation needed to handle this state properly ***

        pass

    def tcp_fsm(self, metadata=None, syscall=None):
        """ Run TCP finite state machine """

        # Make note of remote ACK number that indcates how much of data we sent was received
        if metadata:
            self.remote_ack_num = metadata.ack_num

        return {
            "CLOSED": self.__tcp_fsm_closed,
            "LISTEN": self.__tcp_fsm_listen,
            "SYN_SENT": self.__tcp_fsm_syn_sent,
            "SYN_RCVD": self.__tcp_fsm_syn_rcvd,
            "ESTABLISHED": self.__tcp_fsm_established,
            "FIN_WAIT_1": self.__tcp_fsm_fin_wait_1,
            "FIN_WAIT_2": self.__tcp_fsm_fin_wait_2,
            "CLOSING": self.__tcp_fsm_closing,
            "CLOSE_WAIT": self.__tcp_fsm_close_wait,
            "LAST_ACK": self.__tcp_fsm_last_ack,
            "TIME_WAIT": self.__tcp_fsm_time_wait,
        }[self.state](metadata, syscall)


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
        if socket := TcpSocket.open_sockets.get(metadata.session_id, None):
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of established sessin {metadata.session_id}")
            socket.tcp_session.tcp_fsm(metadata=metadata)
            return True

        # Check if incoming packet is an initial SYN packet and matches any listening socket, if so create new session and assign it to that socket
        if all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            for socket_id in metadata.listening_socket_ids:
                if socket := TcpSocket.open_sockets.get(socket_id, None):
                    tcp_session = TcpSession(metadata=metadata, socket=socket)
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet with SYN flag, created new session {tcp_session}")
                    socket.tcp_sessions[tcp_session.session_id] = tcp_session
                    tcp_session.listen()
                    tcp_session.tcp_fsm(metadata=metadata)
                    return True

        # Check if incoming packet matches any listening socket
        for socket_id in metadata.listening_socket_ids:
            if socket := TcpSocket.open_sockets.get(socket_id, None):
                if tcp_session := socket.tcp_sessions.get(metadata.session_id, None):
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of existing session {tcp_session}")
                    tcp_session.tcp_fsm(metadata=metadata)
                    return True
