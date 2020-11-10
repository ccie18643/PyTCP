#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_session.py - module contains class supporting TCP finite state machine

"""

import loguru
import threading
import random

import stack

from tracker import Tracker


DELAYED_ACK_DELAY = 200  # 200ms between consecutive delayed ACK outbound packets
TIME_WAIT_DELAY = 15000  # 15s delay for the TIME_WAIT state, default is 120s
PACKET_RESEND_DELAY = 1000  # 1s for initial packet resend delay, then exponenial
PACKET_RESEND_COUNT = 4  # 4 retries in case we get no response to packet sent


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, socket=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket = socket

        self.data_rx = []
        self.data_tx = []

        self.remote_seq_rcvd = None
        self.remote_seq_ackd = None

        self.local_seq_sent = random.randint(0, 0xFFFFFFFF)
        self.local_seq_ackd = self.local_seq_sent

        self.state = None
        self.state_init = None

        self.local_win = stack.local_tcp_win
        self.local_mss = stack.local_tcp_mss
        self.remote_win = None
        self.remote_mss = None

        self.event_connect = threading.Semaphore(0)
        self.event_data_rx = threading.Semaphore(0)

        self.lock_fsm = threading.RLock()
        self.lock_data_rx = threading.Lock()
        self.lock_data_tx = threading.Lock()

        self.__change_state("CLOSED")
        stack.stack_timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})

    def __str__(self):
        """ String representation """

        return self.tcp_session_id

    @property
    def tcp_session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def __change_state(self, state):
        """ Change the state of TCP finite state machine """

        with self.lock_fsm:
            old_state = self.state
            self.state = state
            self.state_init = True
            if old_state:
                self.logger.opt(ansi=True, depth=1).info(f"{self.tcp_session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

    def __send_packet(self, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b"", tracker=None, echo_tracker=None):
        """ Send out TCP packet """

        stack.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_seq_num=self.local_seq_ackd,
            tcp_ack_num=self.remote_seq_rcvd if flag_ack else 0,
            tcp_flag_syn=flag_syn,
            tcp_flag_ack=flag_ack,
            tcp_flag_fin=flag_fin,
            tcp_flag_rst=flag_rst,
            tcp_win=self.local_win,
            tcp_mss=self.local_mss if flag_syn else None,
            raw_data=raw_data,
            tracker=tracker,
            echo_tracker=echo_tracker,
        )
        self.remote_seq_ackd = self.remote_seq_rcvd
        self.local_seq_sent = self.local_seq_ackd + len(raw_data) + flag_syn + flag_fin

        # If in ESTABLISHED state then reset ACK delay timer
        if self.state == "ESTABLISHED":
            stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)

    def listen(self):
        """ LISTEN syscall """

        self.logger.debug(f"State {self.state} - got LISTEN syscall")
        return self.tcp_fsm(syscall="LISTEN")

    def connect(self):
        """ CONNECT syscall """

        self.logger.debug(f"State {self.state} - got CONNECT syscall")
        self.tcp_fsm(syscall="CONNECT")
        self.event_connect.acquire()
        return self.state == "ESTABLISHED"

    def send(self, raw_data):
        """ Send out raw_data passed from socket """

        if self.state in {"ESTABLISHED", "CLOSE_WAIT"}:
            with self.lock_data_tx:
                self.data_tx.extend(list(raw_data))
                return len(raw_data)

    def receive(self, byte_count=None):
        """ Read bytes from RX buffer """

        # Wait till there is any data in the buffer
        self.event_data_rx.acquire()

        # If there is no data in RX buffer and remote end closed connection then notify application
        if not self.data_rx and self.state == "CLOSE_WAIT":
            return None

        with self.lock_data_rx:
            if byte_count is None:
                byte_count = len(self.data_rx)
            else:
                byte_count = min(byte_count, len(self.data_rx))

            data_rx = self.data_rx[:byte_count]
            del self.data_rx[:byte_count]

            # If there is any data left in buffer or the remote end closed connection then release the data_rx event
            if len(self.data_rx) or self.state == "CLOSE_WAIT":
                self.event_data_rx.release()

        return bytes(data_rx)

    def close(self):
        """ Close syscall """

        self.logger.debug(f"State {self.state} - got CLOSE syscall")
        return self.tcp_fsm(syscall="CLOSE")

    def __enqueue_data_rx(self, raw_data):
        """ Process the incoming segment and enqueue the data to be used by socket """

        # Gain exclusive access to the buffer
        with self.lock_data_rx:
            self.data_rx.extend(list(raw_data))

            # If data_rx event has not been realeased yet (it could be released if some data were siting in buffer already) then release it
            if not self.event_data_rx._value:
                self.event_data_rx.release()

    def __tcp_fsm_closed(self, packet, syscall, timer):
        """ TCP FSM CLOSED state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got CONNECT syscall -> Send SYN packet / change state to SYN_SENT
        if syscall == "CONNECT":
            self.__send_packet(flag_syn=True)
            self.logger.debug(f"{self.tcp_session_id} - Sent initial SYN packet")
            self.__change_state("SYN_SENT")

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall == "LISTEN":
            self.__change_state("LISTEN")

    def __tcp_fsm_listen(self, packet, syscall, timer):
        """ TCP FSM LISTEN state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == 0 and not packet.raw_data:

                # Create new session in LISTEN state
                tcp_session = TcpSession(
                    local_ip_address=self.local_ip_address,
                    local_port=self.local_port,
                    remote_ip_address=self.remote_ip_address,
                    remote_port=self.remote_port,
                    socket=self.socket,
                )
                tcp_session.listen()

                # Adjust this session to match incoming connection
                stack.tcp_sessions.pop(self.tcp_session_id)
                self.local_ip_address = packet.local_ip_address
                self.local_port = packet.local_port
                self.remote_ip_address = packet.remote_ip_address
                self.remote_port = packet.remote_port
                stack.tcp_sessions[self.tcp_session_id] = self

                # Register the new listening session
                stack.tcp_sessions[tcp_session.tcp_session_id] = tcp_session

                # Initialize session parameters
                self.remote_win = packet.win
                self.remote_mss = min(packet.mss, stack.mtu - 80)

                # Send SYN + ACK packet / change state to SYN_RCVD
                self.remote_seq_rcvd = packet.seq_num + packet.flag_syn
                self.__send_packet(flag_syn=True, flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} Sent SYN+ACK packet")
                self.__change_state("SYN_RCVD")
                return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

        # Got SEND syscall -> Send SYN packet / change state to SYS_SENT
        if syscall == "SEND":

            # *** Further research and possible implementation needed ***

            return

    def __tcp_fsm_syn_sent(self, packet, syscall, timer):
        """ TCP FSM SYN_SENT state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.syn_sent_resend_count = 0
            stack.stack_timer.register_timer(self.tcp_session_id + "syn_sent", PACKET_RESEND_DELAY)
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event / syn_sent timer expired / no ACK yet received -> Re-send SYN packet
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "syn_sent"):
            if self.local_seq_ackd < self.local_seq_sent:
                if self.syn_sent_resend_count == PACKET_RESEND_COUNT:
                    self.__change_state("CLOSED")
                    return
                self.__send_packet(flag_syn=True)
                self.syn_sent_resend_count += 1
                self.logger.debug(f"{self.tcp_session_id} Re-sent SYN packet")
                stack.stack_timer.register_timer(self.tcp_session_id + "syn_sent", PACKET_RESEND_DELAY * (1 << self.syn_sent_resend_count))
                return

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if packet and all({packet.flag_syn, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent and not packet.raw_data:

                self.local_seq_ackd = packet.ack_num

                # Initialize session parameters
                self.remote_win = packet.win
                self.remote_mss = min(packet.mss, stack.mtu - 80)

                # Send ACK / change state to ESTABLISHED
                self.remote_seq_rcvd = packet.seq_num + packet.flag_syn
                self.__send_packet(flag_ack=True)
                self.__change_state("ESTABLISHED")

                # Inform connect syscall that connection related event happened
                self.event_connect.release()
                return

        # Got RST -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_fin, packet.flag_syn}):
            self.__change_state("CLOSED")
            # Inform connect syscall that connection related event happened
            self.event_connect.release()
            return

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            if packet.ack_num == 0 and not packet.raw_data:
                self.__send_packet(flag_syn=True, flag_ack=True)
                self.__change_state("SYN_RCVD")
                return

        # Got CLOSE syscall -> Change state to CLOSE
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_rcvd(self, packet, syscall, timer):
        """ TCP FSM ESTABLISHED state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.syn_rcvd_resend_count = 0
            stack.stack_timer.register_timer(self.tcp_session_id + "syn_rcvd", PACKET_RESEND_DELAY)
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event / syn_rcvd timer expired / no ACK yet received -> Re-send SYN + ACK packet
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "syn_rcvd"):
            if self.local_seq_ackd < self.local_seq_sent:
                if self.syn_rcvd_resend_count == PACKET_RESEND_COUNT:
                    self.__change_state("CLOSED")
                    return
                self.__send_packet(flag_syn=True, flag_ack=True)
                self.syn_rcvd_resend_count += 1
                self.logger.debug(f"{self.tcp_session_id} Re-sent SYN + ACK packet")
                stack.stack_timer.register_timer(self.tcp_session_id + "syn_rcvd", PACKET_RESEND_DELAY * (1 << self.syn_rcvd_resend_count))
                return

        # Got ACK packet -> Change state to ESTABLISHED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent and not packet.raw_data:
                self.local_seq_ackd = packet.ack_num
                self.__change_state("ESTABLISHED")
                # Inform socket that session has been established so accept method can pick it up
                self.socket.event_tcp_session_established.release()
                # Inform connect syscall that connection related event happened, this is needed only in case of tcp simultaneous open
                self.event_connect.release()
                return

        # Got CLOSE sycall -> Send FIN packet / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send_packet(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_established(self, packet, syscall, timer):
        """ TCP FSM ESTABLISHED state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event -> send out data segment from TX buffer
        if timer and self.data_tx:
            if self.local_seq_ackd == self.local_seq_sent:
                with self.lock_data_tx:
                    data_tx = self.data_tx[: self.remote_mss]
                    del self.data_tx[: self.remote_mss]
                self.__send_packet(flag_ack=True, raw_data=bytes(data_tx))
                self.logger.debug(f"Sent out data segment, {len(data_tx)} bytes")
            return

        # Got timer event -> run Delayed ACK mechanism
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "delayed_ack"):
            if self.remote_seq_rcvd > self.remote_seq_ackd:
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.remote_seq_rcvd})")
            stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)
            return

        # Got ACK packet
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):

            # Make note of how much of our data has been ACKed by peer already
            self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)

            # Check if we are missing any data due to lost packet, if so drop the packet so need of retansmission of lost data is signalized to the peer
            if packet.seq_num > self.remote_seq_ackd:
                self.logger.warning(f"TCP packet has higher sequence number ({packet.seq_num}) than expected ({packet.ack_num}), droping packet")
                return

            # Respond to TCP Keep-Alive packet
            if packet.seq_num == self.remote_seq_ackd - 1:
                self.logger.debug(f"{packet.tracker} - Received TCP Keep-Alive packet")
                tracker = Tracker("TX", packet.tracker)
                self.__send_packet(flag_ack=True, tracker=tracker)
                self.logger.debug(f"{tracker} - Sent TCP Keep-Alive ACK packet")
                return

            # If packet's sequence number matches what we are expecting and if packet contains any data then enqueue the data
            if packet.seq_num == self.remote_seq_ackd and packet.raw_data:
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data)
                self.__enqueue_data_rx(packet.raw_data)

        # Got FIN packet -> Send ACK packet (let delayed ACK mechanism do it) / change state to CLOSE_WAIT / notifiy application that peer closed connection
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            if packet.seq_num == self.remote_seq_rcvd:
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data) + packet.flag_fin
                # Let application know that remote peer closed connection by releasing the semaphore on empty buffer
                self.event_data_rx.release()
                self.__change_state("CLOSE_WAIT")
                return

        # Got CLOSE syscall -> Send FIN packet / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send_packet(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_fin_wait_1(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_1 state handler """

        # *** In this state we should still be able to receive data from peer - needs to be investigated and possibly implemented ***

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK packet -> Change state to FIN_WAIT_2
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent:
                self.local_seq_ackd = packet.ack_num
                self.__change_state("FIN_WAIT_2")
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent:
                self.local_seq_ackd = packet.ack_num
                self.remote_seq_rcvd = packet.seq_num + packet.flag_fin
                self.__send_packet(flag_ack=True, tracker=packet.tracker)
                self.__change_state("TIME_WAIT")
                return

        # Got FIN packet -> Send ACK packet / change state to CLOSING
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            self.remote_seq_rcvd = packet.seq_num + packet.flag_fin
            self.__send_packet(flag_ack=True, tracker=packet.tracker)
            self.__change_state("CLOSING")
            return

    def __tcp_fsm_fin_wait_2(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_2 state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got FIN packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            self.remote_seq_rcvd = packet.seq_num + packet.flag_fin
            self.__send_packet(flag_ack=True, tracker=packet.tracker)
            self.__change_state("TIME_WAIT")
            return

    def __tcp_fsm_closing(self, packet, syscall, timer):
        """ TCP FSM CLOSING state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK packet -> Change state to TIME_WAIT
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent:
                self.local_seq_ackd = packet.ack_num
                self.__change_state("TIME_WAIT")
                return

    def __tcp_fsm_close_wait(self, packet, syscall, timer):
        """ TCP FSM CLOSE_WAIT state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event -> send out data segment from TX buffer
        if timer and self.data_tx:
            if self.local_seq_ackd == self.local_seq_sent:
                with self.lock_data_tx:
                    data_tx = self.data_tx[: self.remote_mss]
                    del self.data_tx[: self.remote_mss]
                self.__send_packet(flag_ack=True, raw_data=bytes(data_tx))
                self.logger.debug(f"Sent out data segment, {len(data_tx)} bytes")
            return

        # Got timer event -> run Delayed ACK mechanism
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "delayed_ack"):
            if self.remote_seq_rcvd > self.remote_seq_ackd:
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.remote_seq_rcvd})")
            stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)
            return

        # Got CLOSE syscall -> Send FIN packet / change state to LAST_ACK
        if syscall == "CLOSE":
            self.__send_packet(flag_fin=True, flag_ack=True)
            self.__change_state("LAST_ACK")
            return

    def __tcp_fsm_last_ack(self, packet, syscall, timer):
        """ TCP FSM LAST_ACK state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent:
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_time_wait(self, packet, syscall, timer):
        """ TCP FSM TIME_WAIT state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            stack.stack_timer.register_timer(self.tcp_session_id + "time_wait", TIME_WAIT_DELAY)
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event -> Run TIME_WAIT delay
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "time_wait"):
            self.__change_state("CLOSED")
            return

    def tcp_fsm(self, packet=None, syscall=None, timer=False):
        """ Run TCP finite state machine """

        # Process event
        with self.lock_fsm:
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
            }[self.state](packet, syscall, timer)
