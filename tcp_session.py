#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_session.py - module contains class supporting TCP finite state machine

"""

import loguru
import threading
import random

import stack


DELAYED_ACK_DELAY = 200  # 200ms between consecutive delayed ACK outbound packets
TIME_WAIT_DELAY = 15000  # 15s delay for the TIME_WAIT state, default is 120s
PACKET_RESEND_DELAY = 1000  # 1s for initial packet resend delay, then exponenial
PACKET_RESEND_COUNT = 4  # 4 retries in case we get no response to packet sent


def fsm_trace(function):
    """ Decorator for tracing FSM state """

    def _(self, *args, **kwargs):
        print(
            f"[ >>> ] local_seq_sent {self.local_seq_sent}, local_seq_ackd {self.local_seq_ackd},",
            f"remote_seq_rcvd {self.remote_seq_rcvd}, remote_seq_ackd {self.remote_seq_ackd}",
        )
        retval = function(self, *args, **kwargs)
        print(
            f"[ <<< ] local_seq_sent {self.local_seq_sent}, local_seq_ackd {self.local_seq_ackd},",
            f"remote_seq_rcvd {self.remote_seq_rcvd}, remote_seq_ackd {self.remote_seq_ackd}",
        )
        return retval

    return _


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

        self.remote_seq_init = None
        self.remote_seq_rcvd = None
        self.remote_seq_ackd = None

        self.local_seq_init = random.randint(0, 0xFFFFFFFF)
        self.local_seq_sent = self.local_seq_init
        self.local_seq_ackd = self.local_seq_init
        self.local_seq_fin = None

        self.window_seq_adjustment = self.local_seq_init + 1

        self.state = None
        self.state_init = None

        self.local_win = stack.local_tcp_win
        self.local_mss = stack.local_tcp_mss
        self.remote_win = None
        self.remote_mss = None

        self.event_connect = threading.Semaphore(0)
        self.event_data_rx = threading.Semaphore(0)

        self.lock_fsm = threading.Lock()
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

        old_state = self.state
        self.state = state
        self.state_init = True
        old_state and self.logger.opt(ansi=True, depth=1).info(f"{self.tcp_session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

    @fsm_trace
    def __send_packet(self, seq_num=None, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b""):
        """ Send out TCP packet """

        stack.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_seq_num=seq_num if seq_num else self.local_seq_sent,
            tcp_ack_num=self.remote_seq_rcvd if flag_ack else 0,
            tcp_flag_syn=flag_syn,
            tcp_flag_ack=flag_ack,
            tcp_flag_fin=flag_fin,
            tcp_flag_rst=flag_rst,
            tcp_win=self.local_win,
            tcp_mss=self.local_mss if flag_syn else None,
            raw_data=raw_data,
        )
        self.remote_seq_ackd = self.remote_seq_rcvd
        self.local_seq_sent = (seq_num if seq_num else self.local_seq_sent) + len(raw_data) + flag_syn + flag_fin

        # In case packet is FIN packet, make note of its SEQ number
        if flag_fin:
            self.local_seq_fin = self.local_seq_sent

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

    def __send_data(self):
        """ Send out data segment from TX buffer """

        win_pointer = self.local_seq_sent - self.window_seq_adjustment

        if len(self.data_tx) and self.remote_win - win_pointer:
            if self.local_seq_ackd == self.local_seq_sent:
                with self.lock_data_tx:
                    data_tx = self.data_tx[win_pointer : win_pointer + self.remote_mss]
                    del self.data_tx[: win_pointer + len(data_tx)]
                    self.window_seq_adjustment += win_pointer + len(data_tx)
                self.__send_packet(flag_ack=True, raw_data=bytes(data_tx))
                self.logger.debug(f"Sent out data segment, {len(data_tx)} bytes")

    def __delayed_ack(self):
        """ Run Delayed ACK mechanism """

        if stack.stack_timer.timer_expired(self.tcp_session_id + "delayed_ack"):
            if self.remote_seq_rcvd > self.remote_seq_ackd:
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.remote_seq_rcvd})")
            stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)

    def __handle_regular_ack_packet(self, packet):
        """ Used in ESTABLISHED, FIN_WAIT_1 and FIN_WAIT_2 phases to handle regular ack packet """

        # Make note of how much of our data has been ACKed by peer already
        self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)

        # Check if we are missing any data due to lost packet, if so drop the packet so need of retansmission of lost data is signalized to the peer
        if packet.seq_num > self.remote_seq_rcvd:
            self.logger.warning(f"TCP packet has higher sequence number ({packet.seq_num}) than expected ({packet.ack_num}), droping packet")
            return

        # Respond to TCP Keep-Alive packet
        if packet.seq_num == self.remote_seq_ackd - 1:
            self.logger.debug(f"{self.tcp_session_id} - Received TCP Keep-Alive packet")
            self.__send_packet(flag_ack=True)
            self.logger.debug(f"{self.tcp_session_id} - Sent TCP Keep-Alive ACK packet")
            return

        # If packet's sequence number matches what we are expecting and if packet contains any data then enqueue the data
        if packet.seq_num == self.remote_seq_rcvd and packet.raw_data:
            self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data)
            self.__enqueue_data_rx(packet.raw_data)
            return

    def __tcp_fsm_closed(self, packet, syscall, timer):
        """ TCP FSM CLOSED state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got CONNECT syscall -> Send SYN packet / change state to SYN_SENT
        if syscall == "CONNECT":
            self.__send_packet(flag_syn=True)
            self.logger.debug(f"{self.tcp_session_id} - Sent initial SYN ({self.local_seq_sent}) packet")
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
            # Packet sanity check
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
                self.remote_seq_init = packet.seq_num
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + packet.flag_syn
                # Send SYN + ACK packet / change state to SYN_RCVD
                self.__send_packet(flag_syn=True, flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} Sent initial SYN ({self.local_seq_sent}) + ACK ({self.remote_seq_ackd}) packet")
                self.__change_state("SYN_RCVD")
                return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
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
                self.__send_packet(flag_syn=True, seq_num=self.local_seq_ackd)
                self.syn_sent_resend_count += 1
                self.logger.debug(f"{self.tcp_session_id} Re-sent SYN packet")
                stack.stack_timer.register_timer(self.tcp_session_id + "syn_sent", PACKET_RESEND_DELAY * (1 << self.syn_sent_resend_count))
                return

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if packet and all({packet.flag_syn, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack_num == self.local_seq_sent and not packet.raw_data:
                # Store ACK infomration since ACK flag is present
                self.local_seq_ackd = packet.ack_num
                # Initialize session parameters
                self.remote_win = packet.win
                self.remote_mss = min(packet.mss, stack.mtu - 80)
                self.remote_seq_init = packet.seq_num
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + packet.flag_syn
                # Send ACK packet
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} Sent initial ACK ({self.remote_seq_ackd}) packet")
                # Change state to ESTABLISHED
                self.__change_state("ESTABLISHED")
                # Inform connect syscall that connection related event happened
                self.event_connect.release()
                return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_fin, packet.flag_syn}):
            # Change state to CLOSED
            self.__change_state("CLOSED")
            # Inform connect syscall that connection related event happened
            self.event_connect.release()
            return

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            # Packet sanity check
            if packet.ack_num == 0 and not packet.raw_data:
                # Send SYN + ACK packet
                self.__send_packet(flag_syn=True, flag_ack=True)
                # Change state to SYN_RCVD
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
                self.__send_packet(flag_syn=True, flag_ack=True, seq_num=self.local_seq_ackd)
                self.syn_rcvd_resend_count += 1
                self.logger.debug(f"{self.tcp_session_id} Re-sent SYN + ACK packet")
                stack.stack_timer.register_timer(self.tcp_session_id + "syn_rcvd", PACKET_RESEND_DELAY * (1 << self.syn_rcvd_resend_count))
                return

        # Got ACK packet -> Change state to ESTABLISHED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack_num == self.local_seq_sent and not packet.raw_data:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Change state to ESTABLISHED
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
            # stack.stack_timer.register_timer(self.tcp_session_id + "delayed_ack", DELAYED_ACK_DELAY)
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self.__send_data()
            self.__delayed_ack()
            return

        # Got ACK packet -> Process data
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data)
                # In case packet contains data enqueue it
                packet.raw_data and self.__enqueue_data_rx(packet.raw_data)
                return

        # Got FIN + ACK packet -> Send ACK packet (let delayed ACK mechanism do it) / change state to CLOSE_WAIT / notifiy app that peer closed connection
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer, only if higher than already noted
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data) + packet.flag_fin
                # In case packet contains data enqueue it
                packet.raw_data and self.__enqueue_data_rx(packet.raw_data)
                # Let application know that remote peer closed connection
                self.event_data_rx.release()
                # Change state to CLOSE_WAIT
                self.__change_state("CLOSE_WAIT")
                return

        # Got CLOSE syscall -> Send FIN packet / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            while self.data_tx:
                self.__send_data()
            self.__send_packet(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_fin_wait_1(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_1 state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK (acking our FIN) packet -> Change state to FIN_WAIT_2 
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data)
                # In case packet contains data enqueue it and send out ACK
                if packet.raw_data:
                    self.__enqueue_data_rx(packet.raw_data)
                    self.__send_packet(flag_ack=True)
                # Check if packet acks our FIN
                if packet.ack_num >= self.local_seq_fin:
                    # Change state to FIN_WAIT_2
                    self.__change_state("FIN_WAIT_2")
            return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT or CLOSING
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + packet.flag_fin
                # In case packet contains data enqueue it
                packet.raw_data and self.__enqueue_data_rx(packet.raw_data)
                # Send out final ACK packet
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.remote_seq_rcvd}) packet")
                # Check if packet acks our FIN
                if packet.ack_num >= self.local_seq_fin:
                    # Change state to TIME_WAIT
                    self.__change_state("TIME_WAIT")
                else:
                    # Change state to CLOSING
                    self.__change_state("CLOSING")
            return

    def __tcp_fsm_fin_wait_2(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_2 state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK packet -> Process data
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data)
                # In case packet contains data enqueue it and send out ACK
                if packet.raw_data:
                    self.__enqueue_data_rx(packet.raw_data)
                    self.__send_packet(flag_ack=True)
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq_num == self.remote_seq_rcvd:
                # Make note of the local SEQ that has been acked by peer
                self.local_seq_ackd = max(self.local_seq_ackd, packet.ack_num)
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq_num + len(packet.raw_data) + packet.flag_fin
                # In case packet contains data enqueue it
                packet.raw_data and self.__enqueue_data_rx(packet.raw_data)  # enqueue data if present
                # Send out final ACK packet
                self.__send_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.remote_seq_rcvd}) packet")
                # Change state to TIME_WAIT
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
            if packet.ack_num == self.local_seq_sent:  # packet sanity check
                self.local_seq_ackd = packet.ack_num
                self.__change_state("TIME_WAIT")
                return

    def __tcp_fsm_close_wait(self, packet, syscall, timer):
        """ TCP FSM CLOSE_WAIT state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self.__send_data()
            self.__delayed_ack()
            return

        # Got CLOSE syscall -> Send FIN packet / change state to LAST_ACK
        if syscall == "CLOSE":
            self.__send_packet(flag_fin=True, flag_ack=True)
            self.__change_state("LAST_ACK")
            return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_ack}):
            if packet.ack_num == 0 and packet.seq_num == self.remote_seq_rcvd:  # packet sanity check
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_last_ack(self, packet, syscall, timer):
        """ TCP FSM LAST_ACK state handler """

        # State initialization
        if self.state_init:
            self.state_init = False
            self.logger.debug(f"State {self.state} initialized")

        # Got ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_sent:  # packet sanity check
                self.__change_state("CLOSED")
            return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_ack}):
            if packet.ack_num == 0 and packet.seq_num == self.remote_seq_rcvd:  # packet sanity check
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
