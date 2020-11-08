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
TIME_WAIT_DELAY = 120000  # 2 minutes delay for the TIME_WAIT state


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, socket=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.syn_sent_event = threading.Semaphore(0)

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

        self.data_rx = []
        self.data_rx_ready = threading.Semaphore(0)

        stack.stack_timer.register_method(method=self.tcp_fsm, kwargs={"timer": True}, delay=100)

    def __str__(self):
        """ String representation """

        return self.tcp_session_id

    def __send(self, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b"", tracker=None, echo_tracker=None):
        """ Send out TCP packet """

        self.last_sent_local_ack_num = self.local_ack_num

        stack.packet_handler.phtx_tcp(
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

    def __change_state(self, state):
        """ Change the state of TCP finite state machine """

        old_state = self.state
        self.state = state
        self.logger.opt(ansi=True).info(f"{self.tcp_session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

        # Execute state specific 'state entry code'
        if self.state == "TIME_WAIT":
            stack.stack_timer.register_timer("time_wait", TIME_WAIT_DELAY)

        if self.state == "ESTABLISHED":
            stack.stack_timer.register_timer("delayed_ack", DELAYED_ACK_DELAY)

    @property
    def tcp_session_id(self):
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

    def __tcp_fsm_closed(self, packet=None, syscall=None, timer=None):
        """ TCP FSM CLOSED state handler """

        # Got timer event -> Disable timer thread, unregister session
        # if timer:
        #    stack.tcp_sessions.pop(self.tcp_session_id, None)
        # *** Need to fix so it desnt fire up in initial CLOSE state

        # Got CONNECT syscall -> Send SYN packet / change state to SYN_SENT
        if syscall == "CONNECT":
            attempt = 0
            self.__change_state("SYN_SENT")
            while (attempt := attempt + 1) <= 5:
                self.__send(flag_syn=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent initial SYN packet, attempt {attempt}")
                if not self.syn_sent_event.acquire(timeout=1 << attempt):
                    continue
                if self.state == "ESTABLISHED":
                    return True
                if self.state == "CLOSED":
                    return False

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall == "LISTEN":
            self.__change_state("LISTEN")

    def __tcp_fsm_listen(self, packet=None, syscall=None, timer=None):
        """ TCP FSM LISTEN state handler """

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_rst}):

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

            # Process FSM event
            self.local_ack_num = packet.seq_num + packet.flag_syn
            self.__send(flag_syn=True, flag_ack=True, tracker=packet.tracker)
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

    def __tcp_fsm_syn_sent(self, packet=None, syscall=None, timer=None):
        """ TCP FSM SYN_SENT state handler """

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if packet and all({packet.flag_syn, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.local_ack_num = packet.seq_num + packet.flag_syn
                self.__send(flag_ack=True, tracker=packet.tracker)
                self.__change_state("ESTABLISHED")
                # Notify connect method that the connection related event happened
                self.syn_sent_event.release()
                return

        # Got RST -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_fin, packet.flag_syn}):
            self.__change_state("CLOSED")
            # Notify connect method that the connection related event happened
            self.syn_sent_event.release()
            return

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            self.__send(flag_syn=True, flag_ack=True, tracker=packet.tracker)
            self.__change_state("SYN_RCVD")
            return

        # Got CLOSE syscall -> Change state to CLOSE
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_rcvd(self, packet=None, syscall=None, timer=None):
        """ TCP FSM ESTABLISHED state handler """

        # Got timer event -> Re-sent SYN + ACK packet if needed
        pass

        # Got ACK packet -> Change state to ESTABLISHED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.__change_state("ESTABLISHED")
                # Inform socket that session has been established
                self.socket.tcp_session_established.release()
                return

        # Got CLOSE sycall -> Send FIN packet / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_established(self, packet=None, syscall=None, timer=None):
        """ TCP FSM ESTABLISHED state handler """

        # Got timer event, run Delayed ACK mechanism
        if timer and stack.stack_timer.timer_expired("delayed_ack"):
            if self.local_ack_num > self.last_sent_local_ack_num:
                self.__send(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.local_ack_num})")
            stack.stack_timer.register_timer("delayed_ack", DELAYED_ACK_DELAY)
            return

        # Got ACK packet
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):

            # Check if we are missing any data due to lost packet, if so drop the packet so need of retansmission of lost data is signalized to the peer
            if packet.seq_num > self.local_ack_num:
                self.logger.warning(f"TCP packet has higher sequence number ({packet.seq_num}) than expected ({packet.ack_num}), droping packet")
                return

            # Respond to TCP Keep-Alive packet
            if packet.seq_num == self.local_ack_num - 1:
                self.logger.debug(f"{packet.tracker} - Received TCP Keep-Alive packet")
                tracker = Tracker("TX", packet.tracker)
                self.__send(flag_ack=True, tracker=tracker)
                self.logger.debug(f"{tracker} - Sent TCP Keep-Alive ACK packet")
                return

            # If packet's sequence number matches what we are expecting and if packet contains any data then pass the data to socket
            if packet.seq_num == self.local_ack_num and len(packet.raw_data) > 0:
                self.local_ack_num = packet.seq_num + len(packet.raw_data)
                self.data_rx.append(packet.raw_data)
                self.data_rx_ready.release()
                return

        # Got FIN packet -> Send ACK packet / change state to CLOSE_WAIT / notifiy application that peer closed connection
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            self.local_ack_num = packet.seq_num + packet.flag_fin
            self.__send(flag_ack=True, tracker=packet.tracker)
            self.__change_state("CLOSE_WAIT")
            # Let application know that remote end closed connection
            self.data_rx.append(None)
            self.data_rx_ready.release()
            return

        # Got CLOSE syscall -> Send FINapcket / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_fin_wait_1(self, packet=None, syscall=None, timer=None):
        """ TCP FSM FIN_WAIT_1 state handler """

        # *** In this state we should still be able to receive data from peer - needs to be investigated and possibly implemented ***

        # Got ACK packet -> Change state to FIN_WAIT_2
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.__change_state("FIN_WAIT_2")
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.local_ack_num = packet.seq_num + packet.flag_fin
                self.__send(flag_ack=True, tracker=packet.tracker)
                self.__change_state("TIME_WAIT")
                return

        # Got FIN packet -> Send ACK packet / change state to CLOSING
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            self.local_ack_num = packet.seq_num + packet.flag_fin
            self.__send(flag_ack=True, tracker=packet.tracker)
            self.__change_state("CLOSING")
            return

    def __tcp_fsm_fin_wait_2(self, packet=None, syscall=None, timer=None):
        """ TCP FSM FIN_WAIT_2 state handler """

        # Got FIN packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin}) and not any({packet.flag_syn, packet.flag_rst}):
            self.local_ack_num = packet.seq_num + packet.flag_fin
            self.__send(flag_ack=True, tracker=packet.tracker)
            self.__change_state("TIME_WAIT")
            return

    def __tcp_fsm_closing(self, packet=None, syscall=None, timer=None):
        """ TCP FSM CLOSING state handler """

        # Got ACK packet -> Change state to TIME_WAIT
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.__change_state("TIME_WAIT")
                return

    def __tcp_fsm_close_wait(self, packet=None, syscall=None, timer=None):
        """ TCP FSM CLOSE_WAIT state handler """

        # Got CLOSE syscall -> Send FIN packet / change state to LAST_ACK
        if syscall == "CLOSE":
            self.__send(flag_fin=True, flag_ack=True)
            self.__change_state("LAST_ACK")
            return

    def __tcp_fsm_last_ack(self, packet=None, syscall=None, timer=None):
        """ TCP FSM LAST_ACK state handler """

        # Got ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            if packet.ack_num == self.local_seq_num:
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_time_wait(self, packet=None, syscall=None, timer=None):
        """ TCP FSM TIME_WAIT state handler """

        # Got timer event -> Run Time Wait delay
        if timer and stack.stack_timer.timer_expired("time_wait"):
            self.__change_state("CLOSED")

    def tcp_fsm(self, packet=None, syscall=None, timer=None):
        """ Run TCP finite state machine """

        # Make note of remote ACK number that indcates how much of data we sent was received
        if packet:
            self.remote_ack_num = packet.ack_num

        # Process event
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
