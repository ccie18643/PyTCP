#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# tcp_session_alt.py - module contains alternate version of class supporting TCP finite state machine, aimed to streamline and simplify original one
#


import random
import threading

import loguru

import config
import stack

PACKET_RETRANSMIT_TIMEOUT = 1000  # Retransmit data if ACK not received
PACKET_RETRANSMIT_MAX_COUNT = 3  # If data is not acked, retransit it 5 times
DELAYED_ACK_DELAY = 100  # Delay between consecutive delayed ACK outbound packets
TIME_WAIT_DELAY = 30000  # 30s delay for the TIME_WAIT state, default is 30-120s


def trace_fsm(function):
    """ Decorator for tracing FSM state """

    def _(self, *args, **kwargs):
        print(
            f"[ >>> ] snd_nxt {self.snd_nxt}, snd_una {self.snd_una},",
            f"rcv_nxt {self.rcv_nxt}, rcv_una {self.rcv_una}",
        )
        retval = function(self, *args, **kwargs)
        print(
            f"[ <<< ] snd_nxt {self.snd_nxt}, snd_una {self.snd_una},",
            f"rcv_nxt {self.rcv_nxt}, rcv_una {self.rcv_una}",
        )
        return retval

    return _


def trace_win(self):
    """ Method used to trace sliding window operation, invoke as 'trace_win(self)' from within the TcpSession object"""

    remaining_data_len = len(self.tx_buffer) - self.tx_buffer_nxt
    usable_window = self.tx_buffer_una + self.snd_ewn - self.tx_buffer_nxt
    transmit_data_len = min(self.snd_mss, usable_window, remaining_data_len)
    print("unsent_data:", remaining_data_len)
    print("usable_window:", usable_window)
    print("transmit_data_len:", transmit_data_len)
    print("self.snd_nxt:", self.snd_nxt)
    print("self.snd_una:", self.snd_una)
    print("self.tx_buffer_seq_mod:", self.tx_buffer_seq_mod)
    print("self.tx_buffer_nxt:", self.tx_buffer_nxt)
    print("self.tx_buffer_una:", self.tx_buffer_una)


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, socket=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="tcp_session.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket = socket  # Keeps track of the socket that owns this session for the session -> socket communication purposes

        self.rx_buffer = []  # Keeps data received from peer and not received by application yet
        self.tx_buffer = []  # Keeps data sent by application but not acknowledged by peer yet

        # Receiving window parameters
        self.rcv_ini = None  # Initial seq number
        self.rcv_nxt = None  # Next seq to be received
        self.rcv_una = None  # Seq we acked
        self.rcv_mss = config.mtu - 40  # Maximum segment size
        self.rcv_wnd = 65535  # Window size
        self.rcv_wsc = 1  # Window scale

        # Sending window paramters
        self.snd_ini = random.randint(0, 0xFFFFFFFF)  # Initial seq number
        self.snd_nxt = self.snd_ini  # Next seq to be sent
        self.snd_max = self.snd_ini  # Maximum seq ever sent
        self.snd_una = self.snd_ini  # Seq not yet acknowledged by peer
        self.snd_fin = None  # Seq of FIN packet
        self.snd_mss = 536  # Maximum segment size
        self.snd_wnd = self.snd_mss  # Window size
        self.snd_ewn = self.snd_mss  # Effective window size, used as simple congestion management mechanism
        self.snd_wsc = 1  # Window scale, this is always initialized as 1 because initial SYN / SYN + ACK packets don't use wscale for backward compatibility

        self.tx_retransmit_request_counter = {}  # Keeps track of DUP packets sent from peer to determine if any of them is a retransmit request
        self.tx_retransmit_timeout_counter = {}  # Keeps track of the timestamps for the sent out packets, used to determine when to retransmit packet
        self.rx_retransmit_request_counter = {}  # Keeps track of us sending 'fast retransmit request' packets so we can limit their count to 2

        self.tx_buffer_seq_mod = self.snd_ini  # Used to help translate local_seq_send and snd_una numbers to TX buffer pointers

        self.state = "CLOSED"  # TCP FSM (Finite State Machine) state

        self.event_connect = threading.Semaphore(0)  # Used to inform CONNECT syscall that connection related event happened
        self.event_rx_buffer = threading.Semaphore(0)  # USed to inform RECV syscall that there is new data in buffer ready to be picked up

        self.lock_fsm = threading.RLock()  # Used to ensure that only single event can run FSM at given time
        self.lock_rx_buffer = threading.Lock()  # Used to ensure only single event has access to RX buffer at given time
        self.lock_tx_buffer = threading.Lock()  # Used to ensure only single event has access to TX buffer at given time

        self.closing = False  # Indicates that CLOSE syscall is in progress, this lets to finish sending data before FIN packet is transmitted

        self.ooo_packet_queue = {}  # Out of order packet buffer

        # Setup timer to execute FSM time event every milisecond
        stack.stack_timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})

    def __str__(self):
        """ String representation """

        return self.tcp_session_id

    @property
    def tcp_session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def tx_buffer_nxt(self):
        """ 'snd_nxt' number relative to TX buffer """

        return max(self.snd_nxt - self.tx_buffer_seq_mod, 0)

    @property
    def tx_buffer_una(self):
        """ 'snd_una' number relative to TX buffer """

        return max(self.snd_una - self.tx_buffer_seq_mod, 0)

    def listen(self):
        """ LISTEN syscall """

        self.logger.debug(f"{self.tcp_session_id} - State {self.state} - got LISTEN syscall")
        return self.tcp_fsm(syscall="LISTEN")

    def connect(self):
        """ CONNECT syscall """

        self.logger.debug(f"{self.tcp_session_id} - State {self.state} - got CONNECT syscall")
        self.tcp_fsm(syscall="CONNECT")
        self.event_connect.acquire()
        return self.state == "ESTABLISHED"

    def send(self, raw_data):
        """ SEND syscall """

        if self.state in {"ESTABLISHED", "CLOSE_WAIT"}:
            with self.lock_tx_buffer:
                self.tx_buffer.extend(list(raw_data))
                return len(raw_data) if self.state == "ESTABLISHED" else -1
        return None

    def receive(self, byte_count=None):
        """ RECEIVE syscall """

        # Wait till there is any data in the buffer
        self.event_rx_buffer.acquire()

        # If there is no data in RX buffer and remote end closed connection then notify application
        if not self.rx_buffer and self.state == "CLOSE_WAIT":
            return None

        with self.lock_rx_buffer:
            if byte_count is None:
                byte_count = len(self.rx_buffer)
            else:
                byte_count = min(byte_count, len(self.rx_buffer))

            rx_buffer = self.rx_buffer[:byte_count]
            del self.rx_buffer[:byte_count]

            # If there is any data left in buffer or the remote end closed connection then release the rx_buffer event
            if self.rx_buffer or self.state == "CLOSE_WAIT":
                self.event_rx_buffer.release()

        return bytes(rx_buffer)

    def close(self):
        """ CLOSE syscall """

        self.logger.debug(f"{self.tcp_session_id} - State {self.state} - got CLOSE syscall, {len(self.tx_buffer)} bytes in TX buffer")
        self.tcp_fsm(syscall="CLOSE")

    def __change_state(self, state):
        """ Change the state of TCP finite state machine """

        old_state = self.state
        self.state = state
        if old_state:
            self.logger.opt(ansi=True, depth=1).info(f"{self.tcp_session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

        # Register session
        if self.state in {"CONNECT", "LISTEN"}:
            stack.tcp_sessions[self.tcp_session_id] = self

        # Unregister session
        if self.state in {"CLOSED"}:
            stack.tcp_sessions.pop(self.tcp_session_id)

    def __transmit_packet(self, seq=None, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b""):
        """ Send out TCP packet """

        seq = seq if seq else self.snd_nxt
        ack = self.rcv_nxt if flag_ack else 0

        stack.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_seq=seq,
            tcp_ack=ack,
            tcp_flag_syn=flag_syn,
            tcp_flag_ack=flag_ack,
            tcp_flag_fin=flag_fin,
            tcp_flag_rst=flag_rst,
            tcp_win=self.rcv_wnd,
            tcp_mss=self.rcv_mss if flag_syn else None,
            raw_data=raw_data,
        )
        self.rcv_una = self.rcv_nxt
        self.snd_nxt = seq + len(raw_data) + flag_syn + flag_fin
        self.snd_max = max(self.snd_max, self.snd_nxt)
        self.tx_buffer_seq_mod += flag_syn + flag_fin

        # In case packet caries FIN flag make note of its SEQ number
        if flag_fin:
            self.snd_fin = self.snd_nxt

        # If in ESTABLISHED state then reset ACK delay timer
        if self.state == "ESTABLISHED":
            stack.stack_timer.register_timer(self.tcp_session_id + "-delayed_ack", DELAYED_ACK_DELAY)

        # If packet contains data then Initialize / adjust packet's retransmit counter and timer
        if raw_data or flag_syn or flag_fin:
            self.tx_retransmit_timeout_counter[seq] = self.tx_retransmit_timeout_counter.get(seq, -1) + 1
            stack.stack_timer.register_timer(
                self.tcp_session_id + "-retransmit_seq-" + str(seq), PACKET_RETRANSMIT_TIMEOUT * (1 << self.tx_retransmit_timeout_counter[seq])
            )

        self.logger.debug(
            f"{self.tcp_session_id} - Sent packet: {'S' if flag_syn else ''}{'F' if flag_fin else ''}{'R' if flag_rst else ''}"
            + f"{'A' if flag_ack else ''}, seq {seq}, ack {ack}, dlen {len(raw_data)}"
        )

    def __enqueue_rx_buffer(self, raw_data):
        """ Process the incoming segment and enqueue the data to be used by socket """

        with self.lock_rx_buffer:
            self.rx_buffer.extend(list(raw_data))
            # If rx_buffer event has not been realeased yet (it could be released if some data were siting in buffer already) then release it
            if not self.event_rx_buffer._value:
                self.event_rx_buffer.release()

    def __transmit_data(self):
        """ Send out data segment from TX buffer using TCP sliding window mechanism """

        assert self.snd_una <= self.snd_nxt <= self.snd_una + self.snd_ewn, "*** SEQ outside of TCP sliding window"

        # Check if we need to (re)transmit initial SYN packet
        if self.state == "SYN_SENT" and self.snd_nxt == self.snd_ini:
            self.logger.debug(f"{self.tcp_session_id} - Transmitting initial SYN packet: seq {self.snd_nxt}")
            self.__transmit_packet(flag_syn=True)
            return

        # Check if we need to (re)transmit initial SYN + ACK packet
        if self.state == "SYN_RCVD" and self.snd_nxt == self.snd_ini:
            self.logger.debug(f"{self.tcp_session_id} - Transmitting initial SYN + ACK packet: seq {self.snd_nxt}")
            self.__transmit_packet(flag_syn=True, flag_ack=True)
            return

        # Make sure we in the state that allows sending data out
        if self.state in {"ESTABLISHED", "CLOSE_WAIT"}:
            remaining_data_len = len(self.tx_buffer) - self.tx_buffer_nxt
            usable_window = self.snd_ewn - self.tx_buffer_nxt
            transmit_data_len = min(self.snd_mss, usable_window, remaining_data_len)
            if remaining_data_len:
                self.logger.opt(ansi=True).debug(
                    f"{self.tcp_session_id} - Sliding window <yellow>[{self.snd_una}|{self.snd_nxt}|{self.snd_una + self.snd_ewn}]</>"
                )
                self.logger.opt(ansi=True).debug(
                    f"{self.tcp_session_id} - {usable_window} left in window, {remaining_data_len} left in buffer, {transmit_data_len} to be sent"
                )
                if transmit_data_len:
                    with self.lock_tx_buffer:
                        transmit_data = self.tx_buffer[self.tx_buffer_nxt : self.tx_buffer_nxt + transmit_data_len]
                    self.logger.debug(f"{self.tcp_session_id} - Transmitting data segment: seq {self.snd_nxt} len {len(transmit_data)}")
                    self.__transmit_packet(flag_ack=True, raw_data=bytes(transmit_data))
                return

        # Check if we need to (re)transmit final FIN packet
        if self.state in {"FIN_WAIT_1", "LAST_ACK"} and self.snd_nxt != self.snd_fin:
            self.logger.debug(f"{self.tcp_session_id} - Transmitting final FIN packet: seq {self.snd_nxt}")
            self.__transmit_packet(flag_fin=True, flag_ack=True)
            return

    def __delayed_ack(self):
        """ Run Delayed ACK mechanism """

        if stack.stack_timer.timer_expired(self.tcp_session_id + "-delayed_ack"):
            if self.rcv_nxt > self.rcv_una:
                self.__transmit_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.rcv_nxt})")
            stack.stack_timer.register_timer(self.tcp_session_id + "-delayed_ack", DELAYED_ACK_DELAY)

    def __retransmit_packet_timeout(self):
        """ Retransmit packet after expired timeout """

        if self.snd_una in self.tx_retransmit_timeout_counter and stack.stack_timer.timer_expired(self.tcp_session_id + "-retransmit_seq-" + str(self.snd_una)):
            if self.tx_retransmit_timeout_counter[self.snd_una] == PACKET_RETRANSMIT_MAX_COUNT:
                # Send RST packet if we received any packet from peer already
                if self.rcv_nxt is not None:
                    self.__transmit_packet(flag_rst=True, flag_ack=True, seq=self.snd_una)
                    self.logger.debug(f"{self.tcp_session_id} - Packet retransmit counter expired, reseting session")
                else:
                    self.logger.debug(f"{self.tcp_session_id} - Packet retransmit counter expired")
                # If in any state with established connection inform socket about connection failure
                if self.state in {"ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT"}:
                    self.event_rx_buffer.release()
                # If in SYN_SENT state inform CONNECT syscall that the connection related event happened
                if self.state == "SYN_SENT":
                    self.event_connect.release()
                # Change state to CLOSED
                self.__change_state("CLOSED")
                return
            self.snd_ewn = self.snd_mss
            self.snd_nxt = self.snd_una
            # In case we need to retransmit packt containing SYN flag adjust tx_buffer_seq_mod so it doesn't reflect SYN flag yet
            if self.snd_nxt == self.snd_ini or self.snd_nxt == self.snd_fin:
                self.tx_buffer_seq_mod -= 1
            self.logger.debug(f"{self.tcp_session_id} - Got retansmit timeout, sending segment {self.snd_nxt}, reseting snd_ewn to {self.snd_ewn}")
            return

    def __retransmit_packet_request(self, packet):
        """ Retransmit packet after rceiving request from peer """

        self.tx_retransmit_request_counter[packet.ack] = self.tx_retransmit_request_counter.get(packet.ack, 0) + 1
        if self.tx_retransmit_request_counter[packet.ack] > 1:
            self.snd_nxt = self.snd_una
            self.logger.debug(f"{self.tcp_session_id} - Got retransmit request, sending segment {self.snd_nxt}, keeping snd_ewn at {self.snd_ewn}")

    def __process_ack_packet(self, packet):
        """ Process regular data/ACK packet """

        # Make note of the local SEQ that has been acked by peer
        self.snd_una = max(self.snd_una, packet.ack)
        # Adjust local SEQ accordingly to what peer acked (needed after the retransmit happens and peer is jumping to previously received SEQ)
        if self.snd_nxt < self.snd_una <= self.snd_max:
            self.snd_nxt = self.snd_una
        # Make note of the remote SEQ number
        self.rcv_nxt = packet.seq + len(packet.raw_data) + packet.flag_syn + packet.flag_fin
        # In case packet contains data enqueue it
        if packet.raw_data:
            self.__enqueue_rx_buffer(packet.raw_data)
            self.logger.debug(f"{self.tcp_session_id} - Enqueued {len(packet.raw_data)} bytes starting at {packet.seq}")
        # Purge acked data from TX buffer
        with self.lock_tx_buffer:
            del self.tx_buffer[: self.tx_buffer_una]
        self.tx_buffer_seq_mod += self.tx_buffer_una
        self.logger.debug(f"{self.tcp_session_id} - Purged TX buffer up to SEQ {self.snd_una}")
        # Update remote window size
        if self.snd_wnd != packet.win * self.snd_wsc:
            self.logger.debug(f"{self.tcp_session_id} - Updated sending window size {self.snd_wnd} -> {packet.win * self.snd_wsc}")
            self.snd_wnd = packet.win * self.snd_wsc
        # Enlarge effective sending window
        self.snd_ewn = min(self.snd_ewn << 1, self.snd_wnd)
        self.logger.debug(f"{self.tcp_session_id} - Updated effective sending window to {self.snd_ewn}")
        # Purge expired tx packet retransmit requests
        for seq in list(self.tx_retransmit_request_counter):
            if seq < packet.ack:
                self.tx_retransmit_request_counter.pop(seq)
                self.logger.debug(f"{self.tcp_session_id} - Purged expired TX packet retransmit request counter for {seq}")
        # Purge expired tx packet retransmit timeouts
        for seq in list(self.tx_retransmit_timeout_counter):
            if seq < packet.ack:
                self.tx_retransmit_timeout_counter.pop(seq)
                self.logger.debug(f"{self.tcp_session_id} - Purged expired TX packet retransmit timeout for {seq}")
        # Purge expired rx retransmit requests
        for seq in list(self.rx_retransmit_request_counter):
            if seq < self.rcv_nxt:
                self.rx_retransmit_request_counter.pop(seq)
                self.logger.debug(f"{self.tcp_session_id} - Purged expired RX packet retransmit request counter for {seq}")
        # Bring next packet from ooo_packet_queue if available
        if packet := self.ooo_packet_queue.pop(self.rcv_nxt, None):
            self.logger.opt(ansi=True).debug(f"{self.tcp_session_id} - <green>Retrieving packet {self.rcv_nxt} from Out of Order queue</>")
            self.tcp_fsm(packet)

    def __tcp_fsm_closed(self, packet, syscall, timer):
        """ TCP FSM CLOSED state handler """

        # Got CONNECT syscall -> Send SYN packet (this actually will be done in SYN_SENT state) / change state to SYN_SENT
        if syscall == "CONNECT":
            self.__change_state("SYN_SENT")

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall == "LISTEN":
            self.__change_state("LISTEN")

    def __tcp_fsm_listen(self, packet, syscall, timer):
        """ TCP FSM LISTEN state handler """

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == 0 and not packet.raw_data:
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
                self.snd_mss = min(packet.mss, config.mtu - 40)
                self.snd_wnd = packet.win * self.snd_wsc  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self.snd_wsc = packet.wscale if packet.wscale else 1  # Peer's wscale set to None means that peer desn't support window scaling
                self.logger.debug(f"{self.tcp_session_id} - Initialized remote window scale at {self.snd_wsc}")
                self.rcv_ini = packet.seq
                self.snd_ewn = self.snd_mss
                # Make note of the remote SEQ number
                self.rcv_nxt = packet.seq + packet.flag_syn
                # Send SYN + ACK packet (this actually will be done in SYN_SENT state) / change state to SYN_RCVD
                self.__change_state("SYN_RCVD")
                return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_sent(self, packet, syscall, timer):
        """ TCP FSM SYN_SENT state handler """

        # Got timer event -> Resend SYN packet if its timer expired
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if packet and all({packet.flag_syn, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.snd_nxt and not packet.raw_data:
                # Initialize session parameters
                self.snd_mss = min(packet.mss, config.mtu - 40)
                self.snd_wnd = packet.win * self.snd_wsc  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self.snd_wsc = packet.wscale if packet.wscale else 1  # Peer's wscale set to None means that peer desn't support window scaling
                self.logger.debug(f"{self.tcp_session_id} - Initialized remote window scale at {self.snd_wsc}")
                self.rcv_ini = packet.seq
                self.snd_ewn = self.snd_mss
                # Process ACK packet
                self.__process_ack_packet(packet)
                # Send initial ACK packet
                self.__transmit_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent initial ACK ({self.rcv_una}) packet")
                # Change state to ESTABLISHED
                self.__change_state("ESTABLISHED")
                # Inform connect syscall that connection related event happened
                self.event_connect.release()
                return

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if packet and all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            # Packet sanity check
            if packet.ack == 0 and not packet.raw_data:
                # Send SYN + ACK packet
                self.__transmit_packet(flag_syn=True, flag_ack=True)
                # Change state to SYN_RCVD
                self.__change_state("SYN_RCVD")
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == 0 and packet.ack == self.snd_nxt:
                # Change state to CLOSED
                self.__change_state("CLOSED")
                # Inform connect syscall that connection related event happened
                self.event_connect.release()
            return

        # Got CLOSE syscall -> Change state to CLOSE
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_rcvd(self, packet, syscall, timer):
        """ TCP FSM ESTABLISHED state handler """

        # Got timer event -> Resend SYN packet if its timer expired
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK packet -> Change state to ESTABLISHED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and packet.ack == self.snd_nxt and not packet.raw_data:
                self.__process_ack_packet(packet)
                # Change state to ESTABLISHED
                self.__change_state("ESTABLISHED")
                # Inform socket that session has been established so accept method can pick it up
                self.socket.event_tcp_session_established.release()
                # Inform connect syscall that connection related event happened, this is needed only in case of tcp simultaneous open
                self.event_connect.release()
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got CLOSE sycall -> Send FIN packet (this actually will be done in SYN_SENT state) / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_established(self, packet, syscall, timer):
        """ TCP FSM ESTABLISHED state handler """

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            self.__delayed_ack()
            if self.closing and not self.tx_buffer:
                self.__change_state("FIN_WAIT_1")
            return

        # Got packet that doesn't fit into receive window
        if packet and not self.rcv_nxt <= packet.seq <= self.rcv_nxt + self.rcv_wnd - len(packet.raw_data):
            self.logger.debug(f"{self.tcp_session_id} - Packet seq {packet.seq} + {len(packet.raw_data)} doesn't fit into receive window, droping")
            return

        # Got ACK packet
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Suspected retransmit request -> Reset TX window and local SEQ number
            if packet.seq == self.rcv_nxt and packet.ack == self.snd_una and not packet.raw_data:
                self.__retransmit_packet_request(packet)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and send 'fast retransmit' request (don't send more than two)
            if packet.seq > self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.ooo_packet_queue[packet.seq] = packet
                self.rx_retransmit_request_counter[self.rcv_nxt] = self.rx_retransmit_request_counter.get(self.rcv_nxt, 0) + 1
                if self.rx_retransmit_request_counter[self.rcv_nxt] <= 2:
                    self.__transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                return
            return

        # Got FIN + ACK packet -> Send ACK packet (let delayed ACK mechanism do it) / change state to CLOSE_WAIT / notifiy app that peer closed connection
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                # Immidiately acknowledge the received data if any
                if packet.raw_data:
                    self.__transmit_packet(flag_ack=True)
                # Let application know that remote peer closed connection
                self.event_rx_buffer.release()
                # Change state to CLOSE_WAIT
                self.__change_state("CLOSE_WAIT")
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Let application know that remote peer closed connection
                self.event_rx_buffer.release()
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got CLOSE syscall -> Send FIN packet (this actually will be done in SYN_SENT state) / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.closing = True
            return

    def __tcp_fsm_fin_wait_1(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_1 state handler """

        # Got timer event -> Transmit final FIN packet
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK (acking our FIN) packet -> Change state to FIN_WAIT_2
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                # Immidiately acknowledge the received data if any
                if packet.raw_data:
                    self.__transmit_packet(flag_ack=True)
                # Check if packet acks our FIN
                if packet.ack >= self.snd_fin:
                    # Change state to FIN_WAIT_2
                    self.__change_state("FIN_WAIT_2")
            return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT or CLOSING
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                # Send out final ACK packet
                self.__transmit_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.rcv_nxt}) packet")
                # Check if packet acks our FIN
                if packet.ack >= self.snd_fin:
                    # Change state to TIME_WAIT
                    self.__change_state("TIME_WAIT")
                    # Initialize TIME_WAIT delay
                    stack.stack_timer.register_timer(self.tcp_session_id + "-time_wait", TIME_WAIT_DELAY)
                else:
                    # Change state to CLOSING
                    self.__change_state("CLOSING")
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_fin_wait_2(self, packet, syscall, timer):
        """ TCP FSM FIN_WAIT_2 state handler """

        # Got ACK packet -> Process data
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                # Immidiately acknowledge the received data if any
                if packet.raw_data:
                    self.__transmit_packet(flag_ack=True)
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__process_ack_packet(packet)
                # Send out final ACK packet
                self.__transmit_packet(flag_ack=True)
                self.logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.rcv_nxt}) packet")
                # Change state to TIME_WAIT
                self.__change_state("TIME_WAIT")
                # Initialize TIME_WAIT delay
                stack.stack_timer.register_timer(self.tcp_session_id + "-time_wait", TIME_WAIT_DELAY)
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_closing(self, packet, syscall, timer):
        """ TCP FSM CLOSING state handler """

        # Got ACK packet -> Change state to TIME_WAIT
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.snd_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.snd_una = packet.ack
                self.__change_state("TIME_WAIT")
                # Initialize TIME_WAIT delay
                stack.stack_timer.register_timer(self.tcp_session_id + "-time_wait", TIME_WAIT_DELAY)
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_close_wait(self, packet, syscall, timer):
        """ TCP FSM CLOSE_WAIT state handler """

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            self.__delayed_ack()
            if self.closing and not self.tx_buffer:
                self.__change_state("LAST_ACK")
            return

        # Got ACK packet
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Suspected retransmit request -> Reset TX window and local SEQ number
            if packet.seq == self.rcv_nxt and packet.ack == self.snd_una and not packet.raw_data:
                self.__retransmit_packet_request(packet)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and send 'fast retransmit' request
            if packet.seq > self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.ooo_packet_queue[packet.seq] = packet
                self.rx_retransmit_request_counter[self.rcv_nxt] = self.rx_retransmit_request_counter.get(self.rcv_nxt, 0) + 1
                if self.rx_retransmit_request_counter[self.rcv_nxt] <= 2:
                    self.__transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max and not packet.raw_data:
                self.__process_ack_packet(packet)
                return
            return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got CLOSE syscall -> Send FIN packet (this actually will be done in SYN_SENT state) / change state to LAST_ACK
        if syscall == "CLOSE":
            self.closing = True
            return

    def __tcp_fsm_last_ack(self, packet, syscall, timer):
        """ TCP FSM LAST_ACK state handler """

        # Got timer event -> Transmit final FIN packet
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.snd_nxt and self.snd_una <= packet.ack <= self.snd_max:
                self.__change_state("CLOSED")
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.rcv_nxt and self.snd_una <= packet.ack <= self.snd_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_time_wait(self, packet, syscall, timer):
        """ TCP FSM TIME_WAIT state handler """

        # Got timer event -> Run TIME_WAIT delay
        if timer and stack.stack_timer.timer_expired(self.tcp_session_id + "-time_wait"):
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
