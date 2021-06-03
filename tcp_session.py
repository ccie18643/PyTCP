#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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
# tcp_session_alt.py - module contains alternate version of class supporting TCP finite state machine
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
    """Decorator for tracing FSM state"""

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


def trace_win(self):
    """Method used to trace sliding window operation, invoke as 'trace_win(self)' from within the TcpSession object"""

    unsent_data_len = len(self.tx_buffer) - self.tx_buffer_seq_sent
    unused_tx_win_len = self.tx_buffer_seq_ackd + self.tx_win - self.tx_buffer_seq_sent
    data_tx_len = min(self.remote_mss, unused_tx_win_len, unsent_data_len)
    print("unsent_data:", unsent_data_len)
    print("unused_tx_win_len:", unused_tx_win_len)
    print("data_tx_len:", data_tx_len)
    print("self.local_seq_sent:", self.local_seq_sent)
    print("self.local_seq_ackd:", self.local_seq_ackd)
    print("self.tx_buffer_seq_mod:", self.tx_buffer_seq_mod)
    print("self.tx_buffer_seq_sent:", self.tx_buffer_seq_sent)
    print("self.tx_buffer_seq_ackd:", self.tx_buffer_seq_ackd)


class TcpSession:
    """Class defining all the TCP session parameters"""

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, socket=None):
        """Class constructor"""

        if __debug__:
            self._logger = loguru.logger.bind(object_name="tcp_session.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port if local_port else self.__pick_random_local_port()
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket = socket  # Keeps track of the socket that owns this session for the session -> socket communication purposes

        self.rx_buffer = []  # Keeps data received from peer and not received by application yet
        self.tx_buffer = []  # Keeps data sent by application but not acknowledged by peer yet

        # SEQ of the packet means it's sequence number plus length of the data (and flags) packet carries
        self.remote_seq_init = None  # Initial SEQ received from peer
        self.remote_seq_rcvd = None  # Highest SEQ received from peer, its highest because all packets containing SEQ below it are dropped
        self.remote_seq_ackd = None  # Last SEQ we acked to peer
        self.local_seq_init = random.randint(0, 0xFFFFFFFF)  # Our initial SEQ number
        self.local_seq_sent = self.local_seq_init  # SEQ we sent to peer in last packet
        self.local_seq_sent_max = self.local_seq_init  # Highest (SEQ + data) number we ever sent to peer
        self.local_seq_ackd = self.local_seq_init  # Highest SEQ number that peer acked
        self.local_seq_fin = None  # SEQ of FIN packet we sent, used to track peer's ACK for it and for FIN retransmit

        self.tx_retransmit_request_counter = {}  # Keeps track of DUP packets sent from peer to determine if any of them is a retransmit request
        self.tx_retransmit_timeout_counter = {}  # Keeps track of the timestamps for the sent out packets, used to determine when to retransmit packet
        self.rx_retransmit_request_counter = {}  # Keeps track of us sending 'fast retransmit request' packets so we can limit their count to 2

        self.tx_buffer_seq_mod = self.local_seq_init  # Used to help translate local_seq_send and local_seq_ackd numbers to TX buffer pointers

        self.state = None  # TCP FSM (Finite State Machine) state
        self.state_init = None  # Indicates that FSM state transition just happened so next time event can initialize new state

        self.local_win = config.local_tcp_win  # Window size we advertise to peer
        self.local_mss = config.local_tcp_mss  # Maximum Segment Size we advertise to peer
        self.remote_mss = 536  # Maximum Segment Size peer advertised to us, initialized with TCP minimum MSS value of 536
        self.remote_win = self.remote_mss  # Window size peer advertised to us, initialized with remote MSS value
        self.remote_wscale = 1  # Wscale is always initialized as 1 because initial SYN / SYN + ACK packets don't use wscale for backward compatibility
        self.tx_win = self.remote_mss  # Current sliding window size, initialized with remote MSS value

        self.event_connect = threading.Semaphore(0)  # Used to inform CONNECT syscall that connection related event happened
        self.event_rx_buffer = threading.Semaphore(0)  # USed to inform RECV syscall that there is new data in buffer ready to be picked up

        self.lock_fsm = threading.RLock()  # Used to ensure that only single event can run FSM at given time
        self.lock_rx_buffer = threading.Lock()  # Used to ensure only single event has access to RX buffer at given time
        self.lock_tx_buffer = threading.Lock()  # Used to ensure only single event has access to TX buffer at given time

        self.closing = False  # Indicates that CLOSE syscall is in progress, this lets to finish sending data before FIN packet is transmitted

        self.ooo_packet_queue = {}  # Out of order packet buffer

        # Start session in CLOSED state
        self.__change_state("CLOSED")

        # Setup timer to execute FSM time event every millisecond
        stack.timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})

    def __str__(self):
        """String representation"""

        return self.tcp_session_id

    @property
    def tcp_session_id(self):
        """Session ID"""

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def tx_buffer_seq_sent(self):
        """'local_seq_sent' number relative to TX buffer"""

        return max(self.local_seq_sent - self.tx_buffer_seq_mod, 0)

    @property
    def tx_buffer_seq_ackd(self):
        """'local_seq_ackd' number relative to TX buffer"""

        return max(self.local_seq_ackd - self.tx_buffer_seq_mod, 0)

    def listen(self):
        """LISTEN syscall"""

        if __debug__:
            self._logger.debug(f"{self.tcp_session_id} - State {self.state} - got LISTEN syscall")
        return self.tcp_fsm(syscall="LISTEN")

    def connect(self):
        """CONNECT syscall"""

        if __debug__:
            self._logger.debug(f"{self.tcp_session_id} - State {self.state} - got CONNECT syscall")
        self.tcp_fsm(syscall="CONNECT")
        self.event_connect.acquire()
        return self.state == "ESTABLISHED"

    def send(self, raw_data):
        """SEND syscall"""

        if self.state in {"ESTABLISHED", "CLOSE_WAIT"}:
            with self.lock_tx_buffer:
                self.tx_buffer.extend(list(raw_data))
                return len(raw_data) if self.state == "ESTABLISHED" else -1
        return None

    def receive(self, byte_count=None):
        """RECEIVE syscall"""

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
        """CLOSE syscall"""

        if __debug__:
            self._logger.debug(f"{self.tcp_session_id} - State {self.state} - got CLOSE syscall, {len(self.tx_buffer)} bytes in TX buffer")
        self.tcp_fsm(syscall="CLOSE")

    def __pick_random_local_port(self):
        """Pick random local port, making sure it is not already being used by any session bound to the same local IP"""

        used_ports = {int(_.split("/")[2]) for _ in stack.tcp_sessions if _.split("/")[1] in {"*", self.local_ip_address}}
        while (port := random.randint(*config.TCP_EPHEMERAL_PORT_RANGE)) not in used_ports:
            return port

    def __change_state(self, state):
        """Change the state of TCP finite state machine"""

        old_state = self.state
        self.state = state
        self.state_init = True
        if old_state:
            if __debug__:
                self._logger.opt(ansi=True, depth=1).info(f"{self.tcp_session_id} - State changed: <yellow> {old_state} -> {self.state}</>")

        # Register session
        if self.state in {"SYN_SENT", "LISTEN"}:
            stack.tcp_sessions[self.tcp_session_id] = self
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Registered TCP session")

        # Unregister session
        if self.state in {"CLOSED"}:
            stack.tcp_sessions.pop(self.tcp_session_id)
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Unregistered TCP session")

    def __transmit_packet(self, seq=None, flag_syn=False, flag_ack=False, flag_fin=False, flag_rst=False, raw_data=b""):
        """Send out TCP packet"""

        seq = seq if seq else self.local_seq_sent
        ack = self.remote_seq_rcvd if flag_ack else 0

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
            tcp_win=self.local_win,
            tcp_mss=self.local_mss if flag_syn else None,
            raw_data=raw_data,
        )
        self.remote_seq_ackd = self.remote_seq_rcvd
        self.local_seq_sent = seq + len(raw_data) + flag_syn + flag_fin
        self.local_seq_sent_max = max(self.local_seq_sent_max, self.local_seq_sent)
        self.tx_buffer_seq_mod += flag_syn + flag_fin

        # In case packet caries FIN flag make note of its SEQ number
        if flag_fin:
            self.local_seq_fin = self.local_seq_sent

        # If in ESTABLISHED state then reset ACK delay timer
        if self.state == "ESTABLISHED":
            stack.timer.register_timer(self.tcp_session_id + "-delayed_ack", DELAYED_ACK_DELAY)

        # If packet contains data then Initialize / adjust packet's retransmit counter and timer
        if raw_data or flag_syn or flag_fin:
            self.tx_retransmit_timeout_counter[seq] = self.tx_retransmit_timeout_counter.get(seq, -1) + 1
            stack.timer.register_timer(
                self.tcp_session_id + "-retransmit_seq-" + str(seq), PACKET_RETRANSMIT_TIMEOUT * (1 << self.tx_retransmit_timeout_counter[seq])
            )

        if __debug__:
            self._logger.debug(
                f"{self.tcp_session_id} - Sent packet: {'S' if flag_syn else ''}{'F' if flag_fin else ''}{'R' if flag_rst else ''}"
                + f"{'A' if flag_ack else ''}, seq {seq}, ack {ack}, dlen {len(raw_data)}"
            )

    def __enqueue_rx_buffer(self, raw_data):
        """Process the incoming segment and enqueue the data to be used by socket"""

        with self.lock_rx_buffer:
            self.rx_buffer.extend(list(raw_data))
            # If rx_buffer event has not been released yet (it could be released if some data were siting in buffer already) then release it
            if not self.event_rx_buffer._value:
                self.event_rx_buffer.release()

    def __transmit_data(self):
        """Send out data segment from TX buffer using TCP sliding window mechanism"""

        assert self.local_seq_ackd <= self.local_seq_sent <= self.local_seq_ackd + self.tx_win, "*** SEQ outside of TCP sliding window"

        # Check if we need to (re)transmit initial SYN packet
        if self.state == "SYN_SENT" and self.local_seq_sent == self.local_seq_init:
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Transmitting initial SYN packet: seq {self.local_seq_sent}")
            self.__transmit_packet(flag_syn=True)
            return

        # Check if we need to (re)transmit initial SYN + ACK packet
        if self.state == "SYN_RCVD" and self.local_seq_sent == self.local_seq_init:
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Transmitting initial SYN + ACK packet: seq {self.local_seq_sent}")
            self.__transmit_packet(flag_syn=True, flag_ack=True)
            return

        # Make sure we in the state that allows sending data out
        if self.state in {"ESTABLISHED", "CLOSE_WAIT"}:
            unsent_data_len = len(self.tx_buffer) - self.tx_buffer_seq_sent
            unused_tx_win_len = self.tx_buffer_seq_ackd + self.tx_win - self.tx_buffer_seq_sent
            data_tx_len = min(self.remote_mss, unused_tx_win_len, unsent_data_len)
            if unsent_data_len:
                if __debug__:
                    self._logger.opt(ansi=True).debug(
                        f"{self.tcp_session_id} - Sliding window <yellow>[{self.local_seq_ackd}|{self.local_seq_sent}|{self.local_seq_ackd + self.tx_win}]</>"
                    )
                if __debug__:
                    self._logger.opt(ansi=True).debug(
                        f"{self.tcp_session_id} - {unused_tx_win_len} left in window, {unsent_data_len} left in buffer, {data_tx_len} to be sent"
                    )
                if data_tx_len:
                    with self.lock_tx_buffer:
                        data_tx = self.tx_buffer[self.tx_buffer_seq_sent : self.tx_buffer_seq_sent + data_tx_len]
                    if __debug__:
                        self._logger.debug(f"{self.tcp_session_id} - Transmitting data segment: seq {self.local_seq_sent} len {len(data_tx)}")
                    self.__transmit_packet(flag_ack=True, raw_data=bytes(data_tx))
                return

        # Check if we need to (re)transmit final FIN packet
        if self.state in {"FIN_WAIT_1", "LAST_ACK"} and self.local_seq_sent != self.local_seq_fin:
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Transmitting final FIN packet: seq {self.local_seq_sent}")
            self.__transmit_packet(flag_fin=True, flag_ack=True)
            return

    def __delayed_ack(self):
        """Run Delayed ACK mechanism"""

        if stack.timer.timer_expired(self.tcp_session_id + "-delayed_ack"):
            if self.remote_seq_rcvd > self.remote_seq_ackd:
                self.__transmit_packet(flag_ack=True)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Sent out delayed ACK ({self.remote_seq_rcvd})")
            stack.timer.register_timer(self.tcp_session_id + "-delayed_ack", DELAYED_ACK_DELAY)

    def __retransmit_packet_timeout(self):
        """Retransmit packet after expired timeout"""

        if self.local_seq_ackd in self.tx_retransmit_timeout_counter and stack.timer.timer_expired(
            self.tcp_session_id + "-retransmit_seq-" + str(self.local_seq_ackd)
        ):
            if self.tx_retransmit_timeout_counter[self.local_seq_ackd] == PACKET_RETRANSMIT_MAX_COUNT:
                # Send RST packet if we received any packet from peer already
                if self.remote_seq_rcvd is not None:
                    self.__transmit_packet(flag_rst=True, flag_ack=True, seq=self.local_seq_ackd)
                    if __debug__:
                        self._logger.debug(f"{self.tcp_session_id} - Packet retransmit counter expired, resetting session")
                else:
                    if __debug__:
                        self._logger.debug(f"{self.tcp_session_id} - Packet retransmit counter expired")
                # If in any state with established connection inform socket about connection failure
                if self.state in {"ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT"}:
                    self.event_rx_buffer.release()
                # If in SYN_SENT state inform CONNECT syscall that the connection related event happened
                if self.state == "SYN_SENT":
                    self.event_connect.release()
                # Change state to CLOSED
                self.__change_state("CLOSED")
                return
            self.tx_win = self.remote_mss
            self.local_seq_sent = self.local_seq_ackd
            # In case we need to retransmit packt containing SYN flag adjust tx_buffer_seq_mod so it doesn't reflect SYN flag yet
            if self.local_seq_sent == self.local_seq_init or self.local_seq_sent == self.local_seq_fin:
                self.tx_buffer_seq_mod -= 1
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Got retansmit timeout, sending segment {self.local_seq_sent}, resetting tx_win to {self.tx_win}")
            return

    def __retransmit_packet_request(self, packet):
        """Retransmit packet after rceiving request from peer"""

        self.tx_retransmit_request_counter[packet.ack] = self.tx_retransmit_request_counter.get(packet.ack, 0) + 1
        if self.tx_retransmit_request_counter[packet.ack] > 1:
            self.local_seq_sent = self.local_seq_ackd
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Got retransmit request, sending segment {self.local_seq_sent}, keeping tx_win at {self.tx_win}")

    def __process_ack_packet(self, packet):
        """Process regular data/ACK packet"""

        # Make note of the local SEQ that has been acked by peer
        self.local_seq_ackd = max(self.local_seq_ackd, packet.ack)
        # Adjust local SEQ accordingly to what peer acked (needed after the retransmit happens and peer is jumping to previously received SEQ)
        if self.local_seq_sent < self.local_seq_ackd <= self.local_seq_sent_max:
            self.local_seq_sent = self.local_seq_ackd
        # Make note of the remote SEQ number
        self.remote_seq_rcvd = packet.seq + len(packet.raw_data) + packet.flag_syn + packet.flag_fin
        # In case packet contains data enqueue it
        if packet.raw_data:
            self.__enqueue_rx_buffer(packet.raw_data)
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Enqueued {len(packet.raw_data)} bytes starting at {packet.seq}")
        # Purge acked data from TX buffer
        with self.lock_tx_buffer:
            del self.tx_buffer[: self.tx_buffer_seq_ackd]
        self.tx_buffer_seq_mod += self.tx_buffer_seq_ackd
        if __debug__:
            self._logger.debug(f"{self.tcp_session_id} - Purged TX buffer up to SEQ {self.local_seq_ackd}")
        # Update remote window size
        if self.remote_win != packet.win * self.remote_wscale:
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - Updating remote window size {self.remote_win} -> {packet.win * self.remote_wscale}")
            self.remote_win = packet.win * self.remote_wscale
        # Enlarge TX window
        self.tx_win = min(self.tx_win << 1, self.remote_win)
        if __debug__:
            self._logger.debug(f"{self.tcp_session_id} - Set TX window to {self.tx_win}")
        # Purge expired tx packet retransmit requests
        for seq in list(self.tx_retransmit_request_counter):
            if seq < packet.ack:
                self.tx_retransmit_request_counter.pop(seq)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Purged expired TX packet retransmit request counter for {seq}")
        # Purge expired tx packet retransmit timeouts
        for seq in list(self.tx_retransmit_timeout_counter):
            if seq < packet.ack:
                self.tx_retransmit_timeout_counter.pop(seq)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Purged expired TX packet retransmit timeout for {seq}")
        # Purge expired rx retransmit requests
        for seq in list(self.rx_retransmit_request_counter):
            if seq < self.remote_seq_rcvd:
                self.rx_retransmit_request_counter.pop(seq)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Purged expired RX packet retransmit request counter for {seq}")
        # Bring next packet from ooo_packet_queue if available
        if packet := self.ooo_packet_queue.pop(self.remote_seq_rcvd, None):
            if __debug__:
                self._logger.opt(ansi=True).debug(f"{self.tcp_session_id} - <green>Retrieving packet {self.remote_seq_rcvd} from Out of Order queue</>")
            self.tcp_fsm(packet)

    def __tcp_fsm_closed(self, packet, syscall, timer):
        """TCP FSM CLOSED state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got CONNECT syscall -> Send SYN packet (this actually will be done in SYN_SENT state) / change state to SYN_SENT
        if syscall == "CONNECT":
            self.__change_state("SYN_SENT")

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall == "LISTEN":
            self.__change_state("LISTEN")

    def __tcp_fsm_listen(self, packet, syscall, timer):
        """TCP FSM LISTEN state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

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
                self.remote_mss = min(packet.mss, config.mtu - 40)
                self.remote_win = packet.win * self.remote_wscale  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self.remote_wscale = packet.wscale if packet.wscale else 1  # Peer's wscale set to None means that peer doesn't support window scaling
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Initialized remote window scale at {self.remote_wscale}")
                self.remote_seq_init = packet.seq
                self.tx_win = self.remote_mss
                # Make note of the remote SEQ number
                self.remote_seq_rcvd = packet.seq + packet.flag_syn
                # Send SYN + ACK packet (this actually will be done in SYN_SENT state) / change state to SYN_RCVD
                self.__change_state("SYN_RCVD")
                return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall == "CLOSE":
            self.__change_state("CLOSED")
            return

    def __tcp_fsm_syn_sent(self, packet, syscall, timer):
        """TCP FSM SYN_SENT state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Resend SYN packet if its timer expired
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if packet and all({packet.flag_syn, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.local_seq_sent and not packet.raw_data:
                # Initialize session parameters
                self.remote_mss = min(packet.mss, config.mtu - 40)
                self.remote_win = packet.win * self.remote_wscale  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self.remote_wscale = packet.wscale if packet.wscale else 1  # Peer's wscale set to None means that peer doesn't support window scaling
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Initialized remote window scale at {self.remote_wscale}")
                self.remote_seq_init = packet.seq
                self.tx_win = self.remote_mss
                # Process ACK packet
                self.__process_ack_packet(packet)
                # Send initial ACK packet
                self.__transmit_packet(flag_ack=True)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Sent initial ACK ({self.remote_seq_ackd}) packet")
                # Change state to ESTABLISHED
                self.__change_state("ESTABLISHED")
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
            if packet.seq == 0 and packet.ack == self.local_seq_sent:
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
        """TCP FSM ESTABLISHED state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Resend SYN packet if its timer expired
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK packet -> Change state to ESTABLISHED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and packet.ack == self.local_seq_sent and not packet.raw_data:
                self.__process_ack_packet(packet)
                # Change state to ESTABLISHED
                self.__change_state("ESTABLISHED")
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and packet.ack == 0:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got CLOSE sycall -> Send FIN packet (this actually will be done in SYN_SENT state) / change state to FIN_WAIT_1
        if syscall == "CLOSE":
            self.__change_state("FIN_WAIT_1")
            return

    def __tcp_fsm_established(self, packet, syscall, timer):
        """TCP FSM ESTABLISHED state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            # Inform socket that session has been established so accept method can pick it up
            self.socket.event_tcp_session_established.release()
            # Inform connect syscall that connection related event happened
            self.event_connect.release()
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            self.__delayed_ack()
            if self.closing and not self.tx_buffer:
                self.__change_state("FIN_WAIT_1")
            return

        # Got ACK packet
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Suspected retransmit request -> Reset TX window and local SEQ number
            if packet.seq == self.remote_seq_rcvd and packet.ack == self.local_seq_ackd and not packet.raw_data:
                self.__retransmit_packet_request(packet)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and send 'fast retransmit' request
            if packet.seq > self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.ooo_packet_queue[packet.seq] = packet
                self.rx_retransmit_request_counter[self.remote_seq_rcvd] = self.rx_retransmit_request_counter.get(self.remote_seq_rcvd, 0) + 1
                if self.rx_retransmit_request_counter[self.remote_seq_rcvd] <= 2:
                    self.__transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                return
            return

        # Got FIN + ACK packet -> Send ACK packet (let delayed ACK mechanism do it) / change state to CLOSE_WAIT / notify app that peer closed connection
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                # Immediately acknowledge the received data if any
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
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
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
        """TCP FSM FIN_WAIT_1 state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Transmit final FIN packet
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK (acking our FIN) packet -> Change state to FIN_WAIT_2
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                # Immediately acknowledge the received data if any
                if packet.raw_data:
                    self.__transmit_packet(flag_ack=True)
                # Check if packet acks our FIN
                if packet.ack >= self.local_seq_fin:
                    # Change state to FIN_WAIT_2
                    self.__change_state("FIN_WAIT_2")
            return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT or CLOSING
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                # Send out final ACK packet
                self.__transmit_packet(flag_ack=True)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.remote_seq_rcvd}) packet")
                # Check if packet acks our FIN
                if packet.ack >= self.local_seq_fin:
                    # Change state to TIME_WAIT
                    self.__change_state("TIME_WAIT")
                else:
                    # Change state to CLOSING
                    self.__change_state("CLOSING")
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_fin_wait_2(self, packet, syscall, timer):
        """TCP FSM FIN_WAIT_2 state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got ACK packet -> Process data
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst, packet.flag_fin}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                # Immediately acknowledge the received data if any
                if packet.raw_data:
                    self.__transmit_packet(flag_ack=True)
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if packet and all({packet.flag_fin, packet.flag_ack}) and not any({packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__process_ack_packet(packet)
                # Send out final ACK packet
                self.__transmit_packet(flag_ack=True)
                if __debug__:
                    self._logger.debug(f"{self.tcp_session_id} - Sent final ACK ({self.remote_seq_rcvd}) packet")
                # Change state to TIME_WAIT
                self.__change_state("TIME_WAIT")
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_closing(self, packet, syscall, timer):
        """TCP FSM CLOSING state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got ACK packet -> Change state to TIME_WAIT
        if packet and all({packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.local_seq_sent and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.local_seq_ackd = packet.ack
                self.__change_state("TIME_WAIT")
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_close_wait(self, packet, syscall, timer):
        """TCP FSM CLOSE_WAIT state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

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
            if packet.seq == self.remote_seq_rcvd and packet.ack == self.local_seq_ackd and not packet.raw_data:
                self.__retransmit_packet_request(packet)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and send 'fast retransmit' request
            if packet.seq > self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.ooo_packet_queue[packet.seq] = packet
                self.rx_retransmit_request_counter[self.remote_seq_rcvd] = self.rx_retransmit_request_counter.get(self.remote_seq_rcvd, 0) + 1
                if self.rx_retransmit_request_counter[self.remote_seq_rcvd] <= 2:
                    self.__transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max and not packet.raw_data:
                self.__process_ack_packet(packet)
                return
            return

        # Got RST packet -> Change state to CLOSED
        if packet and all({packet.flag_rst}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

        # Got CLOSE syscall -> Send FIN packet (this actually will be done in SYN_SENT state) / change state to LAST_ACK
        if syscall == "CLOSE":
            self.closing = True
            return

    def __tcp_fsm_last_ack(self, packet, syscall, timer):
        """TCP FSM LAST_ACK state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Transmit final FIN packet
        if timer:
            self.__retransmit_packet_timeout()
            self.__transmit_data()
            return

        # Got ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_ack}) and not any({packet.flag_syn, packet.flag_fin, packet.flag_rst}):
            # Packet sanity check
            if packet.ack == self.local_seq_sent and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                self.__change_state("CLOSED")
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if packet and all({packet.flag_rst, packet.flag_ack}) and not any({packet.flag_fin, packet.flag_syn}):
            # Packet sanity_check
            if packet.seq == self.remote_seq_rcvd and self.local_seq_ackd <= packet.ack <= self.local_seq_sent_max:
                # Change state to CLOSED
                self.__change_state("CLOSED")
            return

    def __tcp_fsm_time_wait(self, packet, syscall, timer):
        """TCP FSM TIME_WAIT state handler"""

        # State initialization
        if self.state_init:
            self.state_init = False
            stack.timer.register_timer(self.tcp_session_id + "-time_wait", TIME_WAIT_DELAY)
            if __debug__:
                self._logger.debug(f"{self.tcp_session_id} - State {self.state} initialized")

        # Got timer event -> Run TIME_WAIT delay
        if timer and stack.timer.timer_expired(self.tcp_session_id + "-time_wait"):
            self.__change_state("CLOSED")
            return

    def tcp_fsm(self, packet=None, syscall=None, timer=False):
        """Run TCP finite state machine"""

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
