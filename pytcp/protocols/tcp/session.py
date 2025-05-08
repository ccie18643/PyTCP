#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = expression-not-assigned
# pylint: disable = too-many-branches
# pylint: disable = too-many-lines
# pylint: disable = too-many-arguments
# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-return-statements
# pylint: disable = consider-using-with
# pylint: disable = protected-access
# pylint: disable = import-outside-toplevel

"""
Module contains class supporting TCP finite state machine.

pytcp/protocols/tcp/session.py

ver 2.7
"""


from __future__ import annotations

import random
import threading
from collections.abc import Callable
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from threading import Lock, RLock, Semaphore

    from pytcp.lib.ip_address import IpAddress
    from pytcp.lib.socket import Socket
    from pytcp.protocols.tcp.metadata import TcpMetadata


PACKET_RETRANSMIT_TIMEOUT = 1000  # Retransmit data if ACK not received
PACKET_RETRANSMIT_MAX_COUNT = 3  # If data is not acked, retransit it 5 times
TIME_WAIT_DELAY = 30000  # 30s delay for the TIME_WAIT state, default is 30-120s
DELAYED_ACK_DELAY = (
    100  # Delay between consecutive delayed ACK outbound packets
)


class TcpSessionError(Exception):
    """
    Critical errors.
    """


class SysCall(Enum):
    """
    System call identifier.
    """

    LISTEN = auto()
    CONNECT = auto()
    CLOSE = auto()

    def __str__(self) -> str:
        return str(self.name)


class FsmState(Enum):
    """
    TCP Finite State Machine state identifier.
    """

    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RCVD = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSING = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()

    def __str__(self) -> str:
        return str(self.name)


class ConnError(Enum):
    """
    Connection fail reasons.
    """

    NONE = auto()
    REFUSED = auto()
    TIMEOUT = auto()

    def __str__(self) -> str:
        return str(self.name)


def trace_fsm(function: Callable) -> Callable:
    """
    Decorator for tracing FSM state.
    """

    def wrapper(
        self: TcpSession, *args: list[Any], **kwargs: dict[str, Any]
    ) -> Any:
        print(
            f"[ >>> ] snd_nxt {self._snd_nxt}, snd_una {self._snd_una},",
            f"rcv_nxt {self._rcv_nxt}, rcv_una {self._rcv_una}",
        )
        retval = function(self, *args, **kwargs)
        print(
            f"[ <<< ] snd_nxt {self._snd_nxt}, snd_una {self._snd_una},",
            f"rcv_nxt {self._rcv_nxt}, rcv_una {self._rcv_una}",
        )
        return retval

    return wrapper


def trace_win(self: TcpSession) -> None:
    """
    Method used to trace sliding window operation, invoke as 'trace_win(self)'
    from within the TcpSession object.
    """

    remaining_data_len = len(self._tx_buffer) - self._tx_buffer_nxt
    usable_window = self._tx_buffer_una + self._snd_ewn - self._tx_buffer_nxt
    transmit_data_len = min(self._snd_mss, usable_window, remaining_data_len)

    print("unsent_data:", remaining_data_len)
    print("usable_window:", usable_window)
    print("transmit_data_len:", transmit_data_len)
    print("self._snd_nxt:", self._snd_nxt)
    print("self._snd_una:", self._snd_una)
    print("self._tx_buffer_seq_mod:", self._tx_buffer_seq_mod)
    print("self._tx_buffer_nxt:", self._tx_buffer_nxt)
    print("self._tx_buffer_una:", self._tx_buffer_una)


class TcpSession:
    """
    Class defining all the TCP session parameters.
    """

    def __init__(
        self,
        local_ip_address: IpAddress,
        local_port: int,
        remote_ip_address: IpAddress,
        remote_port: int,
        socket: Socket,
    ) -> None:
        """
        Class constructor.
        """

        ###
        # Parameters derived from the socket
        ###

        self._local_ip_address: IpAddress = local_ip_address
        self._local_port: int = local_port
        self._remote_ip_address: IpAddress = remote_ip_address
        self._remote_port: int = remote_port

        # Keeps track of the socket that owns this session for
        # the session -> socket communication purposes
        self._socket: Socket = socket

        ###
        # Buffers
        ###

        # Keeps data received from peer and not received by application yet
        self._rx_buffer: bytearray = bytearray()

        # Keeps data sent by application but not acknowledged by peer yet
        self._tx_buffer: bytearray = bytearray()

        ###
        # Receiving window parameters
        ###

        # Initial sequence number
        self._rcv_ini: int = 0

        # Next sequence number to be received
        self._rcv_nxt: int = 0

        # Sequence number we acked
        self._rcv_una: int = 0

        # Maximum segment size
        self._rcv_mss: int = config.LOCAL_TCP_MSS

        # Window size
        self._rcv_wnd: int = 65535

        # Window scale
        self._rcv_wsc: int = 1

        ###
        # Sending window parameters
        ###

        # Initial sequence number
        self._snd_ini: int = random.randint(0, 0xFFFFFFFF)

        # Next sequence number to be sent
        self._snd_nxt: int = self._snd_ini

        # Maximum sequence number ever sent
        self._snd_max: int = self._snd_ini

        # Sequence number not yet acknowledged by peer
        self._snd_una: int = self._snd_ini

        # Sequence number of the FIN packet we sent
        self._snd_fin: int = 0

        # Maximum segment size
        self._snd_mss: int = 536

        # Window size
        self._snd_wnd: int = self._snd_mss

        # Effective window size, used as simple congestion management mechanism
        self._snd_ewn: int = self._snd_mss

        # Window scale, initialized to 1 because initial SYN / SYN + ACK packets
        # don't use wscale for backward compatibility
        self._snd_wsc: int = 1

        ###
        # Other variables
        ###

        # Keeps track of number of DUP packets sent by peer to determine if any
        # is a retransmit request
        self._tx_retransmit_request_counter: dict[int, int] = {}

        # Keeps track of the timestamps for the sent out packets, used to
        # determine when to retransmit packet
        self._tx_retransmit_timeout_counter: dict[int, int] = {}

        # Keeps track of us sending 'fast retransmit request' packets so we can
        # limit their count to 2
        self._rx_retransmit_request_counter: dict[int, int] = {}

        # Used to help translate local_seq_send and snd_una numbers to
        # the TX buffer pointers
        self._tx_buffer_seq_mod: int = self._snd_ini

        # TCP FSM (Finite FsmState Machine) state
        self._state: FsmState = FsmState.CLOSED

        # Used to inform CONNECT syscall that connection related event happened
        self._event_connect: Semaphore = threading.Semaphore(0)

        # Used to inform RECV syscall that there is new data in buffer ready
        # to be picked up
        self._event_rx_buffer: Semaphore = threading.Semaphore(0)

        # Used to ensure that only single event can run FSM at given time
        self._lock_fsm: RLock = threading.RLock()

        # Used to ensure only single event has access to RX buffer at given time
        self._lock_rx_buffer: Lock = threading.Lock()

        # Used to ensure only single event has access to TX buffer at given time
        self._lock_tx_buffer: Lock = threading.Lock()

        # Indicates that CLOSE syscall is in progress, this lets to finish
        # sending data before FIN packet is transmitted
        self._closing: bool = False

        # Out of order packet buffer
        self._ooo_packet_queue: dict[int, TcpMetadata] = {}

        # Used to report cause of connection failure
        self._connection_error: ConnError = ConnError.NONE

        # Setup timer to execute FSM time event every millisecond
        stack.timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})

    def __str__(self) -> str:
        """
        String representation.
        """
        return (
            f"{self._local_ip_address}/{self._local_port}/"
            f"{self._remote_ip_address}/{self._remote_port}"
        )

    @property
    def local_ip_address(self) -> IpAddress:
        """
        Getter for the '_local_ip_address' attribute.
        """
        return self._local_ip_address

    @property
    def remote_ip_address(self) -> IpAddress:
        """
        Getter for the '_remote_ip_address' attribute.
        """
        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Getter for the '_local_port' attribute.
        """
        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Getter for '_remote_port' attribute.
        """
        return self._remote_port

    @property
    def socket(self) -> Socket:
        """
        Getter for the '_socket' attribute.
        """
        return self._socket

    @property
    def state(self) -> FsmState:
        """
        Getter for the '_state' attribute.
        """
        return self._state

    @property
    def _tx_buffer_nxt(self) -> int:
        """
        Getter for the 'snd_nxt' number relative to TX buffer.
        """
        return max(self._snd_nxt - self._tx_buffer_seq_mod, 0)

    @property
    def _tx_buffer_una(self) -> int:
        """
        Getter for the 'snd_una' number relative to TX buffer.
        """
        return max(self._snd_una - self._tx_buffer_seq_mod, 0)

    def listen(self) -> None:
        """
        The 'LISTEN' syscall.
        """
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>LISTEN</> syscall",
        )
        self.tcp_fsm(syscall=SysCall.LISTEN)

    def connect(self) -> None:
        """
        The 'CONNECT' syscall.
        """
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CONNECT</> syscall",
        )
        self.tcp_fsm(syscall=SysCall.CONNECT)
        self._event_connect.acquire()
        if (
            self._state is not FsmState.ESTABLISHED
            and self._connection_error is ConnError.REFUSED
        ):
            raise TcpSessionError("Connection refused")
        if (
            self._state is not FsmState.ESTABLISHED
            and self._connection_error is ConnError.TIMEOUT
        ):
            raise TcpSessionError("Connection timeout")

    def send(self, data: bytes) -> int:
        """
        The 'SEND' syscall.
        """
        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            with self._lock_tx_buffer:
                self._tx_buffer.extend(data)
                return len(data)
        # This error should be risen when session is locally or fully closed
        raise TcpSessionError(
            "TCP session not in ESTABLISHED or CLOSE_WAIT state"
        )

    def receive(self, byte_count: int | None = None) -> bytes:
        """
        The 'RECEIVE' syscall.
        """

        # Wait till there is any data in the buffer (this will get bypassed
        # when FSM goes into CLOSE_WAIT or CLOSED).
        self._event_rx_buffer.acquire()

        # If there is no data in RX buffer and remote end closed connection
        # then notify application by returning empty byte string.
        if not self._rx_buffer and self._state in {
            FsmState.CLOSE_WAIT,
            FsmState.CLOSED,
        }:
            return b""

        with self._lock_rx_buffer:
            if byte_count is None:
                byte_count = len(self._rx_buffer)
            else:
                byte_count = min(byte_count, len(self._rx_buffer))

            rx_buffer = self._rx_buffer[:byte_count]
            del self._rx_buffer[:byte_count]

            # If there is any data left in buffer or the remote end closed
            # connection then release the rx_buffer event.
            if self._rx_buffer or self._state in {
                FsmState.CLOSE_WAIT,
                FsmState.CLOSED,
            }:
                self._event_rx_buffer.release()

        return bytes(rx_buffer)

    def close(self) -> None:
        """
        The 'CLOSE' syscall.
        """
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CLOSE</> syscall, "
            "{len(self._tx_buffer)} bytes in TX buffer",
        )
        self.tcp_fsm(syscall=SysCall.CLOSE)

    def _change_state(self, state: FsmState) -> None:
        """
        Change the state of TCP finite state machine.
        """

        old_state = self._state
        self._state = state
        if old_state:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <ly>[{old_state} -> {self._state}]</>",
            )

        # Unregister session
        if self._state in {FsmState.CLOSED}:
            stack.sockets.pop(str(self._socket))
            __debug__ and log(
                "tcp-ss", f"[{self}] - Unregister associated socket"
            )

    def _transmit_packet(
        self,
        seq: int | None = None,
        flag_syn: bool = False,
        flag_ack: bool = False,
        flag_fin: bool = False,
        flag_rst: bool = False,
        data: bytes | None = None,
    ) -> None:
        """
        Send out the TCP packet.
        """

        seq = seq if seq is not None else self._snd_nxt
        ack = self._rcv_nxt if flag_ack else 0

        stack.packet_handler.send_tcp_packet(
            local_ip_address=self._local_ip_address,
            remote_ip_address=self._remote_ip_address,
            local_port=self._local_port,
            remote_port=self._remote_port,
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_fin=flag_fin,
            flag_rst=flag_rst,
            seq=seq,
            ack=ack,
            win=self._rcv_wnd,
            mss=self._rcv_mss if flag_syn else None,
            wscale=0 if flag_syn else None,
            data=data,
        )
        self._rcv_una = self._rcv_nxt
        self._snd_nxt = (
            seq + (0 if data is None else len(data)) + flag_syn + flag_fin
        )
        self._snd_max = max(self._snd_max, self._snd_nxt)
        self._tx_buffer_seq_mod += flag_syn + flag_fin

        # In case packet caries FIN flag make note of its SEQ number.
        if flag_fin:
            self._snd_fin = self._snd_nxt

        # If in ESTABLISHED state then reset ACK delay timer.
        if self._state is FsmState.ESTABLISHED:
            stack.timer.register_timer(f"{self}-delayed_ack", DELAYED_ACK_DELAY)

        # If packet contains data then Initialize / adjust packet's retransmit
        # counter and timer.
        if data or flag_syn or flag_fin:
            self._tx_retransmit_timeout_counter[seq] = (
                self._tx_retransmit_timeout_counter.get(seq, -1) + 1
            )
            stack.timer.register_timer(
                f"{self}-retransmit_seq-{seq}",
                PACKET_RETRANSMIT_TIMEOUT
                * (1 << self._tx_retransmit_timeout_counter[seq]),
            )

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Sent packet_rx_md: {'S' if flag_syn else ''}"
            f"{'F' if flag_fin else ''}{'R' if flag_rst else ''}"
            f"{'A' if flag_ack else ''}, seq {seq}, ack {ack}, "
            f"dlen {(0 if data is None else len(data))}",
        )

    def _enqueue_rx_buffer(self, data: memoryview) -> None:
        """
        Process the incoming segment and enqueue the data
        to be used by socket.
        """

        assert isinstance(
            data, memoryview
        )  # memoryview: check to ensure data gets here as memoryview not bytes

        with self._lock_rx_buffer:
            self._rx_buffer.extend(data)
            # If rx_buffer event has not been released yet
            # (it could be released if some data were siting in buffer already)
            # then release it.
            if not self._event_rx_buffer._value:
                self._event_rx_buffer.release()

    def _transmit_data(self) -> None:
        """
        Send out data segment from TX buffer using TCP
        sliding window mechanism.
        """

        assert (
            self._snd_una <= self._snd_nxt <= self._snd_una + self._snd_ewn
        ), "*** SEQ outside of TCP sliding window"

        # Check if we need to (re)transmit initial SYN packet
        if self._state is FsmState.SYN_SENT and self._snd_nxt == self._snd_ini:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting initial SYN packet_rx_md: "
                f"seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_syn=True)
            return

        # Check if we need to (re)transmit initial SYN + ACK packet
        if self._state is FsmState.SYN_RCVD and self._snd_nxt == self._snd_ini:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting initial SYN + ACK packet_rx_md: "
                f"seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_syn=True, flag_ack=True)
            return

        # Make sure we in the state that allows sending data out
        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            remaining_data_len = len(self._tx_buffer) - self._tx_buffer_nxt
            usable_window = self._snd_ewn - self._tx_buffer_nxt
            transmit_data_len = min(
                self._snd_mss, usable_window, remaining_data_len
            )
            if remaining_data_len:
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sliding window <y>[{self._snd_una}|"
                    f"{self._snd_nxt}|{self._snd_una + self._snd_ewn}]</>",
                )
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - {usable_window} left in window, "
                    f"{remaining_data_len} left in buffer, "
                    f"{transmit_data_len} to be sent",
                )
                if transmit_data_len:
                    with self._lock_tx_buffer:
                        transmit_data = self._tx_buffer[
                            self._tx_buffer_nxt : self._tx_buffer_nxt
                            + transmit_data_len
                        ]
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - Transmitting data segment: "
                        f"seq {self._snd_nxt} len {len(transmit_data)}",
                    )
                    self._transmit_packet(
                        flag_ack=True, data=bytes(transmit_data)
                    )
                return

        # Check if we need to (re)transmit final FIN packet
        if (
            self._state in {FsmState.FIN_WAIT_1, FsmState.LAST_ACK}
            and self._snd_nxt != self._snd_fin
        ):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting final FIN packet_rx_md: "
                f"seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_fin=True, flag_ack=True)
            return

    def _delayed_ack(self) -> None:
        """Run Delayed ACK mechanism"""

        if stack.timer.is_expired(f"{self}-delayed_ack"):
            if self._rcv_nxt > self._rcv_una:
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent out delayed ACK ({self._rcv_nxt})",
                )
            stack.timer.register_timer(f"{self}-delayed_ack", DELAYED_ACK_DELAY)

    def _retransmit_packet_timeout(self) -> None:
        """Retransmit packet after expired timeout"""

        if (
            self._snd_una in self._tx_retransmit_timeout_counter
            and stack.timer.is_expired(f"{self}-retransmit_seq-{self._snd_una}")
        ):
            if (
                self._tx_retransmit_timeout_counter[self._snd_una]
                == PACKET_RETRANSMIT_MAX_COUNT
            ):
                # Send RST packet if we received any packet from peer already
                if self._rcv_nxt is not None:
                    self._transmit_packet(
                        flag_rst=True, flag_ack=True, seq=self._snd_una
                    )
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - Packet retransmit counter expired, "
                        f"resetting session",
                    )
                else:
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - Packet retransmit counter expired",
                    )
                # If in any state with established connection inform socket
                # about connection failure.
                if self._state in {
                    FsmState.ESTABLISHED,
                    FsmState.FIN_WAIT_1,
                    FsmState.FIN_WAIT_2,
                    FsmState.CLOSE_WAIT,
                }:
                    self._connection_error = ConnError.TIMEOUT
                    self._event_rx_buffer.release()
                # If in SYN_SENT state inform CONNECT syscall that the
                # connection related event happened.
                if self._state is FsmState.SYN_SENT:
                    self._connection_error = ConnError.TIMEOUT
                    self._event_connect.release()
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
                return
            self._snd_ewn = self._snd_mss
            self._snd_nxt = self._snd_una
            # In case we need to retransmit packt containing SYN flag adjust
            # tx_buffer_seq_mod so it doesn't reflect SYN flag yet.
            if self._snd_nxt in {self._snd_ini, self._snd_fin}:
                self._tx_buffer_seq_mod -= 1
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Got retransmit timeout, sending segment "
                f"{self._snd_nxt}, resetting snd_ewn to {self._snd_ewn}",
            )
            return

    def _retransmit_packet_request(self, packet_rx_md: TcpMetadata) -> None:
        """
        Retransmit packet after receiving request from peer.
        """
        self._tx_retransmit_request_counter[packet_rx_md.ack] = (
            self._tx_retransmit_request_counter.get(packet_rx_md.ack, 0) + 1
        )
        if self._tx_retransmit_request_counter[packet_rx_md.ack] > 1:
            self._snd_nxt = self._snd_una
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Got retransmit request, sending segment "
                f"{self._snd_nxt}, keeping snd_ewn at {self._snd_ewn}",
            )

    def _process_ack_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process regular data/ACK packet.
        """

        # Make note of the local SEQ that has been acked by peer
        self._snd_una = max(self._snd_una, packet_rx_md.ack)
        # Adjust local SEQ accordingly to what peer acked (needed after the
        # retransmit happens and peer is jumping to previously received SEQ)
        if self._snd_nxt < self._snd_una <= self._snd_max:
            self._snd_nxt = self._snd_una
        # Make note of the remote SEQ number
        self._rcv_nxt = (
            packet_rx_md.seq
            + len(packet_rx_md.data)
            + packet_rx_md.flag_syn
            + packet_rx_md.flag_fin
        )
        # In case packet contains data enqueue it
        if packet_rx_md.data:
            self._enqueue_rx_buffer(packet_rx_md.data)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Enqueued {len(packet_rx_md.data)} bytes "
                f"starting at {packet_rx_md.seq}",
            )
        # Purge acked data from TX buffer
        with self._lock_tx_buffer:
            del self._tx_buffer[: self._tx_buffer_una]
        self._tx_buffer_seq_mod += self._tx_buffer_una
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Purged TX buffer up to SEQ {self._snd_una}",
        )
        # Update remote window size
        if self._snd_wnd != packet_rx_md.win * self._snd_wsc:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Updated sending window size {self._snd_wnd} "
                f"-> {packet_rx_md.win * self._snd_wsc}",
            )
            self._snd_wnd = packet_rx_md.win * self._snd_wsc
        # Enlarge effective sending window
        self._snd_ewn = min(self._snd_ewn << 1, self._snd_wnd)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Updated effective sending window "
            f"to {self._snd_ewn}",
        )
        # Purge expired tx packet retransmit requests
        for seq in list(self._tx_retransmit_request_counter):
            if seq < packet_rx_md.ack:
                self._tx_retransmit_request_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Purged expired TX packet retransmit "
                    f"request counter for {seq}",
                )
        # Purge expired tx packet retransmit timeouts
        for seq in list(self._tx_retransmit_timeout_counter):
            if seq < packet_rx_md.ack:
                self._tx_retransmit_timeout_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Purged expired TX packet retransmit "
                    f"timeout for {seq}",
                )
        # Purge expired rx retransmit requests
        for seq in list(self._rx_retransmit_request_counter):
            if seq < self._rcv_nxt:
                self._rx_retransmit_request_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Purged expired RX packet retransmit "
                    f"request counter for {seq}",
                )
        # Bring next packet from ooo_packet_queue if available
        if ooo_packet := self._ooo_packet_queue.pop(self._rcv_nxt, None):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <lg>Retrieving packet {self._rcv_nxt} from "
                "Out of Order queue</>",
            )
            self.tcp_fsm(ooo_packet)

    def _tcp_fsm_closed(
        self,
        _: TcpMetadata | None,
        syscall: SysCall | None,
        ___: bool | None,
    ) -> None:
        """
        TCP FSM CLOSED state handler.
        """

        # Got CONNECT syscall -> Send SYN packet (this actually will be done in
        # SYN_SENT state) / change state to SYN_SENT.
        if syscall is SysCall.CONNECT:
            self._change_state(FsmState.SYN_SENT)

        # Got LISTEN syscall -> Change state to LISTEN
        if syscall is SysCall.LISTEN:
            self._change_state(FsmState.LISTEN)

    def _tcp_fsm_listen(
        self,
        packet_rx_md: TcpMetadata | None,
        syscall: SysCall | None,
        ___: bool | None,
    ) -> None:
        """
        TCP FSM LISTEN state handler.
        """

        from pytcp.lib.socket import AF_INET4, AF_INET6
        from pytcp.protocols.tcp.socket import TcpSocket

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if (
            packet_rx_md
            and all({packet_rx_md.flag_syn})
            and not any(
                {
                    packet_rx_md.flag_ack,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_rst,
                }
            )
        ):
            # Packet sanity check
            if packet_rx_md.ack == 0 and not packet_rx_md.data:
                # Create new session in LISTEN state and assign it to
                # listening socket
                tcp_session = TcpSession(
                    local_ip_address=self._local_ip_address,
                    local_port=self._local_port,
                    remote_ip_address=self._remote_ip_address,
                    remote_port=self._remote_port,
                    socket=self._socket,
                )
                tcp_session.listen()
                self._socket._tcp_session = tcp_session
                # Adjust this session to match incoming connection and assign
                # it to new socket
                self._local_ip_address = packet_rx_md.local_ip_address
                self._local_port = packet_rx_md.local_port
                self._remote_ip_address = packet_rx_md.remote_ip_address
                self._remote_port = packet_rx_md.remote_port
                self._socket = TcpSocket(
                    (
                        AF_INET6
                        if self._local_ip_address.version == 6
                        else AF_INET4
                    ),
                    tcp_session=self,
                )
                # Initialize session parameters
                self._snd_mss = min(packet_rx_md.mss, config.LOCAL_TCP_MSS)
                self._snd_wnd = (
                    packet_rx_md.win * self._snd_wsc
                )  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self._snd_wsc = (
                    packet_rx_md.wscale if packet_rx_md.wscale else 1
                )  # Peer's wscale set to None means that peer doesn't support window scaling
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Initialized remote window scale at {self._snd_wsc}",
                )
                self._rcv_ini = packet_rx_md.seq
                self._snd_ewn = self._snd_mss
                # Make note of the remote SEQ number
                self._rcv_nxt = packet_rx_md.seq + packet_rx_md.flag_syn
                # Send SYN + ACK packet (this actually will be done in SYN_SENT
                # state) / change state to SYN_RCVD
                self._change_state(FsmState.SYN_RCVD)
                return

        # Got CLOSE syscall -> Change state to CLOSED
        if syscall is SysCall.CLOSE:
            self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_syn_sent(
        self,
        packet_rx_md: TcpMetadata | None,
        syscall: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM SYN_SENT state handler.
        """

        # Got timer event -> Resend SYN packet if its timer expir
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            return

        # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_syn, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_rst})
        ):
            # Packet sanity check
            if packet_rx_md.ack == self._snd_nxt and not packet_rx_md.data:
                # Initialize session parameters
                self._snd_mss = min(packet_rx_md.mss, config.LOCAL_TCP_MSS)
                self._snd_wnd = (
                    packet_rx_md.win * self._snd_wsc
                )  # For SYN / SYN + ACK packets this is initialized with wscale=1
                self._snd_wsc = (
                    packet_rx_md.wscale if packet_rx_md.wscale else 1
                )  # Peer's wscale set to None means that peer doesn't support window scaling
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Initialized remote window scale "
                    f"at {self._snd_wsc}",
                )
                self._rcv_ini = packet_rx_md.seq
                self._snd_ewn = self._snd_mss
                # Process ACK packet
                self._process_ack_packet(packet_rx_md)
                # Send initial ACK packet
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent initial ACK ({self._rcv_una}) packet",
                )
                # Change state to ESTABLISHED
                self._change_state(FsmState.ESTABLISHED)
                # Inform connect syscall that connection related event happened
                self._event_connect.release()
                return

        # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD
        if (
            packet_rx_md
            and all({packet_rx_md.flag_syn})
            and not any(
                {
                    packet_rx_md.flag_ack,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_syn,
                }
            )
        ):
            # Packet sanity check
            if packet_rx_md.ack == 0 and not packet_rx_md.data:
                # Send SYN + ACK packet
                self._transmit_packet(flag_syn=True, flag_ack=True)
                # Change state to SYN_RCVD
                self._change_state(FsmState.SYN_RCVD)
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if packet_rx_md.seq == 0 and packet_rx_md.ack == self._snd_nxt:
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
                # Inform connect syscall that connection related event happened
                self._connection_error = ConnError.REFUSED
                self._event_connect.release()
            return

        # Got CLOSE syscall -> Change state to CLOSE
        if syscall is SysCall.CLOSE:
            self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_syn_rcvd(
        self,
        packet_rx_md: TcpMetadata | None,
        syscall: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM ESTABLISHED state handler.
        """

        # Got timer event -> Resend SYN packet if its timer expir
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            return

        # Got ACK packet -> Change state to ESTABLISHED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_rst,
                }
            )
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and packet_rx_md.ack == self._snd_nxt
                and not packet_rx_md.data
            ):
                self._process_ack_packet(packet_rx_md)
                # Change state to ESTABLISHED
                self._change_state(FsmState.ESTABLISHED)
                # Inform the listening socket that session has been established
                # so accept call can pick it up.
                self._socket._parent_socket._tcp_accept.append(self._socket)
                self._socket._parent_socket._event_tcp_session_established.release()
                # Inform connect syscall that connection related event happened,
                # this is needed only in case of tcp simultaneous open.
                self._event_connect.release()
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

        # Got RST packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst})
            and not any(
                {
                    packet_rx_md.flag_ack,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_syn,
                }
            )
        ):
            # Packet sanity_check
            if packet_rx_md.seq == self._rcv_nxt and packet_rx_md.ack == 0:
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

        # Got CLOSE sycall -> Send FIN packet (this actually will be done in
        # SYN_SENT state) / change state to FIN_WAIT_1.
        if syscall is SysCall.CLOSE:
            self._change_state(FsmState.FIN_WAIT_1)
            return

    def _tcp_fsm_established(
        self,
        packet_rx_md: TcpMetadata | None,
        syscall: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM ESTABLISHED state handler.
        """

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            self._delayed_ack()
            if self._closing and not self._tx_buffer:
                self._change_state(FsmState.FIN_WAIT_1)
            return

        # Got packet that doesn't fit into receive window
        if (
            packet_rx_md
            and not self._rcv_nxt
            <= packet_rx_md.seq
            <= self._rcv_nxt + self._rcv_wnd - len(packet_rx_md.data)
        ):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Packet seq {packet_rx_md.seq} + "
                f"{len(packet_rx_md.data)} doesn't fit into receive "
                "window, dropping",
            )
            return

        # Got ACK packet
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_rst,
                    packet_rx_md.flag_fin,
                }
            )
        ):
            # Suspected retransmit request -> Reset TX window
            # and local SEQ number.
            if (
                packet_rx_md.seq == self._rcv_nxt
                and packet_rx_md.ack == self._snd_una
                and not packet_rx_md.data
            ):
                self._retransmit_packet_request(packet_rx_md)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and
            # send 'fast retransmit' request (don't send more than two).
            if (
                packet_rx_md.seq > self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._ooo_packet_queue[packet_rx_md.seq] = packet_rx_md
                self._rx_retransmit_request_counter[self._rcv_nxt] = (
                    self._rx_retransmit_request_counter.get(self._rcv_nxt, 0)
                    + 1
                )
                if self._rx_retransmit_request_counter[self._rcv_nxt] <= 2:
                    self._transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                return
            return

        # Got FIN + ACK packet -> Send ACK packet (let delayed ACK mechanism
        # do it) / change state to CLOSE_WAIT / notify app that peer closed
        # connection.
        if (
            packet_rx_md
            and all({packet_rx_md.flag_fin, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_syn, packet_rx_md.flag_rst})
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                # Immediately acknowledge the received data if any.
                if packet_rx_md.data:
                    self._transmit_packet(flag_ack=True)
                # Let application know that remote peer closed connection
                # (let receive syscall bypass semaphore).
                self._event_rx_buffer.release()
                # Change state to CLOSE_WAIT
                self._change_state(FsmState.CLOSE_WAIT)
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Let application know that remote peer closed connection
                # (let receive syscall bypass semaphore).
                self._event_rx_buffer.release()
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

        # Got CLOSE syscall -> Send FIN packet (this actually will be done in
        # SYN_SENT state) / change state to FIN_WAIT_1.
        if syscall is SysCall.CLOSE:
            self._closing = True
            return

    def _tcp_fsm_fin_wait_1(
        self,
        packet_rx_md: TcpMetadata | None,
        __: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM FIN_WAIT_1 state handler.
        """

        # Got timer event -> Transmit final FIN packet
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            return

        # Got ACK (acking our FIN) packet -> Change state to FIN_WAIT_2
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_rst,
                    packet_rx_md.flag_fin,
                }
            )
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                # Immediately acknowledge the received data if any
                if packet_rx_md.data:
                    self._transmit_packet(flag_ack=True)
                # Check if packet acks our FIN
                if packet_rx_md.ack >= self._snd_fin:
                    # Change state to FIN_WAIT_2
                    self._change_state(FsmState.FIN_WAIT_2)
            return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        # or CLOSING
        if (
            packet_rx_md
            and all({packet_rx_md.flag_fin, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_syn, packet_rx_md.flag_rst})
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                # Send out final ACK packet
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent final ACK ({self._rcv_nxt}) packet",
                )
                # Check if packet acks our FIN
                if packet_rx_md.ack >= self._snd_fin:
                    # Change state to TIME_WAIT
                    self._change_state(FsmState.TIME_WAIT)
                    # Initialize TIME_WAIT delay
                    stack.timer.register_timer(
                        f"{self}-time_wait", TIME_WAIT_DELAY
                    )
                else:
                    # Change state to CLOSING
                    self._change_state(FsmState.CLOSING)
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_fin_wait_2(
        self,
        packet_rx_md: TcpMetadata | None,
        __: SysCall | None,
        ___: bool | None,
    ) -> None:
        """
        TCP FSM FIN_WAIT_2 state handler.
        """

        # Got ACK packet -> Process data
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_rst,
                    packet_rx_md.flag_fin,
                }
            )
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                # Immediately acknowledge the received data if any
                if packet_rx_md.data:
                    self._transmit_packet(flag_ack=True)
                return

        # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT
        if (
            packet_rx_md
            and all({packet_rx_md.flag_fin, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_syn, packet_rx_md.flag_rst})
        ):
            # Packet sanity check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._process_ack_packet(packet_rx_md)
                # Send out final ACK packet
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent final ACK ({self._rcv_nxt}) packet",
                )
                # Change state to TIME_WAIT
                self._change_state(FsmState.TIME_WAIT)
                # Initialize TIME_WAIT delay
                stack.timer.register_timer(f"{self}-time_wait", TIME_WAIT_DELAY)
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_closing(
        self,
        packet_rx_md: TcpMetadata | None,
        __: SysCall | None,
        ___: bool | None,
    ) -> None:
        """
        TCP FSM CLOSING state handler.
        """

        # Got ACK packet -> Change state to TIME_WAIT
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_rst,
                }
            )
        ):
            # Packet sanity check
            if (
                packet_rx_md.ack == self._snd_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._snd_una = packet_rx_md.ack
                self._change_state(FsmState.TIME_WAIT)
                # Initialize TIME_WAIT delay
                stack.timer.register_timer(f"{self}-time_wait", TIME_WAIT_DELAY)
                return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_close_wait(
        self,
        packet_rx_md: TcpMetadata | None,
        syscall: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM CLOSE_WAIT state handler.
        """

        # Got timer event -> Send out data and run Delayed ACK mechanism
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            self._delayed_ack()
            if self._closing and not self._tx_buffer:
                self._change_state(FsmState.LAST_ACK)
            return

        # Got ACK packet
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_rst,
                    packet_rx_md.flag_fin,
                }
            )
        ):
            # Suspected retransmit request -> Reset TX window
            # and local SEQ number.
            if (
                packet_rx_md.seq == self._rcv_nxt
                and packet_rx_md.ack == self._snd_una
                and not packet_rx_md.data
            ):
                self._retransmit_packet_request(packet_rx_md)
                return
            # Packet with higher SEQ than what we are expecting -> Store it and
            # send 'fast retransmit' request.
            if (
                packet_rx_md.seq > self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._ooo_packet_queue[packet_rx_md.seq] = packet_rx_md
                self._rx_retransmit_request_counter[self._rcv_nxt] = (
                    self._rx_retransmit_request_counter.get(self._rcv_nxt, 0)
                    + 1
                )
                if self._rx_retransmit_request_counter[self._rcv_nxt] <= 2:
                    self._transmit_packet(flag_ack=True)
                return
            # Regular data/ACK packet -> Process data
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
                and not packet_rx_md.data
            ):
                self._process_ack_packet(packet_rx_md)
                return
            return

        # Got RST packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst})
            and not any(
                {
                    packet_rx_md.flag_ack,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_syn,
                }
            )
        ):
            # Packet sanity_check
            if packet_rx_md.seq == self._rcv_nxt:
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

        # Got CLOSE syscall -> Send FIN packet (this actually will be done in
        # SYN_SENT state) / change state to LAST_ACK.
        if syscall is SysCall.CLOSE:
            self._closing = True
            return

    def _tcp_fsm_last_ack(
        self,
        packet_rx_md: TcpMetadata | None,
        __: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM LAST_ACK state handler.
        """

        # Got timer event -> Transmit final FIN packet
        if timer:
            self._retransmit_packet_timeout()
            self._transmit_data()
            return

        # Got ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_ack})
            and not any(
                {
                    packet_rx_md.flag_syn,
                    packet_rx_md.flag_fin,
                    packet_rx_md.flag_rst,
                }
            )
        ):
            # Packet sanity check
            if (
                packet_rx_md.ack == self._snd_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                self._change_state(FsmState.CLOSED)
            return

        # Got RST + ACK packet -> Change state to CLOSED
        if (
            packet_rx_md
            and all({packet_rx_md.flag_rst, packet_rx_md.flag_ack})
            and not any({packet_rx_md.flag_fin, packet_rx_md.flag_syn})
        ):
            # Packet sanity_check
            if (
                packet_rx_md.seq == self._rcv_nxt
                and self._snd_una <= packet_rx_md.ack <= self._snd_max
            ):
                # Change state to CLOSED
                self._change_state(FsmState.CLOSED)
            return

    def _tcp_fsm_time_wait(
        self,
        _: TcpMetadata | None,
        __: SysCall | None,
        timer: bool | None,
    ) -> None:
        """
        TCP FSM TIME_WAIT state handler.
        """

        # Got timer event -> Run TIME_WAIT delay
        if timer and stack.timer.is_expired(f"{self}-time_wait"):
            self._change_state(FsmState.CLOSED)
            return

    def tcp_fsm(
        self,
        packet_rx_md: TcpMetadata | None = None,
        syscall: SysCall | None = None,
        timer: bool | None = None,
    ) -> None:
        """
        Run TCP finite state machine.
        """

        # Process event
        with self._lock_fsm:
            return {
                FsmState.CLOSED: self._tcp_fsm_closed,
                FsmState.LISTEN: self._tcp_fsm_listen,
                FsmState.SYN_SENT: self._tcp_fsm_syn_sent,
                FsmState.SYN_RCVD: self._tcp_fsm_syn_rcvd,
                FsmState.ESTABLISHED: self._tcp_fsm_established,
                FsmState.FIN_WAIT_1: self._tcp_fsm_fin_wait_1,
                FsmState.FIN_WAIT_2: self._tcp_fsm_fin_wait_2,
                FsmState.CLOSING: self._tcp_fsm_closing,
                FsmState.CLOSE_WAIT: self._tcp_fsm_close_wait,
                FsmState.LAST_ACK: self._tcp_fsm_last_ack,
                FsmState.TIME_WAIT: self._tcp_fsm_time_wait,
            }[self._state](packet_rx_md, syscall, timer)
