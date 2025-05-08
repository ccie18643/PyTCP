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
# pylint: disable = too-many-instance-attributes
# pylint: disable = consider-using-with
# pylint: disable = fixme

"""
Module contains BSD like socket interface for the stack.

pytcp/protocols/udp/socket.py

ver 2.7
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address, Ip4AddressFormatError
from pytcp.lib.ip6_address import Ip6Address, Ip6AddressFormatError
from pytcp.lib.logger import log
from pytcp.lib.socket import (
    AF_INET4,
    AF_INET6,
    SOCK_DGRAM,
    ReceiveTimeout,
    Socket,
    gaierror,
)
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.lib.ip_address import IpAddress
    from pytcp.lib.socket import AddressFamily, SocketType
    from pytcp.protocols.udp.metadata import UdpMetadata


class UdpSocket(Socket):
    """
    Support for IPv6/IPv4 UDP socket operations.
    """

    def __init__(self, family: AddressFamily) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._family: AddressFamily = family
        self._type: SocketType = SOCK_DGRAM
        self._local_port: int = 0
        self._remote_port: int = 0
        self._packet_rx_md: list[UdpMetadata] = []
        self._packet_rx_md_ready: Semaphore = threading.Semaphore(0)
        self._unreachable: bool = False
        self._local_ip_address: IpAddress
        self._remote_ip_address: IpAddress

        if self._family is AF_INET6:
            self._local_ip_address = Ip6Address(0)
            self._remote_ip_address = Ip6Address(0)
        if self._family is AF_INET4:
            self._local_ip_address = Ip4Address(0)
            self._remote_ip_address = Ip4Address(0)

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address and specific local port in case provided port equals zero
        # port value will be picked automatically.

        # Check if "bound" already
        if self._local_port in range(1, 65536):
            raise OSError(
                "[Errno 22] Invalid argument - "
                "[Socket bound to specific port already]"
            )

        local_ip_address: IpAddress

        if self._family is AF_INET6:
            try:
                if (local_ip_address := Ip6Address(address[0])) not in set(
                    stack.packet_handler.ip6_unicast
                ) | {Ip6Address(0)}:
                    raise OSError(
                        "[Errno 99] Cannot assign requested address - "
                        "[Local IP address not owned by stack]"
                    )
            except Ip6AddressFormatError as error:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed local IP address]"
                ) from error

        if self._family is AF_INET4:
            try:
                if (local_ip_address := Ip4Address(address[0])) not in set(
                    stack.packet_handler.ip4_unicast
                ) | {Ip4Address(0)}:
                    raise OSError(
                        "[Errno 99] Cannot assign requested address - "
                        "[Local IP address not owned by stack]"
                    )
            except Ip4AddressFormatError as error:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed local IP address]"
                ) from error

        # Sanity check on local port number
        if address[1] not in range(0, 65536):
            raise OverflowError(
                "bind(): port must be 0-65535. - [Port out of range]"
            )

        # Confirm or pick local port number
        if (local_port := address[1]) > 0:
            if self._is_address_in_use(local_ip_address, local_port):
                raise OSError(
                    "[Errno 98] Address already in use - "
                    "[Local address already in use]"
                )
        else:
            local_port = self._pick_local_port()

        # Assigning local port makes socket "bound"
        stack.sockets.pop(str(self), None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets[str(self)] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local IP address (will
        # rebind if necessary), specific local port, specific remote IP address
        # and specific remote port.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError(
                "connect(): port must be 0-65535. - [Port out of range]"
            )

        # Assigning local port makes socket "bound" if not "bound" already
        if (local_port := self._local_port) not in range(1, 65536):
            local_port = self._pick_local_port()

        # Set local and remote ip addresses appropriately
        local_ip_address, remote_ip_address = self._set_ip_addresses(
            address, self._local_ip_address, local_port, remote_port
        )

        # Re-register socket with new socket id
        stack.sockets.pop(str(self), None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[str(self)] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Connected socket")

    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.
        if self._remote_ip_address.is_unspecified or self._remote_port == 0:
            raise OSError(
                "[Errno 89] Destination address require - "
                "[Socket has no destination address set]"
            )

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError(
                "[Errno 111] Connection refused - "
                "[Remote host sent ICMP Unreachable]"
            )

        tx_status = stack.packet_handler.send_udp_packet(
            local_ip_address=self._local_ip_address,
            remote_ip_address=self._remote_ip_address,
            local_port=self._local_port,
            remote_port=self._remote_port,
            data=data,
        )

        sent_data_len = (
            len(data) if tx_status is TxStatus.PASSED__ETHER__TO_TX_RING else 0
        )

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - <lr>Sent</> {sent_data_len} bytes of data",
        )

        return sent_data_len

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send the data to remote host.
        """

        # The 'sendto' call will bind socket to specific local port,
        # will leave local ip address intact.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError(
                "connect(): port must be 0-65535. - [Port out of range]"
            )

        # Assigning local port makes socket "bound" if not "bound" already
        if self._local_port not in range(1, 65536):
            stack.sockets.pop(str(self), None)
            self._local_port = self._pick_local_port()
            stack.sockets[str(self)] = self

        # Set local and remote ip addresses appropriately
        local_ip_address, remote_ip_address = self._set_ip_addresses(
            address, self._local_ip_address, self._local_port, remote_port
        )

        tx_status = stack.packet_handler.send_udp_packet(
            local_ip_address=local_ip_address,
            remote_ip_address=remote_ip_address,
            local_port=self._local_port,
            remote_port=remote_port,
            data=data,
        )

        sent_data_len = (
            len(data) if tx_status is TxStatus.PASSED__ETHER__TO_TX_RING else 0
        )

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - <lr>Sent</> {sent_data_len} bytes of data",
        )

        return sent_data_len

    def recv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> bytes:
        """Read data from socket"""

        # TODO - Implement support for buffsize

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError(
                "[Errno 111] Connection refused - "
                "[Remote host sent ICMP Unreachable]"
            )

        if self._packet_rx_md_ready.acquire(timeout=timeout):
            data_rx = self._packet_rx_md.pop(0).data
            __debug__ and log(
                "socket",
                f"<g>[{self}]</> - <lg>Received</> {len(data_rx)} "
                "bytes of data",
            )
            return data_rx
        raise ReceiveTimeout

    def recvfrom(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        """
        Read data from socket.
        """

        # TODO - Implement support for buffsize

        if self._packet_rx_md_ready.acquire(timeout=timeout):
            packet_rx_md = self._packet_rx_md.pop(0)
            __debug__ and log(
                "socket",
                f"<g>[{self}]</> - <lg>Received</> "
                f"{len(packet_rx_md.data)} bytes of data",
            )
            return (
                packet_rx_md.data,
                (str(packet_rx_md.remote_ip_address), packet_rx_md.remote_port),
            )
        raise ReceiveTimeout

    def close(self) -> None:
        """
        Close socket.
        """
        stack.sockets.pop(str(self), None)
        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_udp_packet(self, packet_rx_md: UdpMetadata) -> None:
        """
        Process incoming packet's metadata.
        """
        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()

    def notify_unreachable(self) -> None:
        """
        Set the unreachable notification.
        """
        self._unreachable = True
