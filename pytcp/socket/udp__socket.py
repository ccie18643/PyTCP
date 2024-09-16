#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains BSD like UDP socket interface for the stack.

pytcp/socket/udp__socket.py

ver 3.0.2
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp import stack
from pytcp.lib.ip_helper import (
    is_address_in_use,
    pick_local_ip_address,
    pick_local_port,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.socket.socket import (
    AddressFamily,
    IpProto,
    ReceiveTimeout,
    Socket,
    SocketType,
    gaierror,
)

if TYPE_CHECKING:
    from net_addr import IpAddress
    from pytcp.socket.udp__metadata import UdpMetadata


class UdpSocket(Socket):
    """
    Support for IPv6/IPv4 UDP socket operations.
    """

    _socket_type = SocketType.DGRAM
    _ip_proto = IpProto.UDP

    def __init__(self, *, address_family: AddressFamily) -> None:
        """
        Class constructor.
        """

        self._address_family = address_family
        self._local_port = 0
        self._remote_port = 0
        self._packet_rx_md: list[UdpMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)
        self._unreachable = False

        match self._address_family:
            case AddressFamily.INET6:
                self._local_ip_address = Ip6Address()
                self._remote_ip_address = Ip6Address()
            case AddressFamily.INET4:
                self._local_ip_address = Ip4Address()
                self._remote_ip_address = Ip4Address()

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address | Ip4Address, Ip6Address | Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._address_family is AddressFamily.INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror(
                "[Errno -2] Name or service not known - "
                "[Malformed remote IP address]"
            ) from error

        if remote_ip_address.is_unspecified:
            self._unreachable = True

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address)
            if local_ip_address.is_unspecified and not (
                (
                    self._address_family == AddressFamily.INET4
                    and self._local_port == 68
                    and remote_address[1] == 67
                )  # The DHCPv4 client operation.
                or (
                    self._address_family == AddressFamily.INET6
                    and self._local_port == 546
                    and remote_address[1] == 547
                )  # The DHCPv6 client operation.
            ):
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed remote IP address]"
                )

        assert isinstance(local_ip_address, (Ip6Address, Ip4Address))

        return local_ip_address, remote_ip_address

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

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

        match self._address_family:
            case AddressFamily.INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(
                        stack.packet_handler.ip6_unicast
                    ) | {Ip6Address()}:
                        raise OSError(
                            "[Errno 99] Cannot assign requested address - "
                            "[Local IP address not owned by stack]"
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror(
                        "[Errno -2] Name or service not known - "
                        "[Malformed local IP address]"
                    ) from error

            case AddressFamily.INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(
                        stack.packet_handler.ip4_unicast
                    ) | {Ip4Address()}:
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
            if is_address_in_use(
                local_ip_address=local_ip_address,
                local_port=local_port,
                address_family=self._address_family,
                socket_type=self._socket_type,
            ):
                raise OSError(
                    "[Errno 98] Address already in use - "
                    "[Local address already in use]"
                )
        else:
            local_port = pick_local_port()

        # Assigning local port makes socket "bound"
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets[self.socket_id] = self

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
            local_port = pick_local_port()

        # Set local and remote ip addresses aproprietely
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[self.socket_id] = self

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
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=self._remote_port,
            udp__payload=data,
        )

        sent_data_len = (
            len(data)
            if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING
            else 0
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
                "sendto(): port must be 0-65535. - [Port out of range]"
            )

        # Assigning local port makes socket "bound" if not "bound" already
        if self._local_port not in range(1, 65536):
            stack.sockets.pop(self.socket_id, None)
            self._local_port = pick_local_port()
            stack.sockets[self.socket_id] = self

        # Set local and remote ip addresses aproprietely
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        tx_status = stack.packet_handler.send_udp_packet(
            ip__local_address=local_ip_address,
            ip__remote_address=remote_ip_address,
            udp__local_port=self._local_port,
            udp__remote_port=remote_port,
            udp__payload=data,
        )

        sent_data_len = (
            len(data)
            if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING
            else 0
        )

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - <lr>Sent</> {sent_data_len} bytes of data",
        )

        return sent_data_len

    def recv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> bytes:
        """
        Read data from socket.
        """

        # TODO - Implement support for buffsize

        if self._unreachable:
            self._unreachable = False
            raise ConnectionRefusedError(
                "[Errno 111] Connection refused - "
                "[Remote host sent ICMP Unreachable]"
            )

        if self._packet_rx_md_ready.acquire(timeout=timeout):
            data_rx = self._packet_rx_md.pop(0).udp__data
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
                f"{len(packet_rx_md.udp__data)} bytes of data",
            )
            return (
                packet_rx_md.udp__data,
                (
                    str(packet_rx_md.ip__remote_address),
                    packet_rx_md.udp__remote_port,
                ),
            )
        raise ReceiveTimeout

    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.pop(self.socket_id, None)

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
