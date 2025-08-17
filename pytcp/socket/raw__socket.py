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
This module contains BSD like Raw socket interface for the stack.

pytcp/socket/raw__socket.py

ver 3.0.3
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING, cast

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp import stack
from pytcp.lib.ip_helper import pick_local_ip_address
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.socket.socket import (
    AddressFamily,
    Socket,
    SocketType,
    gaierror,
)

if TYPE_CHECKING:
    from pytcp.socket.raw__metadata import RawMetadata
    from pytcp.socket.socket import IpProto


class RawSocket(Socket):
    """
    Support for IPv6/IPv4 Raw socket operations.
    """

    _socket_type = SocketType.RAW

    def __init__(
        self, *, address_family: AddressFamily, ip_proto: IpProto
    ) -> None:
        """
        Class constructor.
        """

        self._address_family = address_family
        self._ip_proto = ip_proto
        self._packet_rx_md: list[RawMetadata] = []
        self._packet_rx_md_ready = threading.Semaphore(0)

        match self._address_family:
            case AddressFamily.INET6:
                self._local_ip_address = Ip6Address()
                self._remote_ip_address = Ip6Address()
            case AddressFamily.INET4:
                self._local_ip_address = Ip4Address()
                self._remote_ip_address = Ip4Address()

        self._local_port = int(ip_proto)
        self._remote_port = 0

        __debug__ and log("socket", f"<g>[{self}]</> - Created socket")

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address, Ip6Address] | tuple[Ip4Address, Ip4Address]:
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

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(
                remote_ip_address=remote_ip_address
            )
            if local_ip_address.is_unspecified:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed remote IP address]"
                )
        else:
            local_ip_address = self._local_ip_address

        return local_ip_address, remote_ip_address  # type: ignore[return-value]

    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address.

        local_ip_address: Ip6Address | Ip4Address

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

        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        stack.sockets[self.socket_id] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local IP address (will
        # rebind if necessary) and specific remote IP address.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError(
                "connect(): port must be 0-65535. - [Port out of range]"
            )

        # Set local and remote ip addresses aproprietely
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id
        stack.sockets.pop(self.socket_id, None)
        self._local_ip_address = local_ip_address
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[self.socket_id] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Connected socket")

    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.
        if self._remote_ip_address.is_unspecified:
            raise OSError(
                "[Errno 89] Destination address require - "
                "[Socket has no destination address set]"
            )

        match self._address_family:
            case AddressFamily.INET6:
                tx_status = stack.packet_handler.send_ip6_packet(
                    ip6__local_address=cast(Ip6Address, self._local_ip_address),
                    ip6__remote_address=cast(
                        Ip6Address, self._remote_ip_address
                    ),
                    ip6__next=self._ip_proto,
                    ip6__payload=data,
                )
            case AddressFamily.INET4:
                tx_status = stack.packet_handler.send_ip4_packet(
                    ip4__local_address=cast(Ip4Address, self._local_ip_address),
                    ip4__remote_address=cast(
                        Ip4Address, self._remote_ip_address
                    ),
                    ip4__proto=self._ip_proto,
                    ip4__payload=data,
                )

        sent_data_len = (
            len(data)
            if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING
            else 0
        )

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send the data to remote host.
        """

        # Set local and remote ip addresses aproprietely
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        match self._address_family:
            case AddressFamily.INET6:
                tx_status = stack.packet_handler.send_ip6_packet(
                    ip6__local_address=cast(Ip6Address, local_ip_address),
                    ip6__remote_address=cast(Ip6Address, remote_ip_address),
                    ip6__next=self._ip_proto,
                    ip6__payload=data,
                )
            case AddressFamily.INET4:
                tx_status = stack.packet_handler.send_ip4_packet(
                    ip4__local_address=cast(Ip4Address, local_ip_address),
                    ip4__remote_address=cast(Ip4Address, remote_ip_address),
                    ip4__proto=self._ip_proto,
                    ip4__payload=data,
                )

        sent_data_len = (
            len(data)
            if tx_status is TxStatus.PASSED__ETHERNET__TO_TX_RING
            else 0
        )

        __debug__ and log(
            "socket",
            f"<B><lr>[{self}]</> - Sent {sent_data_len} bytes of data",
        )

        return sent_data_len

    def recv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> bytes:
        """
        Read data from socket.
        """

        # TODO - Implement support for buffsize

        if self._packet_rx_md_ready.acquire(timeout=timeout):
            data_rx = self._packet_rx_md.pop(0).raw__data
            __debug__ and log(
                "socket",
                f"<B><g>[{self}]</> - Received {len(data_rx)} " "bytes of data",
            )
            return data_rx

        raise TimeoutError("RAW Socket - Receive operation timed out.")

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
                f"<B><g>[{self}]</> - Received "
                f"{len(packet_rx_md.raw__data)} bytes of data",
            )
            return (
                packet_rx_md.raw__data,
                (
                    str(packet_rx_md.ip__remote_address),
                    0,
                ),
            )

        raise TimeoutError("RAW Socket - Receive operation timed out.")

    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.pop(self.socket_id, None)

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_raw_packet(self, packet_rx_md: RawMetadata) -> None:
        """
        Process incoming packet's metadata.
        """

        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()
