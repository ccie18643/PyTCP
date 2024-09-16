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
Module contains BSD like Raw socket interface for the stack.

pytcp/socket/raw__socket.py

ver 3.0.2
"""

'''
from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp.lib.ip_helper import pick_local_ip_address
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
    from pytcp.socket.raw__metadata import RawMetadata


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

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address)
            if local_ip_address.is_unspecified:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed remote IP address]"
                )

        assert isinstance(local_ip_address, (Ip6Address, Ip4Address))

        return local_ip_address, remote_ip_address

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
                    ip6__local_address=local_ip_address,
                    ip6__remote_address=remote_ip_address,
                    ip6__next=self._ip_proto,
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
                f"{len(packet_rx_md.raw__data)} bytes of data",
            )
            return (
                packet_rx_md.raw__data,
                (
                    str(packet_rx_md.ip__remote_address),
                    0,
                ),
            )
        raise ReceiveTimeout

    def close(self) -> None:
        """
        Close socket.
        """

        stack.sockets.pop(self.id, None)

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_raw_packet(self, packet_rx_md: RawMetadata) -> None:
        """
        Process incoming packet's metadata.
        """

        self._packet_rx_md.append(packet_rx_md)
        self._packet_rx_md_ready.release()
'''
