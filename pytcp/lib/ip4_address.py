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

# pylint: disable = missing-class-docstring

"""
Module contains IPv4 address manipulation classes.

pytcp/lib/ip4_address.py

ver 2.7
"""


from __future__ import annotations

import re
import socket
import struct

from pytcp.lib.ip_address import (
    IpAddress,
    IpAddressFormatError,
    IpHost,
    IpHostFormatError,
    IpHostGatewayError,
    IpMask,
    IpMaskFormatError,
    IpNetwork,
    IpNetworkFormatError,
)
from pytcp.lib.mac_address import MacAddress

IP4_REGEX = (
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
)


class Ip4AddressFormatError(IpAddressFormatError):
    pass


class Ip4MaskFormatError(IpMaskFormatError):
    pass


class Ip4NetworkFormatError(IpNetworkFormatError):
    pass


class Ip4HostFormatError(IpHostFormatError):
    pass


class Ip4HostGatewayError(IpHostGatewayError):
    pass


class Ip4Address(IpAddress):
    """
    IPv4 address support class.
    """

    def __init__(
        self, address: Ip4Address | str | bytes | bytearray | memoryview | int
    ) -> None:
        """
        Class constructor.
        """

        self._address: int
        self._version: int = 4

        if isinstance(address, int):
            if address & 0xFF_FF_FF_FF == address:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 4:
                self._address = struct.unpack("!L", address)[0]
                return

        if isinstance(address, str):
            if re.search(IP4_REGEX, address):
                try:
                    self._address = struct.unpack(
                        "!L", socket.inet_aton(address)
                    )[0]
                    return
                except OSError:
                    pass

        if isinstance(address, Ip4Address):
            self._address = int(address)
            return

        raise Ip4AddressFormatError(address)

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """
        return socket.inet_ntoa(bytes(self))

    def __bytes__(self) -> bytes:
        """
        The '__bytes__()' dunder.
        """
        return struct.pack("!L", self._address)

    @property
    def is_global(self) -> bool:
        """
        Check if IPv4 address is global.
        """
        return not any(
            (
                self.is_unspecified,
                self.is_invalid,
                self.is_link_local,
                self.is_loopback,
                self.is_multicast,
                self.is_private,
                self.is_reserved,
                self.is_limited_broadcast,
            )
        )

    @property
    def is_link_local(self) -> bool:
        """
        Check if IPv4 address is link local.
        """
        return (
            self._address & 0xFF_FF_00_00 == 0xA9_FE_00_00
        )  # 169.254.0.0 - 169.254.255.255

    @property
    def is_loopback(self) -> bool:
        """
        Check if IPv4 address is loopback.
        """

        return (
            self._address & 0xFF_00_00_00 == 0x7F_00_00_00
        )  # 127.0.0.0 - 127.255.255.255

    @property
    def is_multicast(self) -> bool:
        """
        Check if IPv4 address is multicast.
        """
        return (
            self._address & 0xF0_00_00_00 == 0xE0_00_00_00
        )  # 224.0.0.0 - 239.255.255.255

    @property
    def is_private(self) -> bool:
        """
        Check if IPv4 address is private.
        """
        return (
            self._address & 0xFF_00_00_00
            == 0x0A_00_00_00  # 10.0.0.0 - 10.255.255.255
            or self._address & 0xFF_F0_00_00
            == 0xAC_10_00_00  # 172.16.0.0 - 172.31.255.255
            or self._address & 0xFF_FF_00_00
            == 0xC0_A8_00_00  # 192.168.0.0 - 192.168.255.255
        )

    @property
    def is_reserved(self) -> bool:
        """
        Check if IPv4 address is reserved.
        """
        return (
            self._address & 0xF0_00_00_01 == 0xF0_00_00_00
        )  # 240.0.0.0 - 255.255.255.254

    @property
    def is_limited_broadcast(self) -> bool:
        """
        Check if IPv4 address is a limited broadcast.
        """
        return self._address == 0xFF_FF_FF_FF  # 255.255.255.255

    @property
    def is_invalid(self) -> bool:
        """
        Check if IPv4 address is reserved.
        """
        return (
            self._address != 0x00_00_00_00
            and self._address & 0xFF_00_00_00 == 0x00_00_00_00
        )  # 0.0.0.1 - 0.255.255.255

    @property
    def unspecified(self) -> Ip4Address:
        """
        Return unspecified IPv4 Address.
        """
        return Ip4Address(0)

    @property
    def multicast_mac(self) -> MacAddress:
        """
        Create IPv6 multicast MAC address.
        """
        assert self.is_multicast
        return MacAddress(
            int(MacAddress(0x01005E000000)) | self._address & 0x7FFFFF
        )


class Ip4Mask(IpMask):
    """
    IPv4 network mask support class.
    """

    def __init__(
        self, mask: Ip4Mask | str | bytes | bytearray | memoryview | int
    ) -> None:
        """
        Class constructor.
        """

        self._mask: int
        self._version: int = 4

        def _validate_bits() -> bool:
            """
            Validate that mask is made of consecutive bits.
            """
            bit_mask = f"{self._mask:032b}"
            try:
                return not bit_mask[bit_mask.index("0") :].count("1")
            except ValueError:
                return True

        if isinstance(mask, int):
            if mask & 0xFF_FF_FF_FF == mask:
                self._mask = mask
                if _validate_bits():
                    return

        if isinstance(mask, (memoryview, bytes, bytearray)):
            if len(mask) == 4:
                self._mask = struct.unpack("!L", mask)[0]
                if _validate_bits():
                    return

        if isinstance(mask, str) and re.search(r"^\/\d{1,2}$", mask):
            bit_count = int(mask[1:])
            if bit_count in range(33):
                self._mask = int("1" * bit_count + "0" * (32 - bit_count), 2)
                return

        if isinstance(mask, str) and re.search(IP4_REGEX, mask):
            try:
                self._mask = struct.unpack("!L", socket.inet_aton(mask))[0]
                if _validate_bits():
                    return
            except OSError:
                pass

        if isinstance(mask, Ip4Mask):
            self._mask = mask._mask
            return

        raise Ip4MaskFormatError(mask)

    def __bytes__(self) -> bytes:
        """
        The '__bytes_()' dunder.
        """
        return struct.pack("!L", self._mask)


class Ip4Network(IpNetwork):
    """
    IPv4 network support class.
    """

    def __init__(
        self, network: Ip4Network | tuple[Ip4Address, Ip4Mask] | str
    ) -> None:
        """
        Class constructor.
        """

        self._address: Ip4Address
        self._mask: Ip4Mask
        self._version: int = 4

        if isinstance(network, tuple):
            if len(network) == 2:
                if isinstance(network[0], Ip4Address) and isinstance(
                    network[1], Ip4Mask
                ):
                    self._mask = network[1]
                    self._address = Ip4Address(
                        int(network[0]) & int(network[1])
                    )
                    return

        if isinstance(network, str):
            try:
                address, mask = network.split("/")
                bit_count = int(mask)
                self._mask = Ip4Mask(
                    int("1" * bit_count + "0" * (32 - bit_count), 2)
                )
                self._address = Ip4Address(
                    int(Ip4Address(address)) & int(self._mask)
                )
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        if isinstance(network, Ip4Network):
            self._mask = network.mask
            self._address = Ip4Address(int(network.address) & int(network.mask))
            return

        raise Ip4NetworkFormatError(network)

    @property
    def address(self) -> Ip4Address:
        """
        Getter for the '_address' attribute.
        """
        return self._address

    @property
    def mask(self) -> Ip4Mask:
        """
        Getter for the '_mask' attribute.
        """
        return self._mask

    @property
    def last(self) -> Ip4Address:
        """
        Last address in the network.
        """
        return Ip4Address(int(self._address) + (~int(self._mask) & 0xFFFFFFFF))

    @property
    def broadcast(self) -> Ip4Address:
        """
        Broadcast address (same as last address in the network).
        """
        return self.last


class Ip4Host(IpHost):
    """
    IPv4 host support class.
    """

    def __init__(
        self,
        host: (
            Ip4Host
            | tuple[Ip4Address, Ip4Network]
            | tuple[Ip4Address, Ip4Mask]
            | str
        ),
    ) -> None:
        """
        Class constructor.
        """

        self._address: Ip4Address
        self._network: Ip4Network
        self._version: int = 4

        self._gateway: Ip4Address | None = None

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Network
                ):
                    self._address = host[0]
                    self._network = host[1]
                    return
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Mask
                ):
                    self._address = host[0]
                    self._network = Ip4Network((host[0], host[1]))
                    return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip4Address(address)
                self._network = Ip4Network(host)
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        if isinstance(host, Ip4Host):
            self._address = host.address
            self._network = host.network
            return

        raise Ip4HostFormatError(host)

    @property
    def address(self) -> Ip4Address:
        """
        Getter for the '_address' attribute.
        """
        return self._address

    @property
    def network(self) -> Ip4Network:
        """
        Getter for the '_network' attribute.
        """
        return self._network

    @property
    def gateway(self) -> Ip4Address | None:
        """
        Getter for the '_gateway' attribute.
        """
        return self._gateway

    @gateway.setter
    def gateway(
        self,
        address: Ip4Address | None,
    ) -> None:
        """
        Setter for the '_gateway' attribute.
        """

        if address is not None and (
            address not in self.network
            or address == self._network.address
            or address == self._network.broadcast
            or address == self._address
        ):
            raise Ip4HostGatewayError(address)

        self._gateway = address
