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
Module contains IPv6 address manipulation classes.

pytcp/lib/ip6_address.py

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

IP6_REGEX = (
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:))"
)


class Ip6AddressFormatError(IpAddressFormatError):
    pass


class Ip6MaskFormatError(IpMaskFormatError):
    pass


class Ip6NetworkFormatError(IpNetworkFormatError):
    pass


class Ip6HostFormatError(IpHostFormatError):
    pass


class Ip6HostGatewayError(IpHostGatewayError):
    pass


class Ip6Address(IpAddress):
    """
    IPv6 address support class.
    """

    def __init__(
        self, address: Ip6Address | str | bytes | bytearray | memoryview | int
    ) -> None:
        """
        Class constructor.
        """

        self._address: int
        self._version: int = 6

        if isinstance(address, int):
            if address & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF == address:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 16:
                v_1, v_2, v_3, v_4 = struct.unpack("!LLLL", address)
                self._address = (v_1 << 96) + (v_2 << 64) + (v_3 << 32) + v_4
                return

        if isinstance(address, str):
            if re.search(IP6_REGEX, address):
                try:
                    v_1, v_2, v_3, v_4 = struct.unpack(
                        "!LLLL", socket.inet_pton(socket.AF_INET6, address)
                    )
                    self._address = (
                        (v_1 << 96) + (v_2 << 64) + (v_3 << 32) + v_4
                    )
                    return
                except OSError:
                    pass

        if isinstance(address, Ip6Address):
            self._address = int(address)
            return

        raise Ip6AddressFormatError(address)

    def __str__(self) -> str:
        """String representation"""

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    def __bytes__(self) -> bytes:
        """Bytes representation"""

        return struct.pack(
            "!LLLL",
            (self._address >> 96) & 0xFFFFFFFF,
            (self._address >> 64) & 0xFFFFFFFF,
            (self._address >> 32) & 0xFFFFFFFF,
            self._address & 0xFFFFFFFF,
        )

    @property
    def is_loopback(self) -> bool:
        """
        Check if IPv6 address is loopback.
        """
        return self._address == 1  # ::1/128

    @property
    def is_global(self) -> bool:
        """
        Check if IPv6 address is global.
        """
        return (
            self._address & 0xE000_0000_0000_0000_0000_0000_0000_0000
            == 0x2000_0000_0000_0000_0000_0000_0000_0000
        )  # 2000::/3

    @property
    def is_private(self) -> bool:
        """
        Check if IPv6 address is private.
        """
        return (
            self._address & 0xFE00_0000_0000_0000_0000_0000_0000_0000
            == 0xFC00_0000_0000_0000_0000_0000_0000_0000
        )  # fc00::/7

    @property
    def is_link_local(self) -> bool:
        """
        Check if IPv6 address is link local.
        """
        return (
            self._address & 0xFFC0_0000_0000_0000_0000_0000_0000_0000
            == 0xFE80_0000_0000_0000_0000_0000_0000_0000
        )  # fe80::/10

    @property
    def is_multicast(self) -> bool:
        """
        Check if IPv6 address is multicast.
        """
        return (
            self._address & 0xFF00_0000_0000_0000_0000_0000_0000_0000
            == 0xFF00_0000_0000_0000_0000_0000_0000_0000
        )  # ff00::/8

    @property
    def is_solicited_node_multicast(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast address.
        """
        return (
            self._address & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_0000
            == 0xFF02_0000_0000_0000_0000_0001_FF00_0000
        )  # ff02::1:ff00:0/104

    @property
    def solicited_node_multicast(self) -> Ip6Address:
        """
        Create IPv6 solicited node multicast address.
        """
        return Ip6Address(
            self._address & 0xFFFFFF | int(Ip6Address("ff02::1:ff00:0"))
        )

    @property
    def multicast_mac(self) -> MacAddress:
        """
        Create IPv6 multicast MAC address.
        """
        assert self.is_multicast
        return MacAddress(
            int(MacAddress(0x333300000000)) | self._address & 0xFFFFFFFF
        )

    @property
    def unspecified(self) -> Ip6Address:
        """
        Return unspecified IPv6 Address.
        """
        return Ip6Address(0)


class Ip6Mask(IpMask):
    """
    IPv6 network mask support class.
    """

    def __init__(
        self, mask: Ip6Mask | str | bytes | bytearray | memoryview | int
    ) -> None:
        """
        Class constructor.
        """

        self._mask: int
        self._version: int = 6

        def _validate_bits() -> bool:
            """
            Validate that mask is made of consecutive bits.
            """
            bit_mask = f"{self._mask:0128b}"
            try:
                return not bit_mask[bit_mask.index("0") :].count("1")
            except ValueError:
                return True

        if isinstance(mask, int):
            if mask & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF == mask:
                self._mask = mask
                if _validate_bits():
                    return

        if isinstance(mask, (memoryview, bytes, bytearray)):
            if len(mask) == 16:
                v_1, v_2, v_3, v_4 = struct.unpack("!LLLL", mask)
                self._mask = (v_1 << 96) + (v_2 << 64) + (v_3 << 32) + v_4
                if _validate_bits():
                    return

        if isinstance(mask, str) and re.search(r"^\/\d{1,3}$", mask):
            bit_count = int(mask[1:])
            if bit_count in range(129):
                self._mask = int("1" * bit_count + "0" * (128 - bit_count), 2)
                return

        if isinstance(mask, Ip6Mask):
            self._mask = mask._mask
            return

        raise Ip6MaskFormatError(mask)

    def __bytes__(self) -> bytes:
        """
        The '__bytes__()' dunder.
        """
        return struct.pack(
            "!LLLL",
            (self._mask >> 96) & 0xFFFFFFFF,
            (self._mask >> 64) & 0xFFFFFFFF,
            (self._mask >> 32) & 0xFFFFFFFF,
            self._mask & 0xFFFFFFFF,
        )


class Ip6Network(IpNetwork):
    """
    IPv6 network support class.
    """

    def __init__(
        self, network: Ip6Network | tuple[Ip6Address, Ip6Mask] | str
    ) -> None:
        """
        Class constructor.
        """

        self._address: Ip6Address
        self._mask: Ip6Mask
        self._version: int = 6

        if isinstance(network, tuple):
            if len(network) == 2:
                if isinstance(network[0], Ip6Address) and isinstance(
                    network[1], Ip6Mask
                ):
                    self._mask = network[1]
                    self._address = Ip6Address(
                        int(network[0]) & int(network[1])
                    )
                    return

        if isinstance(network, str):
            try:
                address, mask = network.split("/")
                self._mask = Ip6Mask("/" + mask)
                self._address = Ip6Address(
                    int(Ip6Address(address)) & int(self._mask)
                )
                return
            except (ValueError, Ip6AddressFormatError, Ip6MaskFormatError):
                pass

        if isinstance(network, Ip6Network):
            self._mask = network.mask
            self._address = Ip6Address(int(network.address) & int(network.mask))
            return

        raise Ip6NetworkFormatError(network)

    @property
    def address(self) -> Ip6Address:
        """
        Getter for the '_address' attribute.
        """
        return self._address

    @property
    def mask(self) -> Ip6Mask:
        """
        Getter for the '_mask' attribute.
        """
        return self._mask

    @property
    def last(self) -> Ip6Address:
        """
        Last address in the network.
        """
        return Ip6Address(
            int(self._address)
            + (~int(self._mask) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        )

    def eui64(self, mac_address: MacAddress) -> Ip6Host:
        """
        Create IPv6 EUI64 interface address.
        """
        assert len(self.mask) == 64
        interface_id = (
            ((int(mac_address) & 0xFFFFFF000000) << 16)
            | int(mac_address) & 0xFFFFFF
            | 0xFFFE000000
        ) ^ 0x0200000000000000
        return Ip6Host(
            (Ip6Address(int(self._address) | interface_id), Ip6Mask("/64"))
        )


class Ip6Host(IpHost):
    """
    IPv6 host support class.
    """

    def __init__(
        self,
        host: (
            Ip6Host
            | tuple[Ip6Address, Ip6Network]
            | tuple[Ip6Address, Ip6Mask]
            | str
        ),
    ) -> None:
        """
        Class constructor.
        """

        self._address: Ip6Address
        self._network: Ip6Network
        self._version: int = 6
        self._gateway: Ip6Address | None = None

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip6Address) and isinstance(
                    host[1], Ip6Network
                ):
                    self._address = host[0]
                    self._network = host[1]
                    return
                if isinstance(host[0], Ip6Address) and isinstance(
                    host[1], Ip6Mask
                ):
                    self._address = host[0]
                    self._network = Ip6Network((host[0], host[1]))
                    return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip6Address(address)
                self._network = Ip6Network(host)
                return
            except (ValueError, Ip6AddressFormatError, Ip6MaskFormatError):
                pass

        if isinstance(host, Ip6Host):
            self._address = host.address
            self._network = host.network
            return

        raise Ip6HostFormatError(host)

    @property
    def address(self) -> Ip6Address:
        """
        Getter for the '_address' attribute.
        """
        return self._address

    @property
    def network(self) -> Ip6Network:
        """
        Getter for the '_network' attribute.
        """
        return self._network

    @property
    def gateway(self) -> Ip6Address | None:
        """
        Getter for the '_gateway' attribute.
        """
        return self._gateway

    @gateway.setter
    def gateway(
        self,
        address: Ip6Address | None,
    ) -> None:
        """
        Setter for the '_gateway' attribute.
        """

        if address is not None and address not in Ip6Network("fe80::/10"):
            raise Ip6HostGatewayError(address)

        self._gateway = address
