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


#
# lib/ip4_address.py - module contains IPv4 address manipulation classes
#

from __future__ import annotations  # Required for Python version lower than 3.10

import re
import socket
import struct
from typing import Optional, Union

IP4_REGEX = r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"


class Ip4AddressFormatError(Exception):
    pass


class Ip4MaskFormatError(Exception):
    pass


class Ip4NetworkFormatError(Exception):
    pass


class Ip4HostFormatError(Exception):
    pass


class Ip4Address:
    """IPv4 address support class"""

    def __init__(self, address: Union[Ip4Address, str, bytes, bytearray, memoryview, int]) -> None:
        """Class constructor"""

        if isinstance(address, Ip4Address):
            self._address = int(address)
            return

        if isinstance(address, str):
            if re.search(IP4_REGEX, address):
                try:
                    self._address = struct.unpack("!L", socket.inet_aton(address))[0]
                    return
                except OSError:
                    pass

        if isinstance(address, bytes) or isinstance(address, bytearray) or isinstance(address, memoryview):
            if len(address) == 4:
                self._address = struct.unpack("!L", address)[0]
                return

        if isinstance(address, int):
            if address in range(4294967296):
                self._address = address
                return

        raise Ip4AddressFormatError(address)

    def __str__(self) -> str:
        """String representation"""

        return socket.inet_ntoa(bytes(self))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip4Address('{str(self)}')"

    def __bytes__(self) -> bytes:
        """Bytes representation"""

        return struct.pack("!L", self._address)

    def __int__(self) -> int:
        """Integer representation"""

        return self._address

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip4Address) and self._address == int(other)

    def __hash__(self) -> int:
        """Hash"""

        return hash(bytes(self))

    @property
    def version(self) -> int:
        """IP address version"""

        return 4

    @property
    def is_global(self) -> bool:
        """Check if IPv4 address is global"""

        return (
            self._address != 0  # 0.0.0.0
            and self._address not in range(1, 16777216)  # 0.0.0.1 - 0.255.255.255
            and self._address not in range(167772160, 184549376)  # 10.0.0.0 - 10.255.255.255
            and self._address not in range(2130706432, 2147483648)  # 127.0.0.0 - 127.255.255.255
            and self._address not in range(2851995648, 2852061184)  # 169.254.0.0 - 169.254.255.255
            and self._address not in range(2886729728, 2887778304)  # 172.16.0.0 - 172.31.255.255
            and self._address not in range(3232235520, 3232301056)  # 192.168.0.0 - 192.168.255.255
            and self._address not in range(3758096384, 4026531840)  # 224.0.0.0 - 239.255.255.255
            and self._address not in range(4026531840, 4294967295)  # 240.0.0.0 - 255.255.255.254
            and self._address != 4294967295  # 255.255.255.255
        )

    @property
    def is_link_local(self) -> bool:
        """Check if IPv4 address is link local"""

        return self._address in range(2851995648, 2852061184)  # 169.254.0.0 - 169.254.255.255

    @property
    def is_loopback(self) -> bool:
        """Check if IPv4 address is loopback"""

        return self._address in range(2130706432, 2147483648)  # 127.0.0.0 - 127.255.255.255

    @property
    def is_multicast(self) -> bool:
        """Check if IPv4 address is multicast"""

        return self._address in range(3758096384, 4026531840)  # 224.0.0.0 - 239.255.255.255

    @property
    def is_private(self) -> bool:
        """Check if IPv4 address is private"""

        return (
            self._address in range(167772160, 184549376)  # 10.0.0.0 - 10.255.255.255
            or self._address in range(2886729728, 2887778304)  # 172.16.0.0 - 172.31.255.255
            or self._address in range(3232235520, 3232301056)  # 192.168.0.0 - 192.168.255.255
        )

    @property
    def is_unspecified(self) -> bool:
        """Check if IPv4 address is a unspecified"""

        return self._address == 0  # 0.0.0.0

    @property
    def is_reserved(self) -> bool:
        """Check if IPv4 address is reserved"""

        return self._address in range(4026531840, 4294967295)  # 240.0.0.0 - 255.255.255.254

    @property
    def is_limited_broadcast(self) -> bool:
        """Check if IPv4 address is a limited broadcast"""

        return self._address == 4294967295


class Ip4Mask:
    """IPv4 network mask support class"""

    def __init__(self, mask: Union[Ip4Mask, str, bytes, bytearray, memoryview, int]) -> None:
        """Class constructor"""

        def _validate_bits() -> bool:
            """Validate that mask is made of consecutive bits"""
            bit_mask = f"{self._mask:032b}"
            return not bit_mask[bit_mask.index("0") :].count("1")

        if isinstance(mask, Ip4Mask):
            self._mask: int = mask._mask
            return

        if isinstance(mask, str) and re.search(IP4_REGEX, mask):
            try:
                self._mask = struct.unpack("!L", socket.inet_aton(mask))[0]
                if _validate_bits():
                    return
            except OSError:
                pass

        if isinstance(mask, str) and re.search(r"^\/\d{1,2}$", mask):
            bit_count = int(mask[1:])
            if bit_count in range(33):
                self._mask = int("1" * bit_count + "0" * (32 - bit_count), 2)
                return

        if isinstance(mask, bytes) or isinstance(mask, bytearray) or isinstance(mask, memoryview):
            if len(mask) == 4:
                self._mask = struct.unpack("!L", mask)[0]
                if _validate_bits():
                    return

        if isinstance(mask, int):
            if mask in range(4294967296):
                self._mask = mask
                if _validate_bits():
                    return

        raise Ip4MaskFormatError(mask)

    def __str__(self) -> str:
        """String representation"""

        return f"/{len(self)}"

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip4Mask('{str(self)}')"

    def __bytes__(self) -> bytes:
        """Bytes representation"""

        return struct.pack("!L", self._mask)

    def __int__(self) -> int:
        """Integer representation"""

        return self._mask

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip4Mask) and self._mask == other._mask

    def __hash__(self) -> int:
        """Hash"""

        return hash(bytes(self))

    def __len__(self) -> int:
        """Bit length representation"""

        return f"{self._mask:b}".count("1")

    @property
    def version(self) -> int:
        """IP mask version"""

        return 4


class Ip4Network:
    """IPv4 network support class"""

    def __init__(self, network: Union[Ip4Network, tuple[Ip4Address, Ip4Mask], str]) -> None:
        """Class constructor"""

        if isinstance(network, Ip4Network):
            self._mask = network.mask
            self._address = Ip4Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            if len(network) == 2:
                if isinstance(network[0], Ip4Address) and isinstance(network[1], Ip4Mask):
                    self._mask = network[1]
                    self._address = Ip4Address(int(network[0]) & int(network[1]))
                    return

        if isinstance(network, str):
            try:
                address, mask = network.split("/")
                self._mask = Ip4Mask("/" + mask)
                self._address = Ip4Address(int(Ip4Address(address)) & int(self._mask))
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        raise Ip4NetworkFormatError(network)

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + str(self._mask)

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip4Network('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip4Network) and self._address == other.address and self._mask == other.mask

    def __hash__(self) -> int:
        """Hash"""

        return hash(self._address) ^ hash(self._mask)

    def __iter__(self):
        """Iterator"""

        for address in range(int(self.address), int(self.broadcast) + 1):
            yield Ip4Address(address)

    def __contains__(self, other: object) -> bool:
        """Contains for 'in' operator"""

        if isinstance(other, Ip4Address):
            return int(self.address) <= int(other) <= int(self.broadcast)

        if isinstance(other, Ip4Host):
            return int(self.address) <= int(other.address) <= int(self.broadcast)

        return False

    @property
    def address(self):
        """Network address"""

        return self._address

    @property
    def mask(self):
        """Network mask"""

        return self._mask

    @property
    def broadcast(self):
        """Broadcast address"""

        return Ip4Address(int(self._address) + (~int(self._mask) & 0xFFFFFFFF))

    @property
    def version(self) -> int:
        """IP network version"""

        return 4


class Ip4Host:
    """IPv4 host support class"""

    def __init__(self, host: Union[Ip4Host, tuple[Ip4Address, Ip4Network], tuple[Ip4Address, Ip4Mask], str]) -> None:
        """Class constructor"""

        self.gateway: Optional[Ip4Address] = None

        if isinstance(host, Ip4Host):
            self._address = host.address
            self._network = host.network
            return

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip4Address) and isinstance(host[1], Ip4Network):
                    self._address = host[0]
                    self._network = host[1]
                    return
                if isinstance(host[0], Ip4Address) and isinstance(host[1], Ip4Mask):
                    self._address = host[0]
                    self._network = Ip4Network(host)
                    return

        if isinstance(host, str):
            try:
                address, mask = host.split("/")
                self._address = Ip4Address(address)
                self._network = Ip4Network(host)
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        raise Ip4HostFormatError(host)

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + "/" + str(len(self._network.mask))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip4Host('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip4Host) and self._address == other._address and self._network == other._network

    def __hash__(self) -> int:
        """Hash"""

        return hash(self._address) ^ hash(self._network)

    @property
    def address(self):
        """Host address"""

        return self._address

    @property
    def network(self):
        """Host network"""

        return self._network

    @property
    def version(self) -> int:
        """IP network version"""

        return 4
