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
# lib/ip6_address.py - module contains IPv6 address manipulation classes
#

from __future__ import annotations  # Required for Python version lower than 3.10

import re
import socket
import struct
from typing import Optional, Union

from lib.mac_address import MacAddress

IP6_REGEX = (
    r"("
    + r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"  # 1:2:3:4:5:6:7:8
    + r"([0-9a-fA-F]{1,4}:){1,7}:|"  # 1::, 1:2:3:4:5:6:7::
    + r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"  # 1::8, 1:2:3:4:5:6::8
    + r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"  # 1::7:8, 1:2:3:4:5::7:8, 1:2:3:4:5::8
    + r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"  # 1::6:7:8, 1:2:3:4::6:7:8, 1:2:3:4::8
    + r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"  # 1::5:6:7:8, 1:2:3::5:6:7:8, 1:2:3::8
    + r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"  # 1::4:5:6:7:8, 1:2::4:5:6:7:8, 1:2::8
    + r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"  # 1::3:4:5:6:7:8, 1::3:4:5:6:7:8, 1::8
    + r":((:[0-9a-fA-F]{1,4}){1,7}|:)"  # ::2:3:4:5:6:7:8, ::2:3:4:5:6:7:8, ::8, ::
    + r")"
)


class Ip6AddressFormatError(Exception):
    pass


class Ip6MaskFormatError(Exception):
    pass


class Ip6NetworkFormatError(Exception):
    pass


class Ip6HostFormatError(Exception):
    pass


class Ip6Address:
    """IPv6 address support class"""

    def __init__(self, address: Union[Ip6Address, str, bytes, bytearray, memoryview, int]) -> None:
        """Class constructor"""

        if isinstance(address, Ip6Address):
            self._address = int(address)
            return

        if isinstance(address, str):
            if re.search(IP6_REGEX, address):
                try:
                    v1, v2, v3, v4 = struct.unpack("!LLLL", socket.inet_pton(socket.AF_INET6, address))
                    self._address = (v1 << 96) + (v2 << 64) + (v3 << 32) + v4
                    return
                except OSError:
                    pass

        if isinstance(address, bytes) or isinstance(address, bytearray) or isinstance(address, memoryview):
            if len(address) == 16:
                v1, v2, v3, v4 = struct.unpack("!LLLL", address)
                self._address = (v1 << 96) + (v2 << 64) + (v3 << 32) + v4
                return

        if isinstance(address, int):
            if address in range(340282366920938463463374607431768211455):
                self._address = address
                return

        raise Ip6AddressFormatError(address)

    def __str__(self) -> str:
        """String representation"""

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip6Address('{str(self)}')"

    def __bytes__(self) -> bytes:
        """Bytes representation"""

        return struct.pack(
            "!LLLL", (self._address >> 96) & 0xFFFFFFFF, (self._address >> 64) & 0xFFFFFFFF, (self._address >> 32) & 0xFFFFFFFF, self._address & 0xFFFFFFFF
        )

    def __int__(self) -> int:
        """Integer representation"""

        return self._address

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip6Address) and self._address == int(other)

    def __hash__(self) -> int:
        """Hash"""

        return hash(bytes(self))

    @property
    def version(self) -> int:
        """IP address version"""

        return 6

    @property
    def is_unspecified(self) -> bool:
        """Check if IPv6 address is a unspecified"""

        return self._address == 0  # ::/128

    @property
    def is_loopback(self) -> bool:
        """Check if IPv6 address is loopback"""

        return self._address == 1  # ::1/128

    @property
    def is_global(self) -> bool:
        """Check if IPv6 address is global"""

        return self._address in range(42535295865117307932921825928971026432, 85070591730234615865843651857942052864)  # 2000::/3

    @property
    def is_private(self) -> bool:
        """Check if IPv6 address is private"""

        return self._address in range(334965454937798799971759379190646833152, 337623910929368631717566993311207522304)  # fc00::/7

    @property
    def is_link_local(self) -> bool:
        """Check if IPv6 address is link local"""

        return self._address in range(338288524927261089654018896841347694592, 338620831926207318622244848606417780736)  # fe80::/10

    @property
    def is_multicast(self) -> bool:
        """Check if IPv6 address is multicast"""

        return self._address in range(338953138925153547590470800371487866880, 340282366920938463463374607431768211456)  # ff00::/8

    @property
    def is_solicited_node_multicast(self) -> bool:
        """Check if address is IPv6 solicited node multicast address"""

        return self._address in range(338963523518870617245727861372719464448, 338963523518870617245727861372736241664)  # ff02::1:ff00:0/104

    @property
    def is_unicast(self) -> bool:
        """Check if address is IPv6 unicast address"""

        return self.is_global or self.is_private or self.is_link_local or self.is_loopback

    @property
    def solicited_node_multicast(self) -> Ip6Address:
        """Create IPv6 solicited node multicast address"""

        return Ip6Address(self._address & 0xFFFFFF | int(Ip6Address("ff02::1:ff00:0")))

    @property
    def multicast_mac(self) -> MacAddress:
        """Create IPv6 multicast MAC address"""

        assert self.is_multicast

        return MacAddress(int(MacAddress("33:33:00:00:00:00")) | self._address & 0xFFFFFFFF)


class Ip6Mask:
    """IPv6 network mask support class"""

    def __init__(self, mask: Union[Ip6Mask, str, bytes, bytearray, memoryview, int]) -> None:
        """Class constructor"""

        def _validate_bits() -> bool:
            """Validate that mask is made of consecutive bits"""
            bit_mask = f"{self._mask:0128b}"
            return not bit_mask[bit_mask.index("0") :].count("1")

        if isinstance(mask, Ip6Mask):
            self._mask: int = mask._mask
            return

        if isinstance(mask, str) and re.search(r"^\/\d{1,3}$", mask):
            bit_count = int(mask[1:])
            if bit_count in range(129):
                self._mask = int("1" * bit_count + "0" * (128 - bit_count), 2)
                return

        if isinstance(mask, bytes) or isinstance(mask, bytearray) or isinstance(mask, memoryview):
            if len(mask) == 16:
                v1, v2, v3, v4 = struct.unpack("!LLLL", mask)
                self._mask = (v1 << 96) + (v2 << 64) + (v3 << 32) + v4
                if _validate_bits():
                    return

        if isinstance(mask, int):
            if mask in range(340282366920938463463374607431768211456):
                self._mask = mask
                if _validate_bits():
                    return

        raise Ip6MaskFormatError(mask)

    def __str__(self) -> str:
        """String representation"""

        return f"/{len(self)}"

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip6Mask('{str(self)}')"

    def __bytes__(self) -> bytes:
        """Bytes representation"""

        return struct.pack("!LLLL", (self._mask >> 96) & 0xFFFFFFFF, (self._mask >> 64) & 0xFFFFFFFF, (self._mask >> 32) & 0xFFFFFFFF, self._mask & 0xFFFFFFFF)

    def __int__(self) -> int:
        """Integer representation"""

        return self._mask

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip6Mask) and self._mask == other._mask

    def __hash__(self) -> int:
        """Hash"""

        return hash(bytes(self))

    def __len__(self) -> int:
        """Bit length representation"""

        return f"{self._mask:b}".count("1")

    @property
    def version(self) -> int:
        """IP mask version"""

        return 6


class Ip6Network:
    """IPv6 network support class"""

    def __init__(self, network: Union[Ip6Network, tuple[Ip6Address, Ip6Mask], str]) -> None:
        """Class constructor"""

        if isinstance(network, Ip6Network):
            self._mask = network.mask
            self._address = Ip6Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            if len(network) == 2:
                if isinstance(network[0], Ip6Address) and isinstance(network[1], Ip6Mask):
                    self._mask = network[1]
                    self._address = Ip6Address(int(network[0]) & int(network[1]))
                    return

        if isinstance(network, str):
            try:
                address, mask = network.split("/")
                self._mask = Ip6Mask("/" + mask)
                self._address = Ip6Address(int(Ip6Address(address)) & int(self._mask))
                return
            except (ValueError, Ip6AddressFormatError, Ip6MaskFormatError):
                pass

        raise Ip6NetworkFormatError(network)

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + "/" + str(len(self._mask))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip6Network('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip6Network) and self._address == other.address and self._mask == other.mask

    def __hash__(self) -> int:
        """Hash"""

        return hash(self._address) ^ hash(self._mask)

    def __iter__(self):
        """Iterator"""

        for address in range(int(self.address), int(self.last) + 1):
            yield Ip6Address(address)

    def __contains__(self, other: object) -> bool:
        """Contains for 'in' operator"""

        if isinstance(other, Ip6Address):
            return int(self.address) <= int(other) <= int(self.last)

        if isinstance(other, Ip6Host):
            return int(self.address) <= int(other.address) <= int(self.last)

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
    def last(self):
        """Last address"""

        return Ip6Address(int(self._address) + (~int(self._mask) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))

    def eui64(self, mac_address: MacAddress) -> Ip6Host:
        """Create IPv6 EUI64 interface address"""

        assert len(self.mask) == 64

        interface_id = (((int(mac_address) & 0xFFFFFF000000) << 16) | int(mac_address) & 0xFFFFFF | 0xFFFE000000) ^ 0x0200000000000000
        return Ip6Host((Ip6Address(int(self._address) | interface_id), Ip6Mask("/64")))

    @property
    def version(self) -> int:
        """IP network version"""

        return 6


class Ip6Host:
    """IPv6 host support class"""

    def __init__(self, host: Union[Ip6Host, tuple[Ip6Address, Ip6Network], tuple[Ip6Address, Ip6Mask], str]) -> None:
        """Class constructor"""

        self.gateway: Optional[Ip6Address] = None

        if isinstance(host, Ip6Host):
            self._address = host.address
            self._network = host.network
            return

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip6Address) and isinstance(host[1], Ip6Network):
                    self._address = host[0]
                    self._network = host[1]
                    return
                if isinstance(host[0], Ip6Address) and isinstance(host[1], Ip6Mask):
                    self._address = host[0]
                    self._network = Ip6Network(host)
                    return

        if isinstance(host, str):
            try:
                address, mask = host.split("/")
                self._address = Ip6Address(address)
                self._network = Ip6Network(host)
                return
            except (ValueError, Ip6AddressFormatError, Ip6MaskFormatError):
                pass

        raise Ip6HostFormatError(host)

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + "/" + str(len(self._network.mask))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip6Host('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return isinstance(other, Ip6Host) and self._address == other._address and self._network == other._network

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

        return 6
