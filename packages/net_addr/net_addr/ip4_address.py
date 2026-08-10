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
This module contains IPv4 address support class.

net_addr/ip4_address.py

ver 3.0.10
"""

import socket
from typing import ClassVar, Self, final, override

from net_addr.buffer import Buffer
from net_addr.errors import Ip4AddressFormatError, Ip4AddressSanityError, NetAddrError
from net_addr.ip_address import IpAddress
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MAC__IP4_MULTICAST_PREFIX, MacAddress

IP4__ADDRESS_LEN = 4
IP4__MASK = 0xFF_FF_FF_FF


@final
class Ip4Address(IpAddress):
    """
    IPv4 address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    _address_len: ClassVar[int] = IP4__ADDRESS_LEN

    _sanity_error: ClassVar[type[NetAddrError]] = Ip4AddressSanityError

    def __init__(
        self,
        address: Self | str | Buffer | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, Ip4Address):
            self._address = int(address)
            return

        if isinstance(address, int):
            if 0 <= address <= IP4__MASK:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 4:
                self._address = int.from_bytes(address)
                return

        if isinstance(address, str):
            # Surrounding whitespace is stripped uniformly across
            # every net_addr string constructor. 'socket.inet_pton'
            # is the strict POSIX parser: it accepts only canonical
            # four-octet dotted-decimal and rejects the legacy
            # 'socket.inet_aton' leniencies (octal / hex octets,
            # leading zeros, fewer than four parts) that would
            # otherwise silently reinterpret the address.
            try:
                self._address = int.from_bytes(socket.inet_pton(socket.AF_INET, address.strip()))
                return
            except OSError:
                pass

        raise Ip4AddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 address log string.
        """

        return socket.inet_ntoa(bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 address as a memoryview.
        """

        return memoryview(bytearray(self._address.to_bytes(IP4__ADDRESS_LEN)))

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Get the IPv4 multicast MAC address.
        """

        if not self.is_multicast:
            raise Ip4AddressSanityError(
                f"The IPv4 address must be a multicast address to get a multicast MAC address. Got: {self}"
            )

        return MacAddress(MAC__IP4_MULTICAST_PREFIX | self._address & 0x7F_FFFF)

    @property
    @override
    def reverse_pointer(self) -> str:
        """
        Get the IPv4 reverse-DNS PTR name (reversed octets in
        the in-addr.arpa zone).
        """

        return ".".join(str(octet) for octet in reversed(bytes(self))) + ".in-addr.arpa"

    @override
    def _format_alt(self, format_spec: str, /) -> str | None:
        """
        Render the 'ex' (expanded) text code. IPv4 has no zero
        compression, so the expanded form is the dotted-decimal
        string. Any other code is not recognised.
        """

        if format_spec == "ex":
            return str(self)

        return None

    # Known deliberate divergence: this is "global unicast" in
    # the addressing-architecture sense, NOT RFC 6890 "Globally
    # Reachable". It does not exclude the IANA Special-Purpose
    # blocks 100.64.0.0/10 (RFC 6598), 192.0.0.0/24 (RFC 6890),
    # 192.0.2.0/24 / 198.51.100.0/24 / 203.0.113.0/24 (RFC 5737
    # TEST-NET) or 198.18.0.0/15 (RFC 2544), so it returns True
    # for them. Tightening to RFC-6890 reachability was verified
    # correct but is intentionally NOT applied: is_global has no
    # PyTCP consumer, so the strict form buys no functional
    # correctness while destabilising unrelated stack tests —
    # same disposition as is_site_local.
    @property
    @override
    def is_global(self) -> bool:
        """
        Check if the IPv4 address is a global address.
        """

        return not (
            self.is_unspecified
            or self.is_invalid
            or self.is_link_local
            or self.is_loopback
            or self.is_multicast
            or self.is_private
            or self.is_reserved
            or self.is_limited_broadcast
        )

    @property
    @override
    def is_link_local(self) -> bool:
        """
        Check if the IPv4 address is a link local address.
        """

        return self._address & 0xFF_FF_00_00 == 0xA9_FE_00_00  # 169.254.0.0 - 169.254.255.255

    @property
    @override
    def is_loopback(self) -> bool:
        """
        Check if the IPv4 address is a loopback address.
        """

        return self._address & 0xFF_00_00_00 == 0x7F_00_00_00  # 127.0.0.0 - 127.255.255.255

    @property
    @override
    def is_multicast(self) -> bool:
        """
        Check if the IPv4 address is a multicast address.
        """

        return self._address & 0xF0_00_00_00 == 0xE0_00_00_00  # 224.0.0.0 - 239.255.255.255

    @property
    @override
    def is_private(self) -> bool:
        """
        Check if the IPv4 address is a private address.
        """

        return (
            self._address & 0xFF_00_00_00 == 0x0A_00_00_00  # 10.0.0.0 - 10.255.255.255
            or self._address & 0xFF_F0_00_00 == 0xAC_10_00_00  # 172.16.0.0 - 172.31.255.255
            or self._address & 0xFF_FF_00_00 == 0xC0_A8_00_00  # 192.168.0.0 - 192.168.255.255
        )

    @property
    def is_reserved(self) -> bool:
        """
        Check if the IPv4 address is a reserved address.
        """

        return (
            self._address & 0xF0_00_00_00 == 0xF0_00_00_00 and self._address != 0xFF_FF_FF_FF
        )  # 240.0.0.0 - 255.255.255.254

    @property
    def is_limited_broadcast(self) -> bool:
        """
        Check if the IPv4 address is a limited broadcast address.
        """

        return self._address == 0xFF_FF_FF_FF  # 255.255.255.255

    @property
    def is_invalid(self) -> bool:
        """
        Check if the IPv4 address is an invalid address.
        """

        return (
            self._address & 0xFF_00_00_00 == 0x00_00_00_00
        ) and self._address != 0x00_00_00_00  # 0.0.0.1 - 0.255.255.255
