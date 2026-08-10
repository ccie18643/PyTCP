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
This module contains IP network base class.

net_addr/ip_network.py

ver 3.0.10
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, ClassVar, Self, overload, override

from net_addr.base import Base
from net_addr.errors import IpNetworkSanityError, NetAddrError
from net_addr.ip import Ip
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_wildcard import Ip6Wildcard

if TYPE_CHECKING:
    from net_addr.ip4_network import Ip4Network
    from net_addr.ip6_network import Ip6Network


class IpNetwork[A: (Ip6Address, Ip4Address), M: (Ip6Mask, Ip4Mask)](Base, Ip, ABC):
    """
    IP network support base class.
    """

    __slots__ = (
        "_address",
        "_mask",
    )

    _address: A
    _mask: M

    # The concrete network type's free-message sanity error
    # (net_addr raises only NetAddrError subclasses). Concrete
    # subclasses override with the version-specific Sanity
    # error; the default is a NetAddrError-subclass safety net
    # so a subclass that omits the override still honours the
    # §7.1 contract rather than raising AttributeError.
    _sanity_error: ClassVar[type[NetAddrError]] = IpNetworkSanityError

    @abstractmethod
    def __init__(
        self,
        network: Self | tuple[A, M] | str | None = None,
        /,
        *,
        # Deliberate deviation from net_addr.md §4.2 (no kwargs on a
        # value-type __init__): the keyword-only 'strict' flag is
        # part of the network contract. Declared on the abstract
        # base so code typed against 'IpNetwork' can pass it and the
        # concrete Ip4Network / Ip6Network signatures do not diverge
        # from the base. Default False preserves the silent
        # mask-on-construct behaviour the rest of the stack relies
        # on.
        strict: bool = False,
    ) -> None:
        """
        Initialize the IP network object. Concrete subclasses
        bind the version-specific address / mask types and the
        accepted input forms. Pass strict=True to reject an
        address carrying bits outside the network mask.
        """

        raise NotImplementedError

    @staticmethod
    def _summarize_ints(lo: int, hi: int, bits: int, /) -> Iterator[tuple[int, int]]:
        """
        Iterate over '(network_int, prefixlen)' pairs that
        minimally tile the inclusive integer range [lo, hi] with
        aligned CIDR blocks (RFC 4632 greedy summarization).
        """

        while lo <= hi:
            align = bits if lo == 0 else (lo & -lo).bit_length() - 1
            span = (hi - lo + 1).bit_length() - 1
            step = min(align, span)
            yield lo, bits - step
            lo += 1 << step

    @staticmethod
    def _merge_spans(spans: list[tuple[int, int]], /) -> list[tuple[int, int]]:
        """
        Merge a list of inclusive integer intervals, combining
        overlapping and exactly-adjacent intervals; gaps are
        preserved.
        """

        merged: list[tuple[int, int]] = []
        for lo, hi in sorted(spans):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        return merged

    @overload
    @staticmethod
    def summarize(items: Iterable[Ip4Address | Ip4Network], /) -> "Iterator[Ip4Network]": ...

    @overload
    @staticmethod
    def summarize(items: Iterable[Ip6Address | Ip6Network], /) -> "Iterator[Ip6Network]": ...

    @staticmethod
    def summarize(
        items: "Iterable[Ip4Address | Ip6Address | Ip4Network | Ip6Network]",
        /,
    ) -> "Iterator[Ip4Network | Ip6Network]":
        """
        Iterate over the minimal set of CIDR networks that
        exactly covers the union of the given addresses and
        networks — overlapping and adjacent entries aggregated,
        gaps preserved. All items must be the same IP version
        (a mixed-version or non-address/network item raises
        IpNetworkSanityError); an empty input yields nothing.
        """

        from net_addr.ip4_network import Ip4Network
        from net_addr.ip6_network import Ip6Network

        spans4: list[tuple[int, int]] = []
        spans6: list[tuple[int, int]] = []

        for item in items:
            if isinstance(item, Ip4Address):
                spans4.append((int(item), int(item)))
            elif isinstance(item, Ip6Address):
                spans6.append((int(item), int(item)))
            elif isinstance(item, Ip4Network):
                spans4.append((int(item.address), int(item.last)))
            elif isinstance(item, Ip6Network):
                spans6.append((int(item.address), int(item.last)))
            else:
                raise IpNetworkSanityError(f"summarize() requires IP addresses or networks; got {item!r}")

        if spans4 and spans6:
            raise IpNetworkSanityError("summarize() requires a single IP version; got a mix of IPv4 and IPv6")

        for lo, hi in IpNetwork._merge_spans(spans4):
            for network_int, prefixlen in IpNetwork._summarize_ints(lo, hi, 32):
                yield Ip4Network((Ip4Address(network_int), Ip4Mask(f"/{prefixlen}")))

        for lo, hi in IpNetwork._merge_spans(spans6):
            for network_int, prefixlen in IpNetwork._summarize_ints(lo, hi, 128):
                yield Ip6Network((Ip6Address(network_int), Ip6Mask(f"/{prefixlen}")))

    @override
    def __str__(self) -> str:
        """
        Get the IP network log string.
        """

        return f"{self._address}/{len(self._mask)}"

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare IP network with another object.
        """

        return other is self or (
            isinstance(other, type(self)) and self._address == other._address and self._mask == other._mask
        )

    @override
    def __hash__(self) -> int:
        """
        Get the IP network hash value.
        """

        return hash((type(self), self._address, self._mask))

    def __lt__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) < (int(other._address), int(other._mask))

    def __le__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) <= (int(other._address), int(other._mask))

    def __gt__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) > (int(other._address), int(other._mask))

    def __ge__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) >= (int(other._address), int(other._mask))

    def __contains__(self, other: object, /) -> bool:
        """
        Check if the IP network contains the IP address or host.
        """

        from net_addr.ip4_ifaddr import Ip4IfAddr
        from net_addr.ip6_ifaddr import Ip6IfAddr

        if isinstance(other, (Ip6Address, Ip4Address)):
            return self.version == other.version and int(self.address) <= int(other) <= int(self.last)

        if isinstance(other, (Ip4IfAddr, Ip6IfAddr)):
            return self.version == other.version and int(self.address) <= int(other.address) <= int(self.last)

        return False

    @property
    def address(self) -> A:
        """
        Get the IP network address.
        """

        return self._address

    @property
    def mask(self) -> M:
        """
        Get the IP network mask.
        """

        return self._mask

    @property
    def prefixlen(self) -> int:
        """
        Get the IP network prefix length.
        """

        return len(self._mask)

    @property
    @abstractmethod
    def last(self) -> A:
        """
        Get the IP network last address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def hostmask(self) -> Ip4Wildcard | Ip6Wildcard:
        """
        Get the network wildcard (inverted netmask) — the
        contiguous special case of an ACL/firewall wildcard.
        """

        raise NotImplementedError

    @override
    def __format__(self, format_spec: str, /) -> str:
        """
        Render the network. An empty spec or 'pl' yields the
        canonical 'address/prefixlen' form; 'nm' yields
        'address/netmask'; 'hm' yields 'address/hostmask'
        (wildcard). A trailing-'s' spec applies str-style
        width / alignment.
        """

        match format_spec:
            case "" | "pl":
                return str(self)
            case "nm":
                return f"{self._address}/{type(self._address)(int(self._mask))}"
            case "hm":
                return f"{self._address}/{self.hostmask}"

        if format_spec[-1:] == "s":
            return format(str(self), format_spec)

        raise type(self)._sanity_error(
            f"Unknown format code {format_spec!r} for object of type {type(self).__name__!r}"
        )

    @property
    def max_prefixlen(self) -> int:
        """
        Get the address-family width in bits (32 for IPv4,
        128 for IPv6).
        """

        return self._address.max_prefixlen

    @property
    def num_addresses(self) -> int:
        """
        Get the total number of addresses in the network,
        network and broadcast inclusive.
        """

        return int(self.last) - int(self._address) + 1

    def __iter__(self) -> Iterator[A]:
        """
        Iterate over every address in the network, network and
        broadcast inclusive.
        """

        address_type = type(self._address)
        for value in range(int(self._address), int(self.last) + 1):
            yield address_type(value)

    def __getitem__(self, index: int, /) -> A:
        """
        Get the address at the given index within the network.
        A negative index counts back from the last address; an
        out-of-range index raises the network's sanity error.
        Slicing is not supported.
        """

        count = self.num_addresses

        if index < 0:
            index += count

        if not 0 <= index < count:
            raise type(self)._sanity_error(f"network index out of range: {index}")

        return type(self._address)(int(self._address) + index)

    @abstractmethod
    def hosts(self) -> Iterator[A]:
        """
        Iterate over the usable host addresses in the network.
        """

        raise NotImplementedError

    def subnets(self, *, prefixlen_diff: int = 1, new_prefix: int | None = None) -> Iterator[Self]:
        """
        Iterate over the subnets that tile this network at a
        longer prefix length.
        """

        prefixlen = len(self._mask)

        if prefixlen == self.max_prefixlen:
            yield self
            return

        if new_prefix is not None:
            if new_prefix <= prefixlen:
                raise type(self)._sanity_error(f"new prefix must be longer than {prefixlen}; got {new_prefix}")
            prefixlen_diff = new_prefix - prefixlen
        else:
            if prefixlen_diff < 1:
                raise type(self)._sanity_error(f"prefixlen_diff must be a positive integer; got {prefixlen_diff}")
            new_prefix = prefixlen + prefixlen_diff

        if new_prefix > self.max_prefixlen:
            raise type(self)._sanity_error(
                f"resulting prefix /{new_prefix} exceeds the maximum /{self.max_prefixlen} "
                f"for a /{prefixlen} network"
            )

        network_type = type(self)
        address_type = type(self._address)
        mask = type(self._mask)(self._mask_int(new_prefix))
        step = 1 << (self.max_prefixlen - new_prefix)
        for start in range(int(self._address), int(self.last) + 1, step):
            yield network_type((address_type(start), mask))

    def supernet(self, *, prefixlen_diff: int = 1, new_prefix: int | None = None) -> Self:
        """
        Get the supernet containing this network at a shorter
        prefix length.
        """

        prefixlen = len(self._mask)

        # The /0 default route has no shorter-prefix container;
        # return it unchanged regardless of the arguments (stdlib
        # ipaddress parity, symmetric with the subnets() boundary
        # short-circuit at max_prefixlen).
        if prefixlen == 0:
            return self

        if new_prefix is not None:
            if new_prefix >= prefixlen:
                raise type(self)._sanity_error(f"new prefix must be shorter than {prefixlen}; got {new_prefix}")
        else:
            if prefixlen_diff < 1:
                raise type(self)._sanity_error(f"prefixlen_diff must be a positive integer; got {prefixlen_diff}")
            new_prefix = prefixlen - prefixlen_diff

        if new_prefix < 0:
            raise type(self)._sanity_error(
                f"resulting prefix /{new_prefix} is shorter than the minimum /0 " f"for a /{prefixlen} network"
            )

        return type(self)((type(self._address)(int(self._address)), type(self._mask)(self._mask_int(new_prefix))))

    def address_exclude(self, other: Self, /) -> Iterator[Self]:
        """
        Iterate over the minimal set of aggregate networks
        covering this network with 'other' removed. 'other'
        must be fully contained in this network (else the
        network's sanity error); an equal operand yields
        nothing.
        """

        if not other.subnet_of(self):
            raise type(self)._sanity_error(f"{other} is not contained in {self}")

        if other == self:
            return

        def _halve(network: Self, /) -> tuple[Self, Self]:
            # 'other' is strictly contained in every network
            # passed here, so it is never a single-address
            # (max-prefix) network and subnets() always yields
            # exactly two halves. Convert the structurally
            # unreachable one-element case into the network's
            # sanity error rather than letting the tuple unpack
            # raise a bare ValueError (net_addr.md §7.1).
            halves = list(network.subnets())
            if len(halves) != 2:
                raise type(self)._sanity_error(f"{other} is not contained in {self}")
            return halves[0], halves[1]

        s1, s2 = _halve(self)

        while s1 != other and s2 != other:
            if other.subnet_of(s1):
                yield s2
                s1, s2 = _halve(s1)
            elif other.subnet_of(s2):
                yield s1
                s1, s2 = _halve(s2)
            else:
                raise type(self)._sanity_error(f"{other} is not contained in {self}")

        if s1 == other:
            yield s2
        elif s2 == other:
            yield s1

    def overlaps(self, other: object, /) -> bool:
        """
        Check whether this network shares any address with
        another network. A non-network or cross-version operand
        compares as non-overlapping.
        """

        return (
            isinstance(other, IpNetwork)
            and self.version == other.version
            and int(self._address) <= int(other.last)
            and int(other.address) <= int(self.last)
        )

    def subnet_of(self, other: object, /) -> bool:
        """
        Check whether this network is fully contained within
        another network. A non-network or cross-version operand
        compares as not-contained.
        """

        return (
            isinstance(other, IpNetwork)
            and self.version == other.version
            and int(other.address) <= int(self._address)
            and int(self.last) <= int(other.last)
        )

    def supernet_of(self, other: object, /) -> bool:
        """
        Check whether this network fully contains another
        network. A non-network or cross-version operand
        compares as not-contained.
        """

        return isinstance(other, IpNetwork) and other.subnet_of(self)

    def _mask_int(self, prefixlen: int, /) -> int:
        """
        Build the integer mask value for a given prefix length.
        """

        if prefixlen == 0:
            return 0
        return ((1 << prefixlen) - 1) << (self.max_prefixlen - prefixlen)
