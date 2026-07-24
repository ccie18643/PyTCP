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
This module contains network address base class.

net_addr/address.py

ver 3.0.8
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Self, override

from net_addr.base import Base
from net_addr.buffer import Buffer
from net_addr.errors import IpAddressSanityError, NetAddrError


class Address(Base, ABC):
    """
    Network address support base class.
    """

    __slots__ = ("_address",)

    # The address value packed big-endian into a single integer — the
    # sole per-instance slot. Every concrete leaf's '__init__' parses
    # its accepted input forms (str / bytes / int / Self / None) down to
    # this integer; all arithmetic, comparison, hashing, and wire
    # serialisation read it back out.
    _address: int

    # The concrete value type's free-message sanity error,
    # raised for operation-precondition / invalid-argument
    # failures (net_addr raises only NetAddrError subclasses).
    # Every concrete subclass overrides this with its specific
    # Sanity error; the default is a NetAddrError-subclass
    # safety net so a subclass that omits the override still
    # honours the §7.1 "no bare builtin escapes" contract
    # rather than raising AttributeError.
    _sanity_error: ClassVar[type[NetAddrError]] = IpAddressSanityError

    @abstractmethod
    def __init__(
        self,
        address: Self | str | Buffer | int | None = None,
        /,
    ) -> None:
        """
        Initialize the network address object. Concrete
        subclasses bind the accepted input forms.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def _address_len(self) -> int:
        """
        Get the address-family width in bytes.
        """

        # Each concrete leaf overrides this abstract property with a
        # 'ClassVar[int]' constant, so the hot-path reads
        # ('_with_offset', '__format__', 'max_prefixlen', '_validate')
        # stay a plain class-attribute lookup rather than
        # 'len(memoryview(self))', which would allocate a fresh
        # bytearray + memoryview on every call.
        raise NotImplementedError

    def __int__(self) -> int:
        """
        Get the network address as integer.
        """

        return self._address

    @abstractmethod
    def _format_alt(self, format_spec: str, /) -> str | None:
        """
        Render a type-specific textual format code, or None if
        the code is not recognised by this address type. Every
        concrete leaf implements it (the base declares no default).
        """

        raise NotImplementedError

    @override
    def __format__(self, format_spec: str, /) -> str:
        """
        Format the address. A type-specific text code ('ex'
        for the expanded IP form, 'hy' / 'ci' for MAC
        notations) is rendered by '_format_alt'; 'b' / 'x' /
        'X' yield the integer zero-padded to the
        address-family bit width, accepting the '#' (radix
        prefix) and '_' (4-digit grouping) modifiers; 'd'
        (plain decimal) and 'n' (locale-aware decimal)
        delegate verbatim to the stdlib integer formatter and
        take no modifiers. Any other spec — including an empty
        spec or a bare fill / align / width / precision with
        no presentation code — is delegated to str(self), so
        the canonical text form supports the full string
        mini-language without a trailing 's'.
        """

        if not format_spec or format_spec[-1] == "s":
            return format(str(self), format_spec)

        alt = self._format_alt(format_spec)
        if alt is not None:
            return alt

        code = format_spec[-1]
        flags = format_spec[:-1]

        if code in {"b", "x", "X", "d", "n"}:
            # 'b' / 'x' / 'X' are the address-family-width
            # zero-padded radix forms ('#' radix-prefix and '_'
            # 4-digit grouping modifiers apply); 'd' / 'n'
            # delegate verbatim to the stdlib integer formatter
            # ('d' plain decimal, 'n' locale-aware decimal) and
            # take no modifiers.
            if not ((code in {"b", "x", "X"} and not (set(flags) - {"#", "_"})) or (code in {"d", "n"} and not flags)):
                raise type(self)._sanity_error(
                    f"Unknown format code {format_spec!r} for object of type {type(self).__name__!r}"
                )

            if code in {"d", "n"}:
                return format(self._address, code)

            bits = self._address_len * 8

            digit_width = bits if code == "b" else bits // 4
            digits = format(self._address, f"0{digit_width}{code}")

            if "_" in flags:
                digits = "_".join(digits[i : i + 4] for i in range(0, len(digits), 4))

            if "#" in flags:
                digits = ("0b" if code == "b" else "0x") + digits

            return digits

        # No recognised custom code: the spec is a
        # string-presentation spec (bare fill / align / width /
        # precision, no trailing 's' required). Delegate to
        # str(self), converting the builtin ValueError that an
        # unknown presentation code raises into this type's
        # sanity error (net_addr.md §7.1 — no bare builtin
        # escapes; chain the cause so the offending code is
        # greppable in the traceback).
        try:
            return format(str(self), format_spec)
        except ValueError as error:
            raise type(self)._sanity_error(
                f"Unknown format code {format_spec!r} for object of type {type(self).__name__!r}"
            ) from error

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the network address as a memoryview.
        """

        raise NotImplementedError

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the network address with another object.
        """

        return other is self or (isinstance(other, type(self)) and self._address == other._address)

    @override
    def __hash__(self) -> int:
        """
        Get the network address hash value.
        """

        return hash((type(self), self._address))

    def __lt__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address < other._address

    def __le__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address <= other._address

    def __gt__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address > other._address

    def __ge__(self, other: object, /) -> bool:
        """
        Order the network address by its integer value. Ordering
        across address types (e.g. IPv4 vs IPv6) is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._address >= other._address

    def _with_offset(self, delta: int, /) -> Self:
        """
        Get this address shifted by an integer offset. An
        out-of-range result is an invalid-operation outcome, not
        a malformed literal, so it raises the address type's
        sanity error naming the operation (net_addr.md §7.2).
        """

        result = self._address + delta

        if not 0 <= result <= (1 << (self._address_len * 8)) - 1:
            raise type(self)._sanity_error(
                f"{type(self).__name__} offset out of range: " f"{self} {'+' if delta >= 0 else '-'} {abs(delta)}"
            )

        return type(self)(result)

    def __add__(self, other: object, /) -> Self:
        """
        Get the network address advanced by an integer offset.
        An out-of-range result raises the address-type sanity
        error.
        """

        if not isinstance(other, int):
            return NotImplemented

        return self._with_offset(other)

    def __sub__(self, other: object, /) -> Self:
        """
        Get the network address retreated by an integer offset.
        An out-of-range result raises the address-type sanity
        error.
        """

        if not isinstance(other, int):
            return NotImplemented

        return self._with_offset(-other)

    @property
    def unspecified(self) -> Self:
        """
        Get the unspecified network address.
        """

        return type(self)()

    @property
    def is_unspecified(self) -> bool:
        """
        Check if the network address is unspecified.
        """

        return self._address == 0
