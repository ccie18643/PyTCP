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

# pylint: disable=unnecessary-lambda-assignment


"""
Module contains globals and checks for various lengths integers.

pytcp/lib/ints.py

ver 3.0.0
"""


from __future__ import annotations

UINT_2__MIN = 0x00
UINT_2__MAX = 0x03

UINT_4__MIN = 0x0
UINT_4__MAX = 0xF

UINT_6__MIN = 0x00
UINT_6__MAX = 0x3F

UINT_8__MIN = 0x00
UINT_8__MAX = 0xFF

UINT_13__MIN = 0x0000
UINT_13__MAX = 0xFFF8

UINT_16__MIN = 0x0000
UINT_16__MAX = 0xFFFF

UINT_20__MIN = 0x00000
UINT_20__MAX = 0xFFFFF

UINT_32__MIN = 0x00000000
UINT_32__MAX = 0xFFFFFFFF


def is_uint2(x: int) -> bool:
    """
    Check if provided value is a valid 2-bit unsigned integer.
    """

    return UINT_2__MIN <= x <= UINT_2__MAX


def is_uint4(x: int) -> bool:
    """
    Check if provided value is a valid 4-bit unsigned integer.
    """

    return UINT_4__MIN <= x <= UINT_4__MAX


def is_uint6(x: int) -> bool:
    """
    Check if provided value is a valid 6-bit unsigned integer.
    """

    return UINT_6__MIN <= x <= UINT_6__MAX


def is_uint8(x: int) -> bool:
    """
    Check if provided value is a valid 8-bit unsigned integer.
    """

    return UINT_8__MIN <= x <= UINT_8__MAX


def is_uint13(x: int) -> bool:
    """
    Check if provided value is a valid 13-bit unsigned integer.
    """

    return UINT_13__MIN <= x <= UINT_13__MAX


def is_uint16(x: int) -> bool:
    """
    Check if provided value is a valid 16-bit unsigned integer.
    """

    return UINT_16__MIN <= x <= UINT_16__MAX


def is_uint20(x: int) -> bool:
    """
    Check if provided value is a valid 20-bit unsigned integer.
    """

    return UINT_20__MIN <= x <= UINT_20__MAX


def is_uint32(x: int) -> bool:
    """
    Check if provided value is a valid 32-bit unsigned integer.
    """

    return UINT_32__MIN <= x <= UINT_32__MAX


def is_4_byte_alligned(x: int) -> bool:
    """
    Check if provided value is aligned to 4-byte boundary.
    """

    return x % 4 == 0


def is_8_byte_alligned(x: int) -> bool:
    """
    Check if provided value is aligned to 8-byte boundary.
    """

    return x % 8 == 0
