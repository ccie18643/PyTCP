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
This module contains stack error classes.

net_proto/lib/errors.py

ver 3.0.4
"""


class PyTcpError(Exception):
    """
    Base class for all PyTCP exceptions.
    """


class PacketValidationError(PyTcpError):
    """
    Exception raised when packet validation fails.
    """


class PacketIntegrityError(PacketValidationError):
    """
    Exception raised when integrity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[INTEGRITY ERROR]" + message)


class PacketSanityError(PacketValidationError):
    """
    Exception raised when sanity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[SANITY ERROR]" + message)
