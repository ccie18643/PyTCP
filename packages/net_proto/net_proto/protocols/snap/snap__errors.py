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
This module contains the SNAP protocol error classes.

net_proto/protocols/snap/snap__errors.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class SnapIntegrityError(PacketIntegrityError):
    """
    Exception raised when SNAP packet integrity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[SNAP] " + message)


class SnapSanityError(PacketSanityError):
    """
    Exception raised when SNAP packet sanity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[SNAP] " + message)
