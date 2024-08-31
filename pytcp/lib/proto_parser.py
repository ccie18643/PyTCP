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
Module contains the base class for all of the protocol parser classes.

pytcp/lib/proto_parser.py

ver 3.0.2
"""


from __future__ import annotations

from abc import abstractmethod

from pytcp.lib.proto import Proto


class ProtoParser(Proto):
    """
    Base class for all of the protocol parser classes.
    """

    _frame: memoryview

    @abstractmethod
    def _validate_integrity(self) -> None:
        """
        Validate the integrity of the incoming packet before parsing it.
        """

        raise NotImplementedError

    @abstractmethod
    def _parse(self) -> None:
        """
        Parse the incoming packet.
        """

        raise NotImplementedError

    @abstractmethod
    def _validate_sanity(self) -> None:
        """
        Validate the sanity of the incoming packet after parsing it.
        """

        raise NotImplementedError

    @property
    def frame(self) -> memoryview:
        """
        Get the '_frame' attribute.
        """

        return self._frame
