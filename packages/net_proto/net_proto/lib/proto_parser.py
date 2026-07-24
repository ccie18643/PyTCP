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
This module contains the base class for all protocol parser classes.

net_proto/lib/proto_parser.py

ver 3.0.9
"""

from abc import abstractmethod

from net_addr import Buffer
from net_proto.lib.proto import Proto


class ProtoParser(Proto):
    """
    Base class for all protocol parser classes.
    """

    _frame: Buffer

    @abstractmethod
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the received packet before parsing it.
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
        Ensure sanity of the received packet after parsing it.
        """

        raise NotImplementedError

    @property
    def frame(self) -> memoryview:
        """
        Get the '_frame' attribute.
        """

        return memoryview(self._frame)
