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
The base class for servers and clients used in examples.

examples/lib/subsystem.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from net_addr.ip4_address import Ip4Address
    from net_addr.ip6_address import Ip6Address


class Subsystem(ABC):
    """
    Base class for 'user space' services like clients and servers.
    """

    stack_ip4_address: Ip4Address
    stack_ip6_address: Ip6Address

    _subsystem_name: str
    _is_alive: bool

    @abstractmethod
    def start(self) -> None:
        """
        Start the subsystem.
        """

        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """
        Stop the subsystem.
        """

        raise NotImplementedError

    @property
    def is_alive(self) -> bool:
        """
        Check if the service thread is alive.
        """

        return self._is_alive

    def _log(self, message: str) -> None:
        """
        Log a message.
        """

        click.secho(
            f"{self._subsystem_name} - {message}",
            bg="bright_blue",
            fg="bright_yellow",
            bold=True,
        )
