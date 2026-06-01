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
This module contains the client-side mirror of the sysctl control API.

'ClientSysctl' marshals each sysctl operation across the IPC control
channel to the daemon's 'pytcp.stack.sysctl' registry, mirroring the
in-process module functions ('get' / 'set' / 'list_keys' / 'describe' /
'snapshot' / 'reset_to_defaults') with the same signatures.

pytcp/client/client__sysctl.py

ver 3.0.8
"""

from typing import Any, cast

from pytcp.client.client__base import _ClientApiProxy


class ClientSysctl(_ClientApiProxy):
    """
    The client-side mirror of the sysctl control API.
    """

    _api_name = "sysctl"

    def get(self, key: str) -> Any:
        """
        Get the current value of the sysctl knob 'key'.
        """

        return self._call("get", {"key": key})

    def set(self, key: str, value: Any) -> None:
        """
        Set the sysctl knob 'key' to 'value'.
        """

        self._call("set", {"key": key, "value": value})

    def list_keys(self) -> list[str]:
        """
        List every registered sysctl key.
        """

        return cast(list[str], self._call("list_keys", {}))

    def describe(self, key: str) -> str:
        """
        Describe the sysctl knob 'key'.
        """

        return cast(str, self._call("describe", {"key": key}))

    def snapshot(self) -> dict[str, Any]:
        """
        Return a snapshot of every sysctl key and its current value.
        """

        return cast(dict[str, Any], self._call("snapshot", {}))

    def reset_to_defaults(self) -> None:
        """
        Reset every sysctl knob to its registered default.
        """

        self._call("reset_to_defaults", {})
