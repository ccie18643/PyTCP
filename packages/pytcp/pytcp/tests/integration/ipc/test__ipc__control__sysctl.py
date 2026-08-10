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
Integration tests for the out-of-process sysctl control mirror.

pytcp/tests/integration/ipc/test__ipc__control__sysctl.py

ver 3.0.10
"""

import os
import tempfile
from typing import override
from unittest import TestCase

from pytcp import stack
from pytcp.client import ClientStack, connect
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__server import IpcServer
from pytcp.stack import sysctl as sysctl_module

_LOG__CHANNEL_PRIOR: set[str] = set()

# A stable int-valued sysctl knob to exercise get / set against.
_SAMPLE_KEY: str = "dhcp.retrans_initial_ms"


def setUpModule() -> None:
    """
    Silence the 'stack'-channel Subsystem lifecycle logging for the
    duration of this module.
    """

    global _LOG__CHANNEL_PRIOR
    _LOG__CHANNEL_PRIOR = stack.LOG__CHANNEL
    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the original logger channel set.
    """

    stack.LOG__CHANNEL = _LOG__CHANNEL_PRIOR


class TestIpcControlSysctl(TestCase):
    """
    The out-of-process sysctl control-mirror tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up an 'IpcServer' on a temp AF_UNIX path and register its
        teardown plus the sysctl-registry restore.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self.addCleanup(sysctl_module.reset_to_defaults)

        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _connect(self) -> ClientStack:
        """
        Open a client stack against the server and register its close.
        """

        client = connect(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    def test__ipc__control__sysctl_get_matches_in_process(self) -> None:
        """
        Ensure an out-of-process sysctl get returns the same value the
        in-process registry holds.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.sysctl.get(_SAMPLE_KEY),
            sysctl_module.get(_SAMPLE_KEY),
            msg="A client sysctl get must match the in-process registry value.",
        )

    def test__ipc__control__sysctl_list_keys_matches_in_process(self) -> None:
        """
        Ensure an out-of-process sysctl list_keys returns the same key
        set the in-process registry exposes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.sysctl.list_keys(),
            sysctl_module.list_keys(),
            msg="A client sysctl list_keys must match the in-process key set.",
        )

    def test__ipc__control__sysctl_snapshot_matches_in_process(self) -> None:
        """
        Ensure an out-of-process sysctl snapshot equals the in-process
        snapshot, so every key/value round-trips across the boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.sysctl.snapshot(),
            sysctl_module.snapshot(),
            msg="A client sysctl snapshot must equal the in-process snapshot.",
        )

    def test__ipc__control__sysctl_set_mutates_daemon_state(self) -> None:
        """
        Ensure an out-of-process sysctl set mutates the real daemon-side
        registry, and a subsequent client get reflects the new value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        new_value = sysctl_module.get(_SAMPLE_KEY) + 1000

        client.sysctl.set(_SAMPLE_KEY, new_value)

        self.assertEqual(
            (sysctl_module.get(_SAMPLE_KEY), client.sysctl.get(_SAMPLE_KEY)),
            (new_value, new_value),
            msg="A client sysctl set must mutate the daemon registry and be visible on get.",
        )

    def test__ipc__control__sysctl_get_unknown_key_raises_remote_error(self) -> None:
        """
        Ensure a client sysctl get on an unregistered key raises
        'IpcRemoteError', forwarding the daemon-side failure across the
        boundary rather than returning a bogus value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        with self.assertRaises(IpcRemoteError):
            client.sysctl.get("no.such.sysctl.key")

    def test__ipc__control__sysctl_describe_matches_in_process(self) -> None:
        """
        Ensure an out-of-process sysctl describe returns the same text
        the in-process registry produces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.sysctl.describe(_SAMPLE_KEY),
            sysctl_module.describe(_SAMPLE_KEY),
            msg="A client sysctl describe must match the in-process description.",
        )
