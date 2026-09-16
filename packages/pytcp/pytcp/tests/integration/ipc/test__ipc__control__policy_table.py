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
Integration tests for the out-of-process RFC 6724 policy-table control
mirror — the last control API to reach across the daemon boundary.

pytcp/tests/integration/ipc/test__ipc__control__policy_table.py

ver 3.0.10
"""

import os
import tempfile
from typing import override
from unittest import TestCase

from net_addr import Ip6Network
from pytcp import stack
from pytcp.client import ClientStack, connect
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__server import IpcServer
from pytcp.protocols.ip6 import ip6__policy_table
from pytcp.protocols.ip6.ip6__policy_table import PolicyEntry

_LOG__CHANNEL_PRIOR: set[str] = set()

# A deliberately non-default table, distinguishable from the RFC 6724
# §10.3 defaults by both prefix and values. The ::/0 catch-all is
# mandatory — 'set_policy_table' rejects a table without one so 'lookup'
# stays total.
_CUSTOM_TABLE: tuple[PolicyEntry, ...] = (
    PolicyEntry(network=Ip6Network("2001:db8::/32"), precedence=77, label=9),
    PolicyEntry(network=Ip6Network("::/0"), precedence=40, label=1),
)


def setUpModule() -> None:
    """
    Silence the stack logger channels for the module's IPC servers.
    """

    global _LOG__CHANNEL_PRIOR

    _LOG__CHANNEL_PRIOR = stack.LOG__CHANNEL
    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the stack logger channels.
    """

    stack.LOG__CHANNEL = _LOG__CHANNEL_PRIOR


class TestIpcControlPolicyTable(TestCase):
    """
    The out-of-process policy-table control-mirror tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up an 'IpcServer' on a temp AF_UNIX path and register its
        teardown plus the policy-table restore.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self.addCleanup(ip6__policy_table.reset_policy_table)

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

    def test__policy_table__get_mirrors_the_in_process_table(self) -> None:
        """
        Ensure a client reads the same policy table the stack holds, with
        the row order preserved — 'lookup' takes the first matching
        prefix, so order is part of the value.

        Reference: RFC 6724 §10.3 (default policy table).
        """

        remote = self._connect().policy_table.get_policy_table()

        self.assertEqual(
            remote,
            ip6__policy_table.get_policy_table(),
            msg="The out-of-process table must equal the in-process one, in order.",
        )

    def test__policy_table__set_applies_to_the_stack(self) -> None:
        """
        Ensure a client replacing the table changes what the stack uses,
        so the control API is not a read-only mirror.

        Reference: RFC 6724 §10.3 (policy table is operator-tunable).
        """

        self._connect().policy_table.set_policy_table(_CUSTOM_TABLE)

        self.assertEqual(
            ip6__policy_table.get_policy_table(),
            _CUSTOM_TABLE,
            msg="A client-side set must replace the table the stack reads.",
        )

    def test__policy_table__set_round_trips_entry_fields(self) -> None:
        """
        Ensure a PolicyEntry survives the boundary field-for-field — the
        prefix as a network, the precedence and label as integers — so the
        value codec is not flattening the row.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        client.policy_table.set_policy_table(_CUSTOM_TABLE)

        entry = client.policy_table.get_policy_table()[0]

        self.assertEqual(
            (entry.network, entry.precedence, entry.label),
            (Ip6Network("2001:db8::/32"), 77, 9),
            msg="The policy-table row must round-trip its prefix, precedence and label.",
        )

    def test__policy_table__reset_restores_the_defaults(self) -> None:
        """
        Ensure a client reset restores the RFC 6724 default table after a
        custom one was installed.

        Reference: RFC 6724 §10.3 (default policy table).
        """

        client = self._connect()
        client.policy_table.set_policy_table(_CUSTOM_TABLE)
        client.policy_table.reset_policy_table()

        self.assertEqual(
            ip6__policy_table.get_policy_table(),
            ip6__policy_table.DEFAULT_POLICY_TABLE,
            msg="A client-side reset must restore the RFC 6724 §10.3 defaults.",
        )

    def test__policy_table__private_method_is_refused(self) -> None:
        """
        Ensure the control plane refuses a method outside the policy-table
        allowlist, so a peer cannot reach arbitrary module attributes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        with self.assertRaises(IpcRemoteError):
            client.policy_table._call("lookup", {"address": "::1"})
