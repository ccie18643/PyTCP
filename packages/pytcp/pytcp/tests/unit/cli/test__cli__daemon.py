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
This module contains tests for the 'pytcp daemon stop' pidfile handling.

pytcp/tests/unit/cli/test__cli__daemon.py

ver 3.0.8
"""

import contextlib
import io
import os
import signal
import tempfile
from typing import override
from unittest import TestCase
from unittest.mock import patch

from pytcp.cli.__main__ import main
from pytcp.daemon.daemon import remove_pidfile
from pytcp.ipc.ipc__errors import IpcRemoteError


class _StubMissingOpStack:
    """
    A 'ClientStack' stand-in whose socket-introspection op is unavailable
    — modelling a daemon running an older build that does not expose
    'stack.ss'. Used to exercise the 'daemon status' graceful-degradation
    path without a live daemon.
    """

    class _Link:
        def list_interfaces(self) -> list[int]:
            return []

    class _Route:
        def list_routes(self) -> list[object]:
            return []

    class _Ss:
        def list_sockets(self, **_kwargs: object) -> list[object]:
            raise IpcRemoteError(
                error_type="AttributeError",
                message="module 'pytcp.stack' has no attribute 'ss'",
            )

    def __init__(self) -> None:
        self.link = self._Link()
        self.route = self._Route()
        self.ss = self._Ss()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class TestCliDaemonStop(TestCase):
    """
    The 'pytcp daemon stop' pidfile-handling tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create a temp directory for pidfiles, removed on cleanup.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-cli-")
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        """
        Remove the temp directory and any pidfile left in it.
        """

        for name in os.listdir(self._tmp_dir):
            os.unlink(os.path.join(self._tmp_dir, name))
        os.rmdir(self._tmp_dir)

    def _pidfile(self, *, pid: int | None) -> str:
        """
        Return a pidfile path, optionally pre-written with 'pid'.
        """

        path = os.path.join(self._tmp_dir, "pytcp.pid")
        if pid is not None:
            with open(path, "w", encoding="ascii") as handle:
                handle.write(f"{pid}\n")
        return path

    def _run_stop(self, pidfile_path: str, /) -> int:
        """
        Run 'daemon stop' against a pidfile, silencing its output.
        """

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["daemon", "stop", "--pidfile", pidfile_path])

    def test__daemon_stop__sends_sigterm_to_pid(self) -> None:
        """
        Ensure 'daemon stop' reads the pidfile and sends SIGTERM to the
        recorded process id.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        kill = self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True))

        exit_code = self._run_stop(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 0, msg="daemon stop must succeed when the daemon is running.")
        kill.assert_called_once_with(4242, signal.SIGTERM)

    def test__daemon_stop__removes_stale_pidfile(self) -> None:
        """
        Ensure 'daemon stop' removes a stale pidfile when the recorded
        process no longer exists.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True, side_effect=ProcessLookupError))
        pidfile = self._pidfile(pid=4242)

        exit_code = self._run_stop(pidfile)

        self.assertEqual(exit_code, 1, msg="daemon stop must report failure for a stale pidfile.")
        self.assertFalse(os.path.exists(pidfile), msg="A stale pidfile must be removed.")

    def test__daemon_stop__no_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'daemon stop' reports failure when no pidfile is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        exit_code = self._run_stop(os.path.join(self._tmp_dir, "missing.pid"))

        self.assertEqual(exit_code, 1, msg="daemon stop must report failure when no pidfile exists.")


class TestCliDaemonStatus(TestCase):
    """
    The 'pytcp daemon status' reporting tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create a temp directory for pidfiles, removed on cleanup.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-cli-status-")
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        """
        Remove the temp directory and any pidfile left in it.
        """

        for name in os.listdir(self._tmp_dir):
            os.unlink(os.path.join(self._tmp_dir, name))
        os.rmdir(self._tmp_dir)

    def _pidfile(self, *, pid: int | None) -> str:
        """
        Return a pidfile path, optionally pre-written with 'pid'.
        """

        path = os.path.join(self._tmp_dir, "pytcp.pid")
        if pid is not None:
            with open(path, "w", encoding="ascii") as handle:
                handle.write(f"{pid}\n")
        return path

    def _run_status(self, pidfile_path: str, /) -> tuple[int, str]:
        """
        Run 'daemon status' against a pidfile, capturing its stdout.
        """

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["daemon", "status", "--pidfile", pidfile_path, "--ipc-socket", "/nonexistent.sock"])
        return exit_code, buffer.getvalue()

    def test__daemon_status__no_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'daemon status' reports the daemon is not running and exits
        3 (LSB "program is not running") when no pidfile is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        exit_code, output = self._run_status(os.path.join(self._tmp_dir, "missing.pid"))

        self.assertEqual(exit_code, 3, msg="daemon status must exit 3 when the daemon is not running.")
        self.assertIn("not running", output, msg="daemon status must report the daemon is not running.")

    def test__daemon_status__stale_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'daemon status' reports not-running and exits 3 when the
        pidfile names a process that no longer exists.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True, side_effect=ProcessLookupError))

        exit_code, output = self._run_status(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 3, msg="daemon status must exit 3 for a stale pidfile.")
        self.assertIn("not running", output, msg="daemon status must report a stale pidfile as not running.")

    def test__daemon_status__running_but_unreachable_reports_pid(self) -> None:
        """
        Ensure 'daemon status' reports the daemon is running (with its pid)
        and exits 0 even when the control socket cannot be reached.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True))
        self.enterContext(
            patch("pytcp.cli.__main__.connect", autospec=True, side_effect=OSError("connection refused")),
        )

        exit_code, output = self._run_status(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 0, msg="daemon status must exit 0 when the daemon process is alive.")
        self.assertIn("running (pid 4242)", output, msg="daemon status must report the running pid.")
        self.assertIn("unreachable", output, msg="daemon status must note an unreachable control socket.")

    def test__daemon_status__running_degrades_on_missing_control_op(self) -> None:
        """
        Ensure 'daemon status' degrades a summary section to a note (and
        still exits 0) when the daemon lacks a control op — an older build
        that does not expose 'stack.ss' — rather than aborting with a
        traceback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True))
        self.enterContext(
            patch("pytcp.cli.__main__.connect", autospec=True, return_value=_StubMissingOpStack()),
        )

        exit_code, output = self._run_status(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 0, msg="daemon status must exit 0 when a control op is unavailable.")
        self.assertIn("running (pid 4242)", output, msg="daemon status must report the running pid.")
        self.assertIn("unavailable", output, msg="daemon status must note the unavailable summary section.")


class TestRemovePidfile(TestCase):
    """
    The daemon pidfile-removal helper tests.
    """

    def test__remove_pidfile__removes_and_tolerates_absence(self) -> None:
        """
        Ensure remove_pidfile deletes an existing pidfile and tolerates a
        second removal of the now-absent file.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "pytcp.pid")
            with open(path, "w", encoding="ascii") as handle:
                handle.write("1\n")

            remove_pidfile(path)
            self.assertFalse(os.path.exists(path), msg="remove_pidfile must delete the pidfile.")

            remove_pidfile(path)  # second removal must not raise
