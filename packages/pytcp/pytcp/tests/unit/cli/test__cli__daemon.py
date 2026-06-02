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
