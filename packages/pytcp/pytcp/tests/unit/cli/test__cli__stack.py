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
This module contains tests for the 'pytcp stack' subcommand (start / stop / status).

pytcp/tests/unit/cli/test__cli__stack.py

ver 3.0.10
"""

import contextlib
import io
import json
import os
import signal
import tempfile
from types import SimpleNamespace
from typing import override
from unittest import TestCase
from unittest.mock import ANY, patch

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, MacAddress
from pytcp import __version__
from pytcp.cli.__main__ import (
    _cmd_address,
    _cmd_neighbor_list,
    _cmd_route_list,
    _cmd_ss,
    build_parser,
    main,
)
from pytcp.cli.cli__format import InterfaceView
from pytcp.daemon.daemon import remove_pidfile
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.lib.neighbor import NudState
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.fib import Route
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.stack.socket_introspect import SocketSnapshot


class _StubMissingOpStack:
    """
    A 'ClientStack' stand-in whose socket-introspection op is unavailable
    — modelling a daemon running an older build that does not expose
    'stack.ss'. Used to exercise the 'stack status' graceful-degradation
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

    class _Activity:
        def list_activity(self) -> list[object]:
            raise IpcRemoteError(
                error_type="AttributeError",
                message="module 'pytcp.stack' has no attribute 'activity'",
            )

    def __init__(self) -> None:
        self.link = self._Link()
        self.route = self._Route()
        self.ss = self._Ss()
        self.activity = self._Activity()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class TestCliStackStop(TestCase):
    """
    The 'pytcp stack stop' pidfile-handling tests.
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
        Run 'stack stop' against a pidfile, silencing its output.
        """

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["stack", "stop", "--pidfile", pidfile_path])

    def test__stack_stop__sends_sigterm_to_pid(self) -> None:
        """
        Ensure 'stack stop' reads the pidfile and sends SIGTERM to the
        recorded process id.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        kill = self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True))

        exit_code = self._run_stop(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 0, msg="stack stop must succeed when the daemon is running.")
        kill.assert_called_once_with(4242, signal.SIGTERM)

    def test__stack_stop__removes_stale_pidfile(self) -> None:
        """
        Ensure 'stack stop' removes a stale pidfile when the recorded
        process no longer exists.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True, side_effect=ProcessLookupError))
        pidfile = self._pidfile(pid=4242)

        exit_code = self._run_stop(pidfile)

        self.assertEqual(exit_code, 1, msg="stack stop must report failure for a stale pidfile.")
        self.assertFalse(os.path.exists(pidfile), msg="A stale pidfile must be removed.")

    def test__stack_stop__no_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'stack stop' reports failure when no pidfile is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        exit_code = self._run_stop(os.path.join(self._tmp_dir, "missing.pid"))

        self.assertEqual(exit_code, 1, msg="stack stop must report failure when no pidfile exists.")


class TestCliStackStatus(TestCase):
    """
    The 'pytcp stack status' reporting tests.
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
        Run 'stack status' against a pidfile, capturing its stdout.
        """

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["--ipc-socket", "/nonexistent.sock", "stack", "status", "--pidfile", pidfile_path])
        return exit_code, buffer.getvalue()

    def test__stack_status__no_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'stack status' reports the daemon is not running and exits
        3 (LSB "program is not running") when no pidfile is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        exit_code, output = self._run_status(os.path.join(self._tmp_dir, "missing.pid"))

        self.assertEqual(exit_code, 3, msg="stack status must exit 3 when the daemon is not running.")
        self.assertIn("not running", output, msg="stack status must report the daemon is not running.")

    def test__stack_status__stale_pidfile_reports_not_running(self) -> None:
        """
        Ensure 'stack status' reports not-running and exits 3 when the
        pidfile names a process that no longer exists.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True, side_effect=ProcessLookupError))

        exit_code, output = self._run_status(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 3, msg="stack status must exit 3 for a stale pidfile.")
        self.assertIn("not running", output, msg="stack status must report a stale pidfile as not running.")

    def test__stack_status__running_but_unreachable_reports_pid(self) -> None:
        """
        Ensure 'stack status' reports the daemon is running (with its pid)
        and exits 0 even when the control socket cannot be reached.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(patch("pytcp.cli.__main__.os.kill", autospec=True))
        self.enterContext(
            patch("pytcp.cli.__main__.connect", autospec=True, side_effect=OSError("connection refused")),
        )

        exit_code, output = self._run_status(self._pidfile(pid=4242))

        self.assertEqual(exit_code, 0, msg="stack status must exit 0 when the daemon process is alive.")
        self.assertIn("running (pid 4242)", output, msg="stack status must report the running pid.")
        self.assertIn("unreachable", output, msg="stack status must note an unreachable control socket.")

    def test__stack_status__running_degrades_on_missing_control_op(self) -> None:
        """
        Ensure 'stack status' degrades a summary section to a note (and
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

        self.assertEqual(exit_code, 0, msg="stack status must exit 0 when a control op is unavailable.")
        self.assertIn("running (pid 4242)", output, msg="stack status must report the running pid.")
        self.assertIn("unavailable", output, msg="stack status must note the unavailable summary section.")


class TestCliStackStart(TestCase):
    """
    The 'pytcp stack start' interface-argument tests.
    """

    def test__stack_start__binds_multiple_interfaces(self) -> None:
        """
        Ensure 'pytcp stack start --interface tap7 --interface tap9'
        threads both interface names through to 'run_daemon' so the daemon
        binds a multi-homed host.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.cli.__main__.run_daemon", autospec=True) as run_daemon:
            main(
                [
                    "--ipc-socket",
                    "/tmp/x.sock",
                    "stack",
                    "start",
                    "--interface",
                    "tap7",
                    "--interface",
                    "tap9",
                    "--pidfile",
                    "/tmp/x.pid",
                ]
            )

        run_daemon.assert_called_once_with(
            socket_path="/tmp/x.sock",
            interfaces=["tap7", "tap9"],
            pidfile_path="/tmp/x.pid",
            on_ready=ANY,
        )

    def test__stack_start__defaults_to_single_tap7(self) -> None:
        """
        Ensure 'pytcp stack start' with no --interface defaults to a
        single 'tap7' interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.cli.__main__.run_daemon", autospec=True) as run_daemon:
            main(["--ipc-socket", "/tmp/x.sock", "stack", "start", "--pidfile", "/tmp/x.pid"])

        run_daemon.assert_called_once_with(
            socket_path="/tmp/x.sock",
            interfaces=["tap7"],
            pidfile_path="/tmp/x.pid",
            on_ready=ANY,
        )


class TestRemovePidfile(TestCase):
    """
    The stack-daemon pidfile-removal helper tests.
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


class TestCliAddressJson(TestCase):
    """
    The 'pytcp address --json' output-selection tests.
    """

    _VIEW = InterfaceView(
        ifindex=1,
        name="tap7",
        flags=("BROADCAST", "MULTICAST", "UP"),
        mtu=1500,
        mac_address=MacAddress("02:00:00:00:00:07"),
        addresses=(Ip4IfAddr("10.0.1.7/24"),),
    )

    def test__cmd_address__json_flag_emits_json(self) -> None:
        """
        Ensure 'address -j' renders the interface view as a JSON array
        rather than the human 'ip addr' table.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.cli.__main__._interface_views", return_value=[self._VIEW]):
            output = _cmd_address(SimpleNamespace(), SimpleNamespace(json=True))  # type: ignore[arg-type]
        self.assertEqual(
            json.loads(output)[0]["ifname"],
            "tap7",
            msg="address -j must emit a JSON array of interface objects.",
        )

    def test__cmd_address__default_emits_table(self) -> None:
        """
        Ensure a bare 'address' (no '-j') renders the human-readable 'ip
        addr' table, not JSON.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.cli.__main__._interface_views", return_value=[self._VIEW]):
            output = _cmd_address(SimpleNamespace(), SimpleNamespace(json=False))  # type: ignore[arg-type]
        self.assertEqual(
            output,
            "1: tap7: <BROADCAST,MULTICAST,UP> mtu 1500\n" "    link/ether 02:00:00:00:00:07\n" "    inet 10.0.1.7/24",
            msg="A bare 'address' must render the 'ip addr' table.",
        )


class _StubObservationStack:
    """
    A minimal 'ClientStack' stand-in for the observation-command JSON
    dispatch tests: one IPv4 interface 'tap7' carrying one socket, one
    route, and one neighbour, all IPv4-only.
    """

    class _Link:
        def list_interfaces(self) -> list[int]:
            return [1]

        def interface(self, _ifindex: int, /) -> object:
            return SimpleNamespace(name="tap7")

    class _Ss:
        def list_sockets(self, *, family: AddressFamily, **_kwargs: object) -> list[SocketSnapshot]:
            if family is not AddressFamily.INET4:
                return []
            return [
                SocketSnapshot(
                    address_family=AddressFamily.INET4,
                    socket_type=SocketType.STREAM,
                    local_address=Ip4Address("0.0.0.0"),
                    local_port=80,
                    remote_address=Ip4Address("0.0.0.0"),
                    remote_port=0,
                    state=FsmState.LISTEN,
                    rx_queue=0,
                    tx_queue=0,
                )
            ]

    class _Route:
        def list_routes(self, *, family: AddressFamily) -> list[object]:
            if family is not AddressFamily.INET4:
                return []
            return [Route(destination=Ip4Network("0.0.0.0/0"), gateway=Ip4Address("10.0.1.1"), oif=1)]

    class _Neighbor:
        def interface(self, _ifindex: int, /) -> object:
            def list_neighbors(*, family: AddressFamily) -> list[NeighborSnapshot]:
                if family is not AddressFamily.INET4:
                    return []
                return [
                    NeighborSnapshot(
                        address=Ip4Address("10.0.1.91"),
                        mac_address=MacAddress("02:00:00:00:00:91"),
                        state=NudState.REACHABLE,
                    )
                ]

            return SimpleNamespace(list_neighbors=list_neighbors)

    def __init__(self) -> None:
        self.link = self._Link()
        self.ss = self._Ss()
        self.route = self._Route()
        self.neighbor = self._Neighbor()


class TestCliObservationJson(TestCase):
    """
    The 'ss' / 'route' / 'neighbor' '--json' dispatch tests.
    """

    def test__cmd_ss__json_flag_emits_json(self) -> None:
        """
        Ensure 'ss -j' renders the socket table as a JSON array rather
        than the human section report.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        args = SimpleNamespace(inet=True, inet6=False, tcp=False, udp=False, listening=False, json=True)
        output = _cmd_ss(_StubObservationStack(), args)  # type: ignore[arg-type]
        self.assertEqual(
            json.loads(output)[0]["netid"],
            "tcp",
            msg="ss -j must emit a JSON array of socket objects.",
        )

    def test__cmd_route__json_flag_emits_json(self) -> None:
        """
        Ensure 'route -j' renders the routing table as a JSON array rather
        than the human section report.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        args = SimpleNamespace(inet=True, inet6=False, json=True)
        output = _cmd_route_list(_StubObservationStack(), args)  # type: ignore[arg-type]
        self.assertEqual(
            json.loads(output)[0]["dst"],
            "0.0.0.0/0",
            msg="route -j must emit a JSON array of route objects.",
        )

    def test__cmd_neighbor__json_flag_emits_json(self) -> None:
        """
        Ensure 'neighbor -j' renders the neighbour caches as a JSON array
        rather than the human section report.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        args = SimpleNamespace(inet=True, inet6=False, json=True)
        output = _cmd_neighbor_list(_StubObservationStack(), args)  # type: ignore[arg-type]
        self.assertEqual(
            json.loads(output)[0]["dst"],
            "10.0.1.91",
            msg="neighbor -j must emit a JSON array of neighbour objects.",
        )


class TestCliUnreachableDaemon(TestCase):
    """
    The observation-subcommand unreachable-daemon graceful-failure tests.
    """

    def test__observation_command__unreachable_daemon_reports_cleanly(self) -> None:
        """
        Ensure an observation subcommand pointed at a non-existent daemon
        control socket prints a clean diagnostic and exits non-zero,
        rather than crashing with an unhandled connect traceback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        missing = os.path.join(tempfile.gettempdir(), "pytcp-nonexistent-socket-918273.sock")
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            exit_code = main(["--ipc-socket", missing, "route"])

        self.assertEqual(
            exit_code,
            1,
            msg="An unreachable daemon must exit 1, not raise.",
        )
        self.assertIn(
            "daemon",
            stderr.getvalue().lower(),
            msg="The diagnostic must mention the daemon so the operator knows what failed.",
        )


class TestCliBanner(TestCase):
    """
    The CLI help-banner tests.
    """

    def test__help__leads_with_the_versioned_pytcp_banner(self) -> None:
        """
        Ensure 'pytcp --help' leads with the 'PyTCP - Python TCP/IP Stack'
        banner carrying the version, set off by a blank line before and
        after, ahead of the usage line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stdout = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(stdout):
                main(["--help"])

        output = stdout.getvalue()
        self.assertIn(
            f"\nPyTCP - Python TCP/IP Stack v{__version__}\n\nusage:",
            output,
            msg="The help must lead with the versioned banner, blank-line-separated, before usage.",
        )
        self.assertTrue(
            output.endswith("\n\n"),
            msg="The help must end with a trailing blank line.",
        )

    def test__version__prints_tool_version(self) -> None:
        """
        Ensure 'pytcp --version' prints the tool version and exits 0
        (the version is a top-level option, not per-subcommand).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout):
                main(["--version"])

        self.assertEqual(raised.exception.code, 0, msg="--version must exit 0.")
        self.assertIn(__version__, stdout.getvalue(), msg="--version must print the tool version.")

    def test__help__highlights_banner_and_section_headings(self) -> None:
        """
        Ensure TTY help renders the banner and the section headings
        ('usage:', 'options:', 'commands:') in bold bright-white, while
        body content (command descriptions) stays the terminal default —
        argparse's own 3.14 help colour is disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("sys.stdout") as fake_stdout:
            fake_stdout.isatty.return_value = True
            help_text = build_parser().format_help()

        self.assertIn(
            f"\033[1;97mPyTCP - Python TCP/IP Stack v{__version__}\033[0m",
            help_text,
            msg="The banner must be bold bright-white.",
        )
        for heading in ("usage:", "options:", "commands:"):
            self.assertIn(
                f"\033[1;97m{heading}\033[0m",
                help_text,
                msg=f"The {heading!r} heading must be bold bright-white.",
            )
        self.assertIn(
            "    ss                  Show socket statistics.",
            help_text,
            msg="Body content must stay uncoloured (argparse colour disabled).",
        )

    def test__help__commands_section_has_no_metavar_line(self) -> None:
        """
        Ensure the 'commands:' help section lists the commands directly,
        without the redundant '<command>' metavar header line above them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stdout = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(stdout):
                main(["--help"])

        output = stdout.getvalue()
        self.assertIn("commands:\n    ss ", output, msg="The commands section must list commands directly.")
        self.assertNotIn("  <command>\n", output, msg="The redundant '<command>' header line must be gone.")

    def test__subcommand_help__also_leads_with_the_banner(self) -> None:
        """
        Ensure a subcommand's help ('pytcp route --help') also leads with
        the banner, since every help screen should carry it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stdout = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(stdout):
                main(["route", "--help"])

        self.assertIn(
            "PyTCP - Python TCP/IP Stack",
            stdout.getvalue(),
            msg="Every help screen must carry the banner.",
        )


class TestCliRouteModifyHelp(TestCase):
    """
    The 'route add' help tests.
    """

    def test__route_add_help__prints_usage_without_a_daemon(self) -> None:
        """
        Ensure 'pytcp route add --help' serves the add subcommand usage
        (argparse-native) and exits 0 without contacting the daemon, so
        help works whether or not a daemon is running.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout):
                main(["route", "add", "--help"])

        self.assertEqual(raised.exception.code, 0, msg="route add --help must exit 0.")
        output = stdout.getvalue()
        self.assertIn("DEST", output, msg="The add help must describe the DEST argument.")
        self.assertIn("--via", output, msg="The add help must describe the --via option.")
