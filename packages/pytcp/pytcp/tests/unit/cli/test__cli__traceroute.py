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
This module contains unit tests for the daemon-independent parts of the
'pytcp traceroute' engine — the pure wire helpers, the hop formatter,
and the 'run_traceroute' TTL-ladder generator driven against a faked
raw socket.

packages/pytcp/pytcp/tests/unit/cli/test__cli__traceroute.py

ver 3.0.8
"""

import io
import struct
from contextlib import redirect_stderr, redirect_stdout
from unittest import TestCase
from unittest.mock import create_autospec, patch

import pytcp.cli.__main__ as cli_main
from pytcp import socket
from pytcp.cli.cli__traceroute import (
    HopResult,
    ProbeResult,
    build_probe,
    format_hop_line,
    parse_probe_response,
    run_traceroute,
    traceroute_profile,
)

_ICMP__STRUCT = "!BBHHH"


def _ip4_header() -> bytes:
    """
    Build a minimal 20-octet IPv4 header (only the IHL nibble matters to
    the parser).
    """

    return b"\x45" + b"\x00" * 19


def _v4_echo_reply(*, identifier: int, sequence: int) -> bytes:
    """
    Build a raw-socket IPv4 + ICMP Echo Reply frame.
    """

    return _ip4_header() + struct.pack(_ICMP__STRUCT, 0, 0, 0, identifier, sequence)


def _v4_time_exceeded(*, identifier: int, sequence: int) -> bytes:
    """
    Build a raw-socket IPv4 + ICMP Time Exceeded frame embedding our
    triggering IPv4 + ICMP Echo Request.
    """

    embedded = _ip4_header() + struct.pack(_ICMP__STRUCT, 8, 0, 0, identifier, sequence)
    return _ip4_header() + struct.pack("!BBH", 11, 0, 0) + b"\x00\x00\x00\x00" + embedded


class _FakeTracerouteSocket:
    """
    A raw-socket double that records each TTL set and answers the last
    sent probe per a TTL -> '(hop, kind)' plan (a missing / None entry
    times out), echoing the probe's id and sequence so the engine's
    matcher accepts it.
    """

    def __init__(self, plan: dict[int, tuple[str, str] | None], /) -> None:
        self._plan = plan
        self._ttl = 0
        self._last_probe = b""
        self.ttls: list[int] = []

    def setsockopt(self, level: int, optname: int, value: int, /) -> None:
        self._ttl = value
        self.ttls.append(value)

    def settimeout(self, value: float | None, /) -> None:
        pass

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        self._last_probe = data
        return len(data)

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, tuple[str, int]]:
        entry = self._plan.get(self._ttl)
        if entry is None:
            raise TimeoutError
        hop, kind = entry
        _type, _code, _cksum, identifier, sequence = struct.unpack(_ICMP__STRUCT, self._last_probe)
        if kind == "reply":
            frame = _v4_echo_reply(identifier=identifier, sequence=sequence)
        else:
            frame = _v4_time_exceeded(identifier=identifier, sequence=sequence)
        return frame, (hop, 0)


class TestTracerouteProfile(TestCase):
    """
    The per-IP-version traceroute profile tests.
    """

    def test__cli__traceroute__profile_ipv4(self) -> None:
        """
        Ensure the IPv4 profile carries the Echo 8/0, Time Exceeded 11,
        and IP_TTL option values.

        Reference: RFC 792 (ICMP Echo / Time Exceeded).
        """

        profile = traceroute_profile(is_ipv6=False)

        self.assertEqual(
            (profile.echo_request, profile.echo_reply, profile.time_exceeded, profile.ip_header_included),
            (8, 0, 11, True),
            msg="The IPv4 profile must carry Echo 8/0, Time Exceeded 11, and an included IP header.",
        )

    def test__cli__traceroute__profile_ipv6(self) -> None:
        """
        Ensure the IPv6 profile carries the Echo 128/129 and Time Exceeded
        3 values and no embedded IP header.

        Reference: RFC 4443 (ICMPv6 Echo / Time Exceeded).
        """

        profile = traceroute_profile(is_ipv6=True)

        self.assertEqual(
            (profile.echo_request, profile.echo_reply, profile.time_exceeded, profile.ip_header_included),
            (128, 129, 3, False),
            msg="The IPv6 profile must carry Echo 128/129, Time Exceeded 3, and no included IP header.",
        )


class TestTracerouteBuildProbe(TestCase):
    """
    The probe-builder tests.
    """

    def test__cli__traceroute__build_probe_ipv4_has_valid_checksum(self) -> None:
        """
        Ensure an IPv4 probe is a well-formed 8-byte Echo Request whose
        checksum makes the message sum to zero.

        Reference: RFC 1071 (Internet checksum).
        """

        profile = traceroute_profile(is_ipv6=False)
        probe = build_probe(profile, identifier=0x1234, sequence=7)
        total = 0
        for index in range(0, len(probe), 2):
            total += (probe[index] << 8) + probe[index + 1]
        total = (total & 0xFFFF) + (total >> 16)

        self.assertEqual(
            (len(probe), total),
            (8, 0xFFFF),
            msg="An IPv4 probe must be an 8-byte Echo Request summing to zero (valid checksum).",
        )

    def test__cli__traceroute__build_probe_ipv6_leaves_checksum_zero(self) -> None:
        """
        Ensure an IPv6 probe leaves the checksum zero for the stack to
        fill (it covers a pseudo-header the application cannot see).

        Reference: RFC 4443 §2.3 (ICMPv6 checksum).
        """

        profile = traceroute_profile(is_ipv6=True)
        probe = build_probe(profile, identifier=0x1234, sequence=7)
        _type, _code, cksum, _id, _seq = struct.unpack(_ICMP__STRUCT, probe)

        self.assertEqual(cksum, 0, msg="An IPv6 probe must leave the checksum zero for the stack to fill.")


class TestTracerouteParseResponse(TestCase):
    """
    The probe-response classifier tests.
    """

    def test__cli__traceroute__parse_matches_echo_reply(self) -> None:
        """
        Ensure an Echo Reply matching our id and sequence classifies as
        'reply' (the destination is reached).

        Reference: RFC 792 (ICMP Echo Reply).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_echo_reply(identifier=0x1234, sequence=3)

        self.assertEqual(
            parse_probe_response(frame, profile=profile, identifier=0x1234, sequence=3),
            "reply",
            msg="A matching Echo Reply must classify as 'reply'.",
        )

    def test__cli__traceroute__parse_matches_time_exceeded(self) -> None:
        """
        Ensure a Time Exceeded embedding our Echo Request classifies as
        'time_exceeded' (an intermediate hop).

        Reference: RFC 792 (ICMP Time Exceeded).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_time_exceeded(identifier=0x1234, sequence=3)

        self.assertEqual(
            parse_probe_response(frame, profile=profile, identifier=0x1234, sequence=3),
            "time_exceeded",
            msg="A Time Exceeded embedding our probe must classify as 'time_exceeded'.",
        )

    def test__cli__traceroute__parse_rejects_foreign_sequence(self) -> None:
        """
        Ensure a reply for a different sequence is ignored (None), so
        stale or unrelated ICMP does not corrupt a hop result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_echo_reply(identifier=0x1234, sequence=9)

        self.assertIsNone(
            parse_probe_response(frame, profile=profile, identifier=0x1234, sequence=3),
            msg="A reply for a foreign sequence must be ignored.",
        )

    def test__cli__traceroute__parse_rejects_truncated(self) -> None:
        """
        Ensure a too-short datagram is ignored without raising.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        profile = traceroute_profile(is_ipv6=False)

        self.assertIsNone(
            parse_probe_response(b"\x45\x00\x00", profile=profile, identifier=0x1234, sequence=3),
            msg="A truncated datagram must be ignored without raising.",
        )


class TestTracerouteFormatHopLine(TestCase):
    """
    The hop-line formatter tests.
    """

    def test__cli__traceroute__format_hop_line_collapses_repeated_hop(self) -> None:
        """
        Ensure a hop line prints the TTL, the address once for repeated
        probes of the same hop, each RTT, and '*' for a timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        hop = HopResult(
            ttl=1,
            probes=(
                ProbeResult(hop="10.0.0.1", rtt_ms=1.5),
                ProbeResult(hop="10.0.0.1", rtt_ms=1.25),
                ProbeResult(hop=None, rtt_ms=None),
            ),
            reached=False,
        )

        self.assertEqual(
            format_hop_line(hop),
            " 1   10.0.0.1  1.500 ms  1.250 ms *",
            msg="The hop line must collapse a repeated hop address and mark a timeout with '*'.",
        )


class TestTracerouteRunTraceroute(TestCase):
    """
    The 'run_traceroute' TTL-ladder generator tests (raw socket faked).
    """

    def _clock(self) -> object:
        """
        Build a monotonic clock that advances one millisecond per read.
        """

        ticks = iter(range(1_000_000))

        def time_fn() -> float:
            return next(ticks) * 0.001

        return time_fn

    def test__cli__traceroute__run_walks_hops_until_destination(self) -> None:
        """
        Ensure the generator raises the TTL each hop, records the
        intermediate hops and a timeout, and stops at the destination's
        Echo Reply.

        Reference: RFC 792 (ICMP Time Exceeded / Echo Reply).
        """

        plan: dict[int, tuple[str, str] | None] = {
            1: ("10.0.0.1", "time_exceeded"),
            2: None,
            3: ("10.0.0.3", "reply"),
        }
        sock = _FakeTracerouteSocket(plan)
        profile = traceroute_profile(is_ipv6=False)

        hops = list(
            run_traceroute(
                sock,  # type: ignore[arg-type]
                dest_address="10.0.0.3",
                profile=profile,
                identifier=0x1234,
                max_hops=30,
                probes_per_hop=2,
                timeout=1.0,
                time_fn=self._clock(),  # type: ignore[arg-type]
            )
        )

        self.assertEqual(
            (
                len(hops),
                hops[0].probes[0].hop,
                hops[1].probes[0].hop,
                hops[2].probes[0].hop,
                hops[2].reached,
                sock.ttls[:3],
            ),
            (3, "10.0.0.1", None, "10.0.0.3", True, [1, 2, 3]),
            msg="The trace must walk hop 1, time out at hop 2, reach the destination at hop 3, and stop.",
        )


class TestCliTracerouteCommand(TestCase):
    """
    The 'pytcp traceroute' command-wiring tests (raw socket + generator
    faked, no daemon).
    """

    def _run(self, *argv: str) -> tuple[int, str, str]:
        """
        Run 'main(["traceroute", *argv])', capturing '(exit_code, stdout,
        stderr)'.
        """

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main.main(["traceroute", *argv])
        return code, out.getvalue(), err.getvalue()

    def test__cli__traceroute__command_prints_hops_and_exits_zero(self) -> None:
        """
        Ensure a trace that reaches the destination prints the header and
        each hop line and exits zero.

        Reference: RFC 792 (ICMP Time Exceeded / Echo Reply).
        """

        hops = [
            HopResult(ttl=1, probes=(ProbeResult("10.0.0.1", 1.0),), reached=False),
            HopResult(ttl=2, probes=(ProbeResult("10.0.0.3", 2.0),), reached=True),
        ]
        sock = create_autospec(socket.Socket, spec_set=True)
        with (
            patch.object(cli_main, "resolve_destination", autospec=True, return_value=(False, "10.0.0.3")),
            patch.object(cli_main, "open_traceroute_socket", autospec=True, return_value=sock),
            patch.object(cli_main, "run_traceroute", autospec=True, return_value=iter(hops)),
        ):
            code, out, _err = self._run("example.com")

        self.assertEqual(code, 0, msg="A trace reaching the destination must exit 0.")
        self.assertIn("traceroute to example.com (10.0.0.3)", out, msg="The header must name the destination.")
        self.assertIn("10.0.0.3", out, msg="The reached hop must be printed.")
        sock.close.assert_called_once_with()

    def test__cli__traceroute__command_unreached_exits_one(self) -> None:
        """
        Ensure a trace that never reaches the destination exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        hops = [HopResult(ttl=1, probes=(ProbeResult(None, None),), reached=False)]
        sock = create_autospec(socket.Socket, spec_set=True)
        with (
            patch.object(cli_main, "resolve_destination", autospec=True, return_value=(False, "10.0.0.3")),
            patch.object(cli_main, "open_traceroute_socket", autospec=True, return_value=sock),
            patch.object(cli_main, "run_traceroute", autospec=True, return_value=iter(hops)),
        ):
            code, _out, _err = self._run("example.com")

        self.assertEqual(code, 1, msg="A trace that never reaches the destination must exit 1.")

    def test__cli__traceroute__command_daemon_down_reports_cleanly(self) -> None:
        """
        Ensure a missing daemon raw socket prints the canonical daemon
        diagnostic and exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch.object(cli_main, "resolve_destination", autospec=True, return_value=(False, "10.0.0.3")),
            patch.object(
                cli_main,
                "open_traceroute_socket",
                autospec=True,
                side_effect=FileNotFoundError(2, "No such file or directory"),
            ),
        ):
            code, _out, err = self._run("example.com")

        self.assertEqual(
            (code, "daemon" in err.lower()),
            (1, True),
            msg="A down daemon must exit 1 with a diagnostic mentioning the daemon.",
        )
