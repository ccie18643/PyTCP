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
'pytcp traceroute' engine — the pure wire helpers, the UDP / ICMP
classifiers, the hop formatter, the 'run_traceroute' TTL-ladder
generator (driven against a faked socket), and the command wiring.

packages/pytcp/pytcp/tests/unit/cli/test__cli__traceroute.py

ver 3.0.8
"""

import argparse
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
    classify_icmp,
    classify_udp,
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


def _v4_icmp_error(*, icmp_type: int, src_port: int, dst_port: int) -> bytes:
    """
    Build a raw-socket IPv4 + ICMP error (Time Exceeded / Destination
    Unreachable) frame embedding a triggering IPv4 + UDP header with the
    given ports.
    """

    embedded = _ip4_header() + struct.pack("!HH", src_port, dst_port) + b"\x00\x00\x00\x00"
    return _ip4_header() + struct.pack("!BBH", icmp_type, 0, 0) + b"\x00\x00\x00\x00" + embedded


def _v4_time_exceeded_icmp(*, identifier: int, sequence: int) -> bytes:
    """
    Build a raw-socket IPv4 + ICMP Time Exceeded frame embedding our
    triggering IPv4 + ICMP Echo Request.
    """

    embedded = _ip4_header() + struct.pack(_ICMP__STRUCT, 8, 0, 0, identifier, sequence)
    return _ip4_header() + struct.pack("!BBH", 11, 0, 0) + b"\x00\x00\x00\x00" + embedded


class _FakeLoopSocket:
    """
    A socket double for the 'run_traceroute' loop: records each TTL set
    and answers per a TTL -> '(hop, marker)' plan (a missing / None entry
    times out), returning the marker as the datagram body so the test's
    classifier can map it.
    """

    def __init__(self, plan: dict[int, tuple[str, str] | None], /) -> None:
        self._plan = plan
        self._ttl = 0
        self.ttls: list[int] = []

    def setsockopt(self, level: int, optname: int, value: int, /) -> None:
        self._ttl = value
        self.ttls.append(value)

    def settimeout(self, value: float | None, /) -> None:
        pass

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        return len(data)

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, tuple[str, int]]:
        entry = self._plan.get(self._ttl)
        if entry is None:
            raise TimeoutError
        hop, marker = entry
        return marker.encode("ascii"), (hop, 0)


class TestTracerouteProfile(TestCase):
    """
    The per-IP-version traceroute profile tests.
    """

    def test__cli__traceroute__profile_ipv4(self) -> None:
        """
        Ensure the IPv4 profile carries Echo 8/0, Time Exceeded 11,
        Destination Unreachable 3, and an included IP header.

        Reference: RFC 792 (ICMP Echo / Time Exceeded / Unreachable).
        """

        profile = traceroute_profile(is_ipv6=False)

        self.assertEqual(
            (profile.echo_reply, profile.time_exceeded, profile.dest_unreachable, profile.ip_header_included),
            (0, 11, 3, True),
            msg="The IPv4 profile must carry Echo 0, Time Exceeded 11, Unreachable 3, and an included IP header.",
        )

    def test__cli__traceroute__profile_ipv6(self) -> None:
        """
        Ensure the IPv6 profile carries Echo 128/129, Time Exceeded 3,
        Destination Unreachable 1, and no included IP header.

        Reference: RFC 4443 (ICMPv6 Echo / Time Exceeded / Unreachable).
        """

        profile = traceroute_profile(is_ipv6=True)

        self.assertEqual(
            (profile.echo_reply, profile.time_exceeded, profile.dest_unreachable, profile.ip_header_included),
            (129, 3, 1, False),
            msg="The IPv6 profile must carry Echo 129, Time Exceeded 3, Unreachable 1, and no included IP header.",
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


class TestTracerouteClassifyIcmp(TestCase):
    """
    The ICMP-mode classifier tests.
    """

    def test__cli__traceroute__classify_icmp_reply_is_reached(self) -> None:
        """
        Ensure a matching Echo Reply classifies as 'reached'.

        Reference: RFC 792 (ICMP Echo Reply).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_echo_reply(identifier=0x1234, sequence=3)

        self.assertEqual(
            classify_icmp(frame, profile=profile, identifier=0x1234, sequence=3),
            "reached",
            msg="A matching Echo Reply must classify as 'reached'.",
        )

    def test__cli__traceroute__classify_icmp_time_exceeded_is_hop(self) -> None:
        """
        Ensure a Time Exceeded embedding our Echo Request classifies as
        'hop'.

        Reference: RFC 792 (ICMP Time Exceeded).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_time_exceeded_icmp(identifier=0x1234, sequence=3)

        self.assertEqual(
            classify_icmp(frame, profile=profile, identifier=0x1234, sequence=3),
            "hop",
            msg="A Time Exceeded embedding our probe must classify as 'hop'.",
        )

    def test__cli__traceroute__parse_probe_response_rejects_foreign_sequence(self) -> None:
        """
        Ensure the underlying parser ignores a reply for a different
        sequence so unrelated ICMP does not corrupt a hop result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_echo_reply(identifier=0x1234, sequence=9)

        self.assertIsNone(
            parse_probe_response(frame, profile=profile, identifier=0x1234, sequence=3),
            msg="A reply for a foreign sequence must be ignored.",
        )


class TestTracerouteClassifyUdp(TestCase):
    """
    The UDP-mode classifier tests.
    """

    def test__cli__traceroute__classify_udp_time_exceeded_is_hop(self) -> None:
        """
        Ensure a Time Exceeded embedding our UDP probe (matching source
        and per-probe destination port) classifies as 'hop'.

        Reference: RFC 792 (ICMP Time Exceeded).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_icmp_error(icmp_type=11, src_port=40000, dst_port=33435)

        self.assertEqual(
            classify_udp(frame, profile=profile, local_port=40000, dest_port=33435),
            "hop",
            msg="A Time Exceeded embedding our UDP probe must classify as 'hop'.",
        )

    def test__cli__traceroute__classify_udp_dest_unreachable_is_reached(self) -> None:
        """
        Ensure a Destination Unreachable embedding our UDP probe
        classifies as 'reached'.

        Reference: RFC 792 (ICMP Destination Unreachable).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_icmp_error(icmp_type=3, src_port=40000, dst_port=33435)

        self.assertEqual(
            classify_udp(frame, profile=profile, local_port=40000, dest_port=33435),
            "reached",
            msg="A Destination Unreachable embedding our UDP probe must classify as 'reached'.",
        )

    def test__cli__traceroute__classify_udp_rejects_foreign_port(self) -> None:
        """
        Ensure an error whose embedded destination port is not our
        probe's is ignored (a different probe or unrelated traffic).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        profile = traceroute_profile(is_ipv6=False)
        frame = _v4_icmp_error(icmp_type=11, src_port=40000, dst_port=33435)

        self.assertIsNone(
            classify_udp(frame, profile=profile, local_port=40000, dest_port=33499),
            msg="An error for a foreign destination port must be ignored.",
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
    The 'run_traceroute' TTL-ladder generator tests (socket faked).
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
        intermediate hops and a timeout, and stops when the destination
        answers.

        Reference: RFC 792 (ICMP Time Exceeded / Unreachable).
        """

        plan: dict[int, tuple[str, str] | None] = {
            1: ("10.0.0.1", "hop"),
            2: None,
            3: ("10.0.0.3", "reached"),
        }
        sock = _FakeLoopSocket(plan)

        hops = list(
            run_traceroute(
                sock,  # type: ignore[arg-type]
                sock,  # type: ignore[arg-type]
                ttl_level=0,
                ttl_optname=2,
                max_hops=30,
                probes_per_hop=2,
                timeout=1.0,
                make_probe=lambda sequence: (b"x", ("10.0.0.3", 33434 + sequence)),
                classify=lambda data, sequence: data.decode("ascii") if data else None,
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


class TestCliTracerouteProbers(TestCase):
    """
    The traceroute send / receive socket selection tests.
    """

    def test__cli__traceroute__icmp_mode_uses_one_raw_socket(self) -> None:
        """
        Ensure '-I' opens a single raw ICMP socket used for both sending
        and receiving.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        icmp_sock = create_autospec(socket.Socket, spec_set=True)
        args = argparse.Namespace(icmp=True)
        with (
            patch.object(cli_main, "open_icmp_socket", autospec=True, return_value=icmp_sock),
            patch.object(cli_main, "open_udp_socket", autospec=True) as udp_open,
        ):
            send_sock, recv_sock, _make, _classify = cli_main._traceroute_probers(
                args, is_ipv6=False, address="10.0.0.3"
            )

        self.assertIs(send_sock, recv_sock, msg="ICMP mode must send and receive on one socket.")
        udp_open.assert_not_called()

    def test__cli__traceroute__udp_mode_uses_udp_send_and_raw_recv(self) -> None:
        """
        Ensure the default UDP mode sends on a bound UDP socket and
        receives on a separate raw ICMP socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        udp_sock = create_autospec(socket.Socket, spec_set=True)
        udp_sock.getsockname.return_value = ("0.0.0.0", 40000)
        icmp_sock = create_autospec(socket.Socket, spec_set=True)
        args = argparse.Namespace(icmp=False)
        with (
            patch.object(cli_main, "open_udp_socket", autospec=True, return_value=udp_sock),
            patch.object(cli_main, "open_icmp_socket", autospec=True, return_value=icmp_sock),
        ):
            send_sock, recv_sock, _make, _classify = cli_main._traceroute_probers(
                args, is_ipv6=False, address="10.0.0.3"
            )

        self.assertEqual(
            (send_sock is udp_sock, recv_sock is icmp_sock),
            (True, True),
            msg="UDP mode must send on the UDP socket and receive on the raw ICMP socket.",
        )


class TestCliTracerouteCommand(TestCase):
    """
    The 'pytcp traceroute' command-wiring tests (probers + generator
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
        each hop line, exits zero, and closes its socket.

        Reference: RFC 792 (ICMP Time Exceeded / Unreachable).
        """

        hops = [
            HopResult(ttl=1, probes=(ProbeResult("10.0.0.1", 1.0),), reached=False),
            HopResult(ttl=2, probes=(ProbeResult("10.0.0.3", 2.0),), reached=True),
        ]
        sock = create_autospec(socket.Socket, spec_set=True)
        with (
            patch.object(cli_main, "resolve_destination", autospec=True, return_value=(False, "10.0.0.3")),
            patch.object(
                cli_main,
                "_traceroute_probers",
                autospec=True,
                return_value=(sock, sock, lambda s: (b"", ("10.0.0.3", 1)), lambda d, s: None),
            ),
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
            patch.object(
                cli_main,
                "_traceroute_probers",
                autospec=True,
                return_value=(sock, sock, lambda s: (b"", ("10.0.0.3", 1)), lambda d, s: None),
            ),
            patch.object(cli_main, "run_traceroute", autospec=True, return_value=iter(hops)),
        ):
            code, _out, _err = self._run("example.com")

        self.assertEqual(code, 1, msg="A trace that never reaches the destination must exit 1.")

    def test__cli__traceroute__command_daemon_down_reports_cleanly(self) -> None:
        """
        Ensure a missing daemon (sockets cannot open) prints the canonical
        daemon diagnostic and exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch.object(cli_main, "resolve_destination", autospec=True, return_value=(False, "10.0.0.3")),
            patch.object(
                cli_main,
                "_traceroute_probers",
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
