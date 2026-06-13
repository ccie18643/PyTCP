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
This module contains unit tests for the daemon-independent parts of
the 'pytcp ping' ICMP Echo engine: the wire-format helpers
('icmp_checksum' / 'build_echo_request' / 'parse_echo_reply' /
'icmp_echo_profile'), the 'run_ping' loop driven over a fake socket,
and the plain-text formatters.

pytcp/tests/unit/cli/test__cli__ping.py

ver 3.0.8
"""

import io
import struct
from contextlib import redirect_stdout
from typing import override
from unittest import TestCase
from unittest.mock import patch

import pytcp.cli.__main__ as cli_main
from pytcp.cli.cli__ping import (
    ICMP__HEADER__STRUCT,
    TIMESTAMP__LEN,
    TIMESTAMP__STRUCT,
    PingOutcome,
    build_echo_request,
    format_ping_line,
    format_ping_summary,
    icmp_checksum,
    icmp_echo_profile,
    parse_echo_reply,
    run_ping,
)


def _echo_reply_bytes(*, icmp_type: int, identifier: int, sequence: int, send_time: float = 1.0) -> bytes:
    """
    Build a bare ICMP Echo Reply message (header + send-timestamp
    payload) for the parser / loop tests.
    """

    return struct.pack(ICMP__HEADER__STRUCT, icmp_type, 0, 0, identifier, sequence) + struct.pack(
        TIMESTAMP__STRUCT, send_time
    )


class TestCliPingProfile(TestCase):
    """
    The ICMP Echo per-version profile tests.
    """

    def test__cli__ping__profile_ipv4_is_echo_8_0_with_checksum(self) -> None:
        """
        Ensure the IPv4 profile carries ICMPv4 Echo Request 8 / Reply 0
        and computes its own checksum (the v4 stack does not).

        Reference: RFC 792 (ICMP Echo / Echo Reply types 8 / 0).
        """

        profile = icmp_echo_profile(is_ipv6=False)

        self.assertEqual(
            (profile.echo_request, profile.echo_reply, profile.compute_checksum),
            (8, 0, True),
            msg="The IPv4 profile must be Echo Request 8 / Reply 0 with application-computed checksum.",
        )

    def test__cli__ping__profile_ipv6_is_echo_128_129_no_checksum(self) -> None:
        """
        Ensure the IPv6 profile carries ICMPv6 Echo Request 128 / Reply
        129 and leaves the checksum to the stack (it covers a
        pseudo-header the application cannot see).

        Reference: RFC 4443 §4 (ICMPv6 Echo Request / Reply types 128 / 129).
        """

        profile = icmp_echo_profile(is_ipv6=True)

        self.assertEqual(
            (profile.echo_request, profile.echo_reply, profile.compute_checksum),
            (128, 129, False),
            msg="The IPv6 profile must be Echo Request 128 / Reply 129 with stack-computed checksum.",
        )


class TestCliPingChecksum(TestCase):
    """
    The RFC 1071 Internet-checksum helper tests.
    """

    def test__cli__ping__checksum_of_known_buffer(self) -> None:
        """
        Ensure 'icmp_checksum' matches the RFC 1071 worked example: the
        one's-complement sum of the 16-bit words 0x0001 0xf203 0xf4f5
        0xf6f7 is 0x220d.

        Reference: RFC 1071 §3 (worked checksum example).
        """

        self.assertEqual(
            icmp_checksum(b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"),
            0x220D,
            msg="icmp_checksum must reproduce the RFC 1071 §3 worked example (0x220d).",
        )

    def test__cli__ping__checksum_validates_to_zero(self) -> None:
        """
        Ensure a buffer with its computed checksum appended re-checksums
        to zero, the receiver's validity property.

        Reference: RFC 1071 §1 (checksum-of-checksummed-data is zero).
        """

        body = b"\x08\x00\x00\x00\x12\x34\x00\x01payload!"
        checksummed = body[:2] + struct.pack("!H", icmp_checksum(body)) + body[4:]

        self.assertEqual(
            icmp_checksum(checksummed),
            0,
            msg="A buffer carrying its own checksum must re-checksum to zero.",
        )


class TestCliPingBuildEchoRequest(TestCase):
    """
    The Echo Request wire-format builder tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a typical IPv4 Echo Request for the field assertions.
        """

        self._profile = icmp_echo_profile(is_ipv6=False)
        self._request = build_echo_request(self._profile, identifier=0x1234, sequence=7, size=56)

    def test__cli__ping__request_header_fields(self) -> None:
        """
        Ensure the built request carries Echo type 8, code 0, and the
        supplied identifier / sequence in the 8-byte ICMP header.

        Reference: RFC 792 (ICMP Echo header layout).
        """

        icmp_type, code, _cksum, identifier, sequence = struct.unpack(ICMP__HEADER__STRUCT, self._request[:8])

        self.assertEqual(
            (icmp_type, code, identifier, sequence),
            (8, 0, 0x1234, 7),
            msg="The Echo Request header must carry type 8 / code 0 / id 0x1234 / seq 7.",
        )

    def test__cli__ping__request_total_length_is_header_plus_size(self) -> None:
        """
        Ensure the request is the 8-byte ICMP header plus 'size' payload
        bytes (the timestamp plus filler).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._request),
            8 + 56,
            msg="The request length must be the 8-byte header plus the 56-byte payload.",
        )

    def test__cli__ping__request_payload_leads_with_send_timestamp(self) -> None:
        """
        Ensure the payload's first 8 bytes are a monotonic send timestamp
        the reply echoes back for the RTT measurement.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        (send_time,) = struct.unpack(TIMESTAMP__STRUCT, self._request[8 : 8 + TIMESTAMP__LEN])

        self.assertGreater(
            send_time,
            0.0,
            msg="The payload must lead with a positive monotonic send timestamp.",
        )

    def test__cli__ping__ipv4_request_checksum_is_valid(self) -> None:
        """
        Ensure the IPv4 request carries a valid ICMP checksum, i.e. the
        whole message re-checksums to zero.

        Reference: RFC 792 (ICMP checksum); RFC 1071 §1.
        """

        self.assertEqual(
            icmp_checksum(self._request),
            0,
            msg="The IPv4 Echo Request must carry a valid checksum (re-checksums to zero).",
        )

    def test__cli__ping__ipv6_request_checksum_left_zero(self) -> None:
        """
        Ensure the IPv6 request leaves the checksum field zero for the
        stack to fill (it covers a pseudo-header the app cannot see).

        Reference: RFC 4443 §2.3 (ICMPv6 checksum covers the pseudo-header).
        """

        request = build_echo_request(icmp_echo_profile(is_ipv6=True), identifier=1, sequence=1, size=16)
        _t, _c, checksum, _id, _seq = struct.unpack(ICMP__HEADER__STRUCT, request[:8])

        self.assertEqual(
            checksum,
            0,
            msg="The IPv6 Echo Request checksum field must be left zero for the stack to fill.",
        )


class TestCliPingParseReply(TestCase):
    """
    The Echo Reply parser tests.
    """

    def test__cli__ping__parse_accepts_matching_reply(self) -> None:
        """
        Ensure a bare ICMP Echo Reply parses to its sequence and echoed
        send timestamp, with no TTL on the cmsg-delivered path.

        Reference: RFC 792 (ICMP Echo Reply).
        """

        reply = _echo_reply_bytes(icmp_type=0, identifier=9, sequence=42, send_time=3.5)

        self.assertEqual(
            parse_echo_reply(reply, echo_reply=0, ip_header_in_payload=False, match_identifier=None),
            (42, None, 3.5),
            msg="A matching Echo Reply must parse to (sequence, None TTL, send_time).",
        )

    def test__cli__ping__parse_rejects_wrong_type(self) -> None:
        """
        Ensure a message whose type is not the expected Echo Reply is
        rejected (returns None), so an Echo Request loopback or an error
        message is not mistaken for a reply.

        Reference: RFC 792 (Echo Reply type discrimination).
        """

        not_a_reply = _echo_reply_bytes(icmp_type=8, identifier=9, sequence=1)

        self.assertIsNone(
            parse_echo_reply(not_a_reply, echo_reply=0, ip_header_in_payload=False, match_identifier=None),
            msg="A non-Echo-Reply type must be rejected by the reply parser.",
        )

    def test__cli__ping__parse_filters_by_identifier_in_raw_mode(self) -> None:
        """
        Ensure that when an identifier filter is supplied (raw-socket
        mode, where the app owns the id), a reply carrying a different
        identifier is rejected.

        Reference: RFC 792 (Echo identifier demultiplexing).
        """

        foreign = _echo_reply_bytes(icmp_type=0, identifier=99, sequence=1)

        self.assertIsNone(
            parse_echo_reply(foreign, echo_reply=0, ip_header_in_payload=False, match_identifier=7),
            msg="A reply whose identifier does not match the filter must be rejected.",
        )

    def test__cli__ping__parse_reads_ttl_from_prepended_ip_header(self) -> None:
        """
        Ensure that on the v4-raw path (IP header prepended) the TTL is
        read from the IPv4 header's byte 8 and the ICMP message is taken
        after the IHL-derived header length.

        Reference: RFC 791 §3.1 (IPv4 IHL / TTL fields).
        """

        ip_header = bytes([0x45, 0x00]) + bytes(6) + bytes([57]) + bytes(11)
        reply = ip_header + _echo_reply_bytes(icmp_type=0, identifier=1, sequence=5, send_time=2.0)

        self.assertEqual(
            parse_echo_reply(reply, echo_reply=0, ip_header_in_payload=True, match_identifier=None),
            (5, 57, 2.0),
            msg="The v4-raw path must read TTL=57 from the prepended IPv4 header.",
        )


class _FakeReplySocket:
    """
    A fake ping socket whose 'recvmsg' returns one scripted Echo Reply
    per sequence (so 'run_ping' yields a reply outcome) and whose other
    methods are inert. The TTL rides an IP_TTL-style cmsg.
    """

    def __init__(self, *, echo_reply: int, ttl: int, cmsg_level: int, cmsg_type: int) -> None:
        self._echo_reply = echo_reply
        self._ttl = ttl
        self._cmsg_level = cmsg_level
        self._cmsg_type = cmsg_type
        self._last_sequence = 0

    def sendto(self, data: bytes, _address: tuple[str, int], /) -> int:
        """Record the sequence from the outbound request and ack the bytes."""
        _t, _c, _k, _id, self._last_sequence = struct.unpack(ICMP__HEADER__STRUCT, data[:8])
        return len(data)

    def settimeout(self, _timeout: float, /) -> None:
        """No-op timeout setter."""

    def recvmsg(self, _bufsize: int, _ancbufsize: int, /) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
        """Return a scripted Echo Reply for the most recently sent sequence."""
        reply = _echo_reply_bytes(icmp_type=self._echo_reply, identifier=0, sequence=self._last_sequence, send_time=0.0)
        ancdata = [(self._cmsg_level, self._cmsg_type, bytes([self._ttl]))]
        return reply, ancdata, 0, ("10.0.1.1", 0)

    def close(self) -> None:
        """No-op close."""


class _FakeTimeoutSocket:
    """
    A fake ping socket whose 'recvmsg' always raises 'TimeoutError', so
    'run_ping' yields a timeout outcome.
    """

    def sendto(self, data: bytes, _address: tuple[str, int], /) -> int:
        """Ack the bytes without recording anything."""
        return len(data)

    def settimeout(self, _timeout: float, /) -> None:
        """No-op timeout setter."""

    def recvmsg(self, _bufsize: int, _ancbufsize: int, /) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
        """Always time out."""
        raise TimeoutError

    def close(self) -> None:
        """No-op close."""


class TestCliPingRunLoop(TestCase):
    """
    The 'run_ping' loop tests over a fake socket.
    """

    def test__cli__ping__run_yields_reply_outcome_with_ttl(self) -> None:
        """
        Ensure a single round over a replying socket yields one non-timed-
        out 'PingOutcome' carrying the cmsg TTL and a non-negative RTT.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        profile = icmp_echo_profile(is_ipv6=False)
        sock = _FakeReplySocket(
            echo_reply=profile.echo_reply,
            ttl=63,
            cmsg_level=profile.ttl_cmsg_level,
            cmsg_type=profile.ttl_cmsg_type,
        )

        outcomes = list(
            run_ping(
                sock,  # type: ignore[arg-type]
                profile,
                address="10.0.1.1",
                identifier=1,
                count=1,
                interval=0.0,
                timeout=1.0,
                size=56,
                use_cmsg=True,
                match_identifier=None,
            )
        )

        self.assertEqual(len(outcomes), 1, msg="A count=1 run must yield exactly one outcome.")
        self.assertFalse(outcomes[0].timed_out, msg="The replying socket must produce a non-timed-out outcome.")
        self.assertEqual(outcomes[0].ttl, 63, msg="The outcome must carry the TTL from the IP_TTL cmsg.")
        self.assertIsNotNone(outcomes[0].rtt_ms, msg="A reply outcome must carry an RTT.")
        assert outcomes[0].rtt_ms is not None  # narrow for the comparison below
        self.assertGreaterEqual(outcomes[0].rtt_ms, 0.0, msg="The outcome must carry a non-negative RTT.")

    def test__cli__ping__run_yields_timeout_outcome(self) -> None:
        """
        Ensure a round over a never-replying socket yields one timed-out
        'PingOutcome' with no TTL or RTT.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        outcomes = list(
            run_ping(
                _FakeTimeoutSocket(),  # type: ignore[arg-type]
                icmp_echo_profile(is_ipv6=False),
                address="10.0.1.1",
                identifier=1,
                count=1,
                interval=0.0,
                timeout=0.0,
                size=56,
                use_cmsg=True,
                match_identifier=None,
            )
        )

        self.assertEqual(
            outcomes,
            [PingOutcome(sequence=1, ttl=None, rtt_ms=None, timed_out=True)],
            msg="A never-replying socket must yield exactly one timed-out outcome.",
        )


class TestCliPingFormatters(TestCase):
    """
    The plain-text ping line / summary formatter tests.
    """

    def test__cli__ping__format_reply_line(self) -> None:
        """
        Ensure a reply outcome renders the Linux-'ping'-style bytes /
        icmp_seq / ttl / time line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        line = format_ping_line(
            PingOutcome(sequence=3, ttl=64, rtt_ms=1.5, timed_out=False), address="10.0.1.1", size=56
        )

        self.assertEqual(
            line,
            "64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=1.50 ms",
            msg="A reply outcome must render the canonical ping reply line.",
        )

    def test__cli__ping__format_timeout_line(self) -> None:
        """
        Ensure a timed-out outcome renders the request-timeout line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        line = format_ping_line(
            PingOutcome(sequence=4, ttl=None, rtt_ms=None, timed_out=True), address="10.0.1.1", size=56
        )

        self.assertEqual(
            line,
            "Request timeout for icmp_seq 4",
            msg="A timed-out outcome must render the request-timeout line.",
        )

    def test__cli__ping__format_summary_with_loss(self) -> None:
        """
        Ensure the summary reports transmitted / received / loss and the
        rtt min/avg/max over the received outcomes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        outcomes = [
            PingOutcome(sequence=1, ttl=64, rtt_ms=1.0, timed_out=False),
            PingOutcome(sequence=2, ttl=None, rtt_ms=None, timed_out=True),
            PingOutcome(sequence=3, ttl=64, rtt_ms=3.0, timed_out=False),
        ]

        self.assertEqual(
            format_ping_summary("host", outcomes),
            "--- host ping statistics ---\n"
            "3 packets transmitted, 2 received, 33% packet loss\n"
            "rtt min/avg/max = 1.00/2.00/3.00 ms",
            msg="The summary must report counts, loss, and rtt min/avg/max.",
        )


class TestCliPingCommand(TestCase):
    """
    The 'pytcp ping' command-wiring tests (socket layer faked, no daemon).
    """

    def _run_ping(self, *argv: str, socket_factory: object) -> tuple[int, str]:
        """
        Run 'main(["ping", *argv])' with 'open_ping_socket' patched to
        return '(socket_factory, use_cmsg=True, match_identifier=None)',
        capturing '(exit_code, stdout)'.
        """

        buffer = io.StringIO()
        with patch.object(cli_main, "open_ping_socket", return_value=(socket_factory, True, None)):
            with redirect_stdout(buffer):
                exit_code = cli_main.main(["ping", *argv])
        return exit_code, buffer.getvalue()

    def test__cli__ping__command_streams_replies_and_exits_zero(self) -> None:
        """
        Ensure 'pytcp ping -c 2 <ipv4>' against a replying socket prints
        the PING banner, one reply line per sequence with the cmsg TTL,
        the statistics block, and exits zero.

        Reference: RFC 792 (ICMP Echo Request / Reply).
        """

        profile = icmp_echo_profile(is_ipv6=False)
        sock = _FakeReplySocket(
            echo_reply=profile.echo_reply,
            ttl=64,
            cmsg_level=profile.ttl_cmsg_level,
            cmsg_type=profile.ttl_cmsg_type,
        )

        exit_code, output = self._run_ping("-c", "2", "-i", "0", "10.0.1.1", socket_factory=sock)

        self.assertEqual(exit_code, 0, msg="A run with replies must exit zero.")
        self.assertIn("PING 10.0.1.1 (10.0.1.1): 56 data bytes", output, msg="The PING banner must be printed.")
        self.assertIn("icmp_seq=1 ttl=64", output, msg="The first reply line must be printed.")
        self.assertIn("icmp_seq=2 ttl=64", output, msg="The second reply line must be printed.")
        self.assertIn("2 packets transmitted, 2 received, 0% packet loss", output, msg="The summary must be printed.")

    def test__cli__ping__command_all_timeouts_exits_one(self) -> None:
        """
        Ensure 'pytcp ping -c 1 <ipv4>' against a never-replying socket
        prints the timeout line and 100% loss, and exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        exit_code, output = self._run_ping(
            "-c", "1", "-i", "0", "-W", "0", "10.0.1.1", socket_factory=_FakeTimeoutSocket()
        )

        self.assertEqual(exit_code, 1, msg="A run where every request timed out must exit non-zero.")
        self.assertIn("Request timeout for icmp_seq 1", output, msg="The timeout line must be printed.")
        self.assertIn("100% packet loss", output, msg="The summary must report 100% loss.")
