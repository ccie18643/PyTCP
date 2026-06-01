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
This module contains tests for the TCP packet parser operation.

net_proto/tests/unit/protocols/tcp/test__tcp__parser__operation.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import PacketRx, TcpHeader, TcpOptionNop, TcpOptions, TcpParser


@parameterized_class(
    [
        {
            "_description": ("TCP packet with no payload, no options, all flags except RST/FIN set, non-zero urg."),
            # TCP wire frame (20 bytes, header-only):
            #   Bytes 0-1   : 0x3039       -> sport=12345
            #   Bytes 2-3   : 0xd431       -> dport=54321
            #   Bytes 4-7   : 0x075bcd15   -> seq=123456789
            #   Bytes 8-11  : 0x3ade68b1   -> ack=987654321
            #   Bytes 12-13 : 0x51fa       -> hlen=20, flags=NCEUAPS
            #   Bytes 14-15 : 0x2b67       -> win=11111
            #   Bytes 16-17 : 0xaf64       -> cksum=44900
            #   Bytes 18-19 : 0x56ce       -> urg=22222
            "_frame_rx": b"\x30\x39\xd4\x31\x07\x5b\xcd\x15\x3a\xde\x68\xb1\x51\xfa\x2b\x67\xaf\x64\x56\xce",
            "_results": {
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=123456789,
                    ack=987654321,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=True,
                    flag_ece=True,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=True,
                    flag_fin=False,
                    win=11111,
                    cksum=44900,
                    urg=22222,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with no payload, no options, ACK+FIN (connection close).",
            # TCP wire frame (20 bytes, header-only, ACK+FIN):
            #   Bytes 0-1   : 0x0457       -> sport=1111
            #   Bytes 2-3   : 0x08ae       -> dport=2222
            #   Bytes 4-7   : 0x00000d05   -> seq=3333
            #   Bytes 8-11  : 0x0000115c   -> ack=4444
            #   Bytes 12-13 : 0x5011       -> hlen=20, flags=AF
            #   Bytes 14-15 : 0x15b3       -> win=5555
            #   Bytes 16-17 : 0x6ed5       -> cksum=28373
            #   Bytes 18-19 : 0x0000       -> urg=0
            "_frame_rx": b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3\x6e\xd5\x00\x00",
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=True,
                    win=5555,
                    cksum=28373,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP RST packet with no payload and 8 Nop options (hlen=28).",
            # TCP wire frame (28 bytes = 20-byte header + 8-byte Nop options):
            #   Bytes 0-1   : 0x3039       -> sport=12345
            #   Bytes 2-3   : 0xd431       -> dport=54321
            #   Bytes 4-7   : 0x00000000   -> seq=0
            #   Bytes 8-11  : 0x00000000   -> ack=0
            #   Bytes 12-13 : 0x7004       -> hlen=28, flags=R
            #   Bytes 14-15 : 0x2b67       -> win=11111
            #   Bytes 16-17 : 0x5c25       -> cksum=23589
            #   Bytes 18-19 : 0x0000       -> urg=0
            #   Bytes 20-27 : 0x01 * 8     -> 8 Nop padding options
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x00\x00\x00\x00\x00\x00\x00\x70\x04\x2b\x67"
                b"\x5c\x25\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            "_results": {
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=0,
                    ack=0,
                    hlen=28,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=True,
                    flag_syn=False,
                    flag_fin=False,
                    win=11111,
                    cksum=23589,
                    urg=0,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 8)),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with 16-byte payload, 4 Nop options, no flags set.",
            # TCP wire frame (40 bytes = 20-byte header + 4 Nops + 16-byte payload):
            #   Bytes 0-1   : 0xffff       -> sport=65535
            #   Bytes 2-3   : 0xffff       -> dport=65535
            #   Bytes 4-7   : 0xffffffff   -> seq=UINT_32__MAX
            #   Bytes 8-11  : 0xffffffff   -> ack=UINT_32__MAX
            #   Bytes 12-13 : 0x6000       -> hlen=24, flags=none
            #   Bytes 14-15 : 0xffff       -> win=65535
            #   Bytes 16-17 : 0xcf26       -> cksum=53030
            #   Bytes 18-19 : 0xffff       -> urg=65535
            #   Bytes 20-23 : 0x01 0x01 0x01 0x01 -> 4 Nop options
            #   Bytes 24-39 : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x60\x00\xff\xff"
                b"\xcf\x26\xff\xff\x01\x01\x01\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": TcpHeader(
                    sport=65535,
                    dport=65535,
                    seq=4294967295,
                    ack=4294967295,
                    hlen=24,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=65535,
                    cksum=53030,
                    urg=65535,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 4)),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "TCP packet with maximum 65515-byte payload and no options (total 65535).",
            "_frame_rx": (
                b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x51\x58\x15\xb3" b"\xb5\x2d\x00\x00" + b"X" * 65515
            ),
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=False,
                    flag_ece=True,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=5555,
                    cksum=46381,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"X" * 65515,
            },
        },
        {
            "_description": "TCP packet with maximum 65475-byte payload and max 40-byte Nop options.",
            "_frame_rx": (
                b"\x04\x57\x0d\x05\x00\x00\x15\xb3\x00\x00\x1e\x61\xf0\xb8\x00\x00"
                b"\xbd\x39\x27\x0f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" + b"X" * 65475
            ),
            "_results": {
                "header": TcpHeader(
                    sport=1111,
                    dport=3333,
                    seq=5555,
                    ack=7777,
                    hlen=60,
                    flag_ns=False,
                    flag_cwr=True,
                    flag_ece=False,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=0,
                    cksum=48441,
                    urg=9999,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 40)),
                "payload": b"X" * 65475,
            },
        },
    ]
)
class TestTcpParserOperation(TestCase):
    """
    The TCP packet parser operation tests.

    The TCP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the TCP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(self._frame_rx),
            pshdr_sum=0,
        )

    def test__tcp__parser__header(self) -> None:
        """
        Ensure the TCP packet parser decodes the 20-byte fixed header
        into the expected TcpHeader dataclass.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__tcp__parser__options(self) -> None:
        """
        Ensure the TCP packet parser decodes the options area into the
        expected TcpOptions container.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.options,
            self._results["options"],
            msg=f"Unexpected parsed options for case: {self._description}",
        )

    def test__tcp__parser__payload(self) -> None:
        """
        Ensure the TCP packet parser extracts the payload starting at
        'hlen' and ending at 'ip.payload_len'.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            bytes(tcp_parser.payload),
            self._results["payload"],
            msg=f"Unexpected parsed payload for case: {self._description}",
        )

    def test__tcp__parser__packet_rx_tcp(self) -> None:
        """
        Ensure the TCP packet parser installs itself on the PacketRx as
        'packet_rx.tcp'.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertIs(
            self._packet_rx.tcp,
            tcp_parser,
            msg=f"Parser must install itself on packet_rx.tcp for case: {self._description}",
        )

    def test__tcp__parser__packet_rx_frame_advanced_past_hlen(self) -> None:
        """
        Ensure the TCP packet parser advances 'packet_rx.frame' past the
        TCP header so the remaining bytes are the TCP payload.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"Parser must advance packet_rx.frame past hlen for case: {self._description}",
        )
        # Sanity: parser.payload and packet_rx.frame refer to the same
        # payload region after construction.
        self.assertEqual(
            bytes(self._packet_rx.frame),
            bytes(tcp_parser.payload),
            msg=f"packet_rx.frame and parser.payload must match for case: {self._description}",
        )


class TestTcpParserOperation__ReservedBits(TestCase):
    """
    The TCP packet parser must silently accept any value in the three
    reserved bits between 'hlen' and the 'NS' flag, per RFC 9293 §3.1:

        "Reserved (Rsrvd): A 4-bit field reserved for future use.
         Must be zero in generated segments and must be ignored in
         received segments, if corresponding future features are
         unimplemented by the sending or receiving host."

    Wire layout of the 16-bit hlen|flags word (big-endian):

        hlen (4 bits) | rsrvd (3 bits) | NS (1 bit) | CWR (1) | ECE (1)
        | URG (1) | ACK (1) | PSH (1) | RST (1) | SYN (1) | FIN (1)

    The reserved bits occupy positions 9, 10, 11 (mask 0x0E00 of the
    16-bit word, or equivalently bits 1, 2, 3 of byte 12 - mask 0x0E).
    Setting all three to 1 should produce an identical 'TcpHeader' to
    the all-zero baseline, because:

        1. 'TcpHeader' has no field for the reserved bits.
        2. The parser at 'tcp__header.py:182-200' bit-shifts mask out
           hlen and the 9 named flags only - the reserved bits are
           never extracted.
        3. The parser's '_validate_integrity' has no reserved-bit
           check, so a non-zero value does not raise.

    This test locks in the spec-correct "silently ignore" behaviour
    against a future tightening (e.g. someone adding a "reserved bits
    must be zero" assertion to '_validate_integrity').
    """

    # Baseline TCP wire frame: 20 bytes, no payload, no options,
    # FIN+ACK, all reserved bits zero. Same fixture as the second
    # parametrized case in 'TestTcpParserOperation' above:
    #   sport=1111, dport=2222, seq=3333, ack=4444,
    #   hlen=20, flags=AF, win=5555, urg=0
    # Original cksum 0x6ed5 (valid for pshdr_sum=0).
    _BASELINE_FRAME: bytes = b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3\x6e\xd5\x00\x00"

    # Same frame, but with all three reserved bits set:
    #   Bytes 12-13 : 0x5e11 -> hlen=20, rsrvd=0b111, flags=AF
    #                 (was 0x5011 -> rsrvd=0b000)
    # Cksum recomputed: the 16-bit one's-complement sum (without
    # the cksum field) was originally 0x912a; adding 0x0e00 yields
    # 0x9f2a; one's-complement is 0x60d5. Bytes 16-17 : 0x60d5.
    _RSRVD_BITS_FRAME: bytes = b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x5e\x11\x15\xb3\x60\xd5\x00\x00"

    _BASELINE_HEADER: TcpHeader = TcpHeader(
        sport=1111,
        dport=2222,
        seq=3333,
        ack=4444,
        hlen=20,
        flag_ns=False,
        flag_cwr=False,
        flag_ece=False,
        flag_urg=False,
        flag_ack=True,
        flag_psh=False,
        flag_rst=False,
        flag_syn=False,
        flag_fin=True,
        win=5555,
        cksum=0x60D5,
        urg=0,
    )

    def _packet_rx(self, frame: bytes, /) -> PacketRx:
        """
        Wrap the frame in a 'PacketRx' with a stub IP layer carrying
        'payload_len = len(frame)' and 'pshdr_sum = 0', matching the
        parametrized parent's setUp.
        """

        packet_rx = PacketRx(frame)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(frame),
            pshdr_sum=0,
        )
        return packet_rx

    def test__tcp__parser__reserved_bits__set_value_does_not_raise(self) -> None:
        """
        Ensure the TCP parser accepts a frame whose three reserved
        bits are all set, raising no integrity / sanity error. RFC
        9293 §3.1 mandates that received reserved bits 'must be
        ignored', not rejected.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        # Constructing TcpParser runs the full integrity / parse /
        # sanity pipeline. If the reserved bits triggered a check
        # anywhere along the way, this would raise.
        TcpParser(self._packet_rx(self._RSRVD_BITS_FRAME))

    def test__tcp__parser__reserved_bits__set_value_yields_baseline_header(self) -> None:
        """
        Ensure the parsed 'TcpHeader' from a reserved-bits-set frame
        is equal to the parsed 'TcpHeader' from the all-zero baseline
        in every field except 'cksum'. The cksum differs by
        construction (the wire bytes are different so the segment's
        valid checksum is different too); every other field reflects
        what the parser DID extract, and equality there confirms the
        reserved bits had no effect on the parse.

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        baseline_parser = TcpParser(self._packet_rx(self._BASELINE_FRAME))
        rsrvd_parser = TcpParser(self._packet_rx(self._RSRVD_BITS_FRAME))

        # Compare every field except cksum (which legitimately
        # differs by 0x0e00's checksum delta). The 'replace' trick
        # would normally apply, but TcpHeader is frozen; instead
        # we assert field-by-field via a dict view.
        baseline_fields = {
            field: getattr(baseline_parser.header, field)
            for field in baseline_parser.header.__dataclass_fields__
            if field != "cksum"
        }
        rsrvd_fields = {
            field: getattr(rsrvd_parser.header, field)
            for field in rsrvd_parser.header.__dataclass_fields__
            if field != "cksum"
        }
        self.assertEqual(
            rsrvd_fields,
            baseline_fields,
            msg=(
                "Parsed header from a reserved-bits-set frame must "
                "equal the all-zero-baseline header in every field "
                "except 'cksum'. RFC 9293 §3.1: 'must be ignored in "
                "received segments'."
            ),
        )

    def test__tcp__parser__reserved_bits__cksum_field_reflects_wire(self) -> None:
        """
        Ensure the parsed header's 'cksum' value equals the cksum
        on the wire (here 0x60d5) - confirms the test fixture's
        hand-computed checksum is correct and the parser is happy
        with it (no integrity error from a bad checksum would have
        surfaced as a TcpIntegrityError already).

        Reference: RFC 9293 §3.1 (TCP segment parse).
        """

        rsrvd_parser = TcpParser(self._packet_rx(self._RSRVD_BITS_FRAME))

        self.assertEqual(
            rsrvd_parser.header,
            self._BASELINE_HEADER,
            msg=(
                "Parsed header from the reserved-bits-set frame must "
                "match the hand-computed expected header (with "
                "cksum=0x60d5)."
            ),
        )
