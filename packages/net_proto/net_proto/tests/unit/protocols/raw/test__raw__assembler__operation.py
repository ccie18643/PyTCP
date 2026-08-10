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
This module contains tests for the Raw protocol packet assembler operation.

net_proto/tests/unit/protocols/raw/test__raw__assembler__operation.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import EtherType, IpProto, RawAssembler, Tracker
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Raw packet with an empty payload and default ether_type/ip_proto.",
            "_kwargs": {
                "raw__payload": b"",
            },
            "_results": {
                "__len__": 0,
                "__str__": "Raw, len 0",
                "__repr__": "RawAssembler(raw__payload=b'')",
                # Empty payload serialises to zero bytes on the wire.
                "__bytes__": b"",
                "payload": b"",
                "ether_type": EtherType.RAW,
                "ip_proto": IpProto.RAW,
            },
        },
        {
            "_description": "Raw packet carrying a 16-byte ASCII payload with UDP over IPv4 framing.",
            "_kwargs": {
                "raw__payload": b"0123456789ABCDEF",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.UDP,
            },
            "_results": {
                "__len__": 16,
                "__str__": "Raw, len 16",
                "__repr__": "RawAssembler(raw__payload=b'0123456789ABCDEF')",
                # Raw payload passed through verbatim (no checksum recomputation for non-ICMP):
                #   Bytes 0-15 : b"0123456789ABCDEF" (ASCII payload).
                "__bytes__": b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46",
                "payload": b"0123456789ABCDEF",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.UDP,
            },
        },
        {
            "_description": (
                "Raw packet carrying a minimal ICMPv4 Echo Request with zero checksum; "
                "the assembler must pass it through verbatim — Linux SOCK_RAW does NOT "
                "compute the IPv4 transport checksum; the application owns it."
            ),
            "_kwargs": {
                "raw__payload": b"\x08\x00\x00\x00\x00\x01\x00\x01",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.ICMP4,
            },
            "_results": {
                "__len__": 8,
                "__str__": "Raw, len 8",
                "__repr__": "RawAssembler(raw__payload=b'\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01')",
                # ICMPv4 raw payload emitted verbatim (8 bytes) — the zero
                # checksum is NOT recomputed (Linux SOCK_RAW/IPPROTO_ICMP
                # leaves the transport checksum to the application):
                #   Byte  0     : 0x08       -> ICMPv4 type = Echo Request
                #   Byte  1     : 0x00       -> ICMPv4 code = 0
                #   Bytes 2-3   : 0x0000     -> checksum left as the app set it
                #   Bytes 4-5   : 0x0001     -> Echo Request identifier = 1
                #   Bytes 6-7   : 0x0001     -> Echo Request sequence number = 1
                "__bytes__": b"\x08\x00\x00\x00\x00\x01\x00\x01",
                "payload": b"\x08\x00\x00\x00\x00\x01\x00\x01",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.ICMP4,
            },
        },
        {
            "_description": (
                "Raw packet carrying a minimal ICMPv6 Echo Request with zero checksum and "
                "the default (zero) pseudo-header sum; the assembler always computes the "
                "ICMPv6 checksum in-place (RFC 3542 §3.1 — kernel-mandatory) using "
                "pshdr_sum=0."
            ),
            "_kwargs": {
                "raw__payload": b"\x80\x00\x00\x00\x00\x01\x00\x01",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
            "_results": {
                "__len__": 8,
                "__str__": "Raw, len 8",
                "__repr__": "RawAssembler(raw__payload=b'\\x80\\x00\\x00\\x00\\x00\\x01\\x00\\x01')",
                # ICMPv6 Echo Request wire frame emitted by __buffer__ (8 bytes):
                #   Byte  0     : 0x80       -> ICMPv6 type = Echo Request (128)
                #   Byte  1     : 0x00       -> ICMPv6 code = 0
                #   Bytes 2-3   : 0x7ffd     -> checksum auto-computed by __buffer__ over
                #                              the 8-byte payload with pshdr_sum=0
                #   Bytes 4-5   : 0x0001     -> Echo Request identifier = 1
                #   Bytes 6-7   : 0x0001     -> Echo Request sequence number = 1
                "__bytes__": b"\x80\x00\x7f\xfd\x00\x01\x00\x01",
                "payload": b"\x80\x00\x00\x00\x00\x01\x00\x01",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
        },
        {
            "_description": (
                "Raw packet carrying an ICMPv4 Echo Request with a preset checksum; "
                "the assembler passes ICMPv4 through verbatim regardless (Linux "
                "SOCK_RAW never rewrites the IPv4 transport checksum)."
            ),
            "_kwargs": {
                "raw__payload": b"\x08\x00\x12\x34\x00\x01\x00\x01",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.ICMP4,
            },
            "_results": {
                "__len__": 8,
                "__str__": "Raw, len 8",
                "__repr__": "RawAssembler(raw__payload=b'\\x08\\x00\\x124\\x00\\x01\\x00\\x01')",
                # ICMPv4 Echo Request wire frame passed through verbatim:
                #   Byte  0     : 0x08       -> ICMPv4 type = Echo Request
                #   Byte  1     : 0x00       -> ICMPv4 code = 0
                #   Bytes 2-3   : 0x1234     -> app-supplied checksum; ICMPv4 is never
                #                              rewritten by the assembler
                #   Bytes 4-5   : 0x0001     -> identifier = 1
                #   Bytes 6-7   : 0x0001     -> sequence number = 1
                "__bytes__": b"\x08\x00\x12\x34\x00\x01\x00\x01",
                "payload": b"\x08\x00\x12\x34\x00\x01\x00\x01",
                "ether_type": EtherType.IP4,
                "ip_proto": IpProto.ICMP4,
            },
        },
        {
            "_description": (
                "Raw packet carrying an ICMPv6 payload whose checksum is already set to a "
                "non-zero value; the assembler MUST overwrite it with the computed ICMPv6 "
                "checksum (RFC 3542 §3.1 — the kernel always computes ICMPv6, the app "
                "value is ignored)."
            ),
            "_kwargs": {
                "raw__payload": b"\x80\x00\xab\xcd\x00\x01\x00\x01",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
            "_results": {
                "__len__": 8,
                "__str__": "Raw, len 8",
                "__repr__": "RawAssembler(raw__payload=b'\\x80\\x00\\xab\\xcd\\x00\\x01\\x00\\x01')",
                # ICMPv6 Echo Request wire frame — the preset 0xabcd is
                # zeroed and the checksum recomputed (pshdr_sum=0), giving
                # the same 0x7ffd as the zero-checksum case above:
                #   Byte  0     : 0x80       -> ICMPv6 type = Echo Request (128)
                #   Byte  1     : 0x00       -> ICMPv6 code = 0
                #   Bytes 2-3   : 0x7ffd     -> recomputed (overwrites the app's 0xabcd)
                #   Bytes 4-5   : 0x0001     -> identifier = 1
                #   Bytes 6-7   : 0x0001     -> sequence number = 1
                "__bytes__": b"\x80\x00\x7f\xfd\x00\x01\x00\x01",
                "payload": b"\x80\x00\xab\xcd\x00\x01\x00\x01",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
        },
        {
            "_description": (
                "Raw packet carrying a 3-byte payload declared as ICMPv6; because it is "
                "shorter than 4 bytes, the checksum field does not exist and the "
                "payload must be emitted unchanged."
            ),
            "_kwargs": {
                "raw__payload": b"\x80\x00\x00",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
            "_results": {
                "__len__": 3,
                "__str__": "Raw, len 3",
                "__repr__": "RawAssembler(raw__payload=b'\\x80\\x00\\x00')",
                # 3-byte payload — too short to hold a 2-byte checksum at
                # offset 2, so the length guard skips computation and
                # __buffer__ leaves the payload alone:
                #   Byte 0 : 0x80
                #   Byte 1 : 0x00
                #   Byte 2 : 0x00
                "__bytes__": b"\x80\x00\x00",
                "payload": b"\x80\x00\x00",
                "ether_type": EtherType.IP6,
                "ip_proto": IpProto.ICMP6,
            },
        },
        {
            "_description": (
                "Raw packet with a 65535-byte maximum-size payload; verifies that the "
                "assembler places arbitrarily large payloads into a single buffer unchanged."
            ),
            "_kwargs": {
                "raw__payload": b"X" * 65535,
                "ether_type": EtherType.RAW,
                "ip_proto": IpProto.RAW,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "Raw, len 65535",
                "__repr__": f"RawAssembler(raw__payload=b'{'X' * 65535}')",
                # 65535 bytes of ASCII 'X' (0x58); no header, no checksum recomputation
                # (ip_proto is RAW, not ICMP*).
                "__bytes__": b"X" * 65535,
                "payload": b"X" * 65535,
                "ether_type": EtherType.RAW,
                "ip_proto": IpProto.RAW,
            },
        },
    ]
)
class TestRawAssemblerOperation(TestCase):
    """
    The Raw packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the Raw assembler from the parametrized kwargs.
        """

        self._raw__assembler = RawAssembler(**self._kwargs)

    def test__raw__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the payload length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._raw__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__raw__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._raw__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__raw__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._raw__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__raw__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' (via the buffer protocol) returns the expected
        wire bytes, including any ICMPv4/ICMPv6 auto-computed checksum.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._raw__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__raw__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._raw__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__raw__assembler__ether_type(self) -> None:
        """
        Ensure the 'ether_type' property returns the provided EtherType.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._raw__assembler.ether_type,
            self._results["ether_type"],
            msg=f"Unexpected 'ether_type' for case: {self._description}",
        )

    def test__raw__assembler__ip_proto(self) -> None:
        """
        Ensure the 'ip_proto' property returns the provided IpProto.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._raw__assembler.ip_proto,
            self._results["ip_proto"],
            msg=f"Unexpected 'ip_proto' for case: {self._description}",
        )

    def test__raw__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the raw payload verbatim to the
        provided buffer list — the Raw assembler does not re-emit the
        ICMP checksum from 'assemble()', only '__buffer__()' does.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []

        self._raw__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["payload"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__raw__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly one buffer — the raw payload
        — so Ip4/Ip6 wrappers see the Raw packet as a single contiguous
        block.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []

        self._raw__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            1,
            msg="RawAssembler.assemble must append exactly one buffer (the payload).",
        )
        self.assertEqual(
            len(buffers[0]),
            self._results["__len__"],
            msg="The single appended buffer must be the raw payload.",
        )


class TestRawAssemblerDefaults(TestCase):
    """
    Tests for the Raw assembler default-argument contract. The assembler
    accepts every field as a keyword-only optional argument so callers
    can build a 'zero' packet and override only what they need; this
    suite pins those defaults.
    """

    def test__raw__assembler__defaults(self) -> None:
        """
        Ensure the assembler with no arguments produces an empty packet
        with the default EtherType.RAW / IpProto.RAW framing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = RawAssembler()

        self.assertEqual(
            assembler.payload,
            b"",
            msg="Default 'payload' must be empty.",
        )
        self.assertEqual(
            assembler.ether_type,
            EtherType.RAW,
            msg="Default 'ether_type' must be EtherType.RAW.",
        )
        self.assertEqual(
            assembler.ip_proto,
            IpProto.RAW,
            msg="Default 'ip_proto' must be IpProto.RAW.",
        )
        self.assertEqual(
            len(assembler),
            0,
            msg="Default-constructed assembler must have length 0.",
        )
        self.assertEqual(
            bytes(assembler),
            b"",
            msg="Default-constructed assembler must serialise to empty bytes.",
        )


class TestRawAssemblerPshdrSum(TestCase):
    """
    Tests for the interaction between '_ip_proto' and the 'pshdr_sum'
    class attribute during ICMPv6 checksum auto-computation.

    The Raw assembler is used by the IPv6 TX pipeline as a pre-built
    payload carrier; the IPv6 handler sets 'pshdr_sum' on the Raw
    instance just before serialisation so the ICMPv6 checksum can be
    computed without the IPv6 header. These tests pin that contract.
    """

    def test__raw__assembler__icmp6__non_zero_pshdr_sum(self) -> None:
        """
        Ensure a non-zero 'pshdr_sum' is folded into the ICMPv6
        checksum computed by '__buffer__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = RawAssembler(
            raw__payload=b"\x80\x00\x00\x00\x00\x01\x00\x01",
            ether_type=EtherType.IP6,
            ip_proto=IpProto.ICMP6,
        )
        assembler.pshdr_sum = 0x1234

        # ICMPv6 Echo Request wire frame with pshdr_sum=0x1234:
        #   Byte  0     : 0x80       -> ICMPv6 type = Echo Request
        #   Byte  1     : 0x00       -> ICMPv6 code = 0
        #   Bytes 2-3   : 0x6dc9     -> checksum auto-computed with init=0x1234
        #   Bytes 4-5   : 0x0001     -> identifier = 1
        #   Bytes 6-7   : 0x0001     -> sequence number = 1
        self.assertEqual(
            bytes(assembler),
            b"\x80\x00\x6d\xc9\x00\x01\x00\x01",
            msg="ICMPv6 checksum must be auto-computed with init=pshdr_sum.",
        )

    def test__raw__assembler__icmp4__passed_through_verbatim(self) -> None:
        """
        Ensure ICMPv4 raw payload is emitted verbatim regardless of
        'pshdr_sum': Linux SOCK_RAW does not compute the IPv4
        transport checksum, so the assembler never touches it and
        'pshdr_sum' is irrelevant.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = RawAssembler(
            raw__payload=b"\x08\x00\x00\x00\x00\x01\x00\x01",
            ether_type=EtherType.IP4,
            ip_proto=IpProto.ICMP4,
        )
        assembler.pshdr_sum = 0xABCD  # irrelevant — ICMPv4 is never rewritten

        # ICMPv4 Echo Request wire frame emitted verbatim (zero
        # checksum left as the application set it; pshdr_sum unused):
        #   Byte  0     : 0x08       -> ICMPv4 type = Echo Request
        #   Byte  1     : 0x00       -> ICMPv4 code = 0
        #   Bytes 2-3   : 0x0000     -> checksum untouched (app owns it)
        #   Bytes 4-5   : 0x0001     -> identifier = 1
        #   Bytes 6-7   : 0x0001     -> sequence number = 1
        self.assertEqual(
            bytes(assembler),
            b"\x08\x00\x00\x00\x00\x01\x00\x01",
            msg="ICMPv4 raw payload must be passed through verbatim, pshdr_sum ignored.",
        )


class TestRawAssemblerMisc(TestCase):
    """
    The Raw packet assembler miscellaneous functions tests.
    """

    def test__raw__assembler__echo_tracker(self) -> None:
        """
        Ensure the Raw packet assembler 'tracker' property threads the
        provided echo tracker through to the new TX tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        echo_tracker = Tracker(prefix="RX")

        raw__assembler = RawAssembler(echo_tracker=echo_tracker)

        self.assertIs(
            raw__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="'tracker.echo_tracker' must be the provided echo tracker.",
        )

    def test__raw__assembler__tracker_without_echo(self) -> None:
        """
        Ensure the Raw packet assembler creates a TX tracker with no
        echo tracker when 'echo_tracker' is omitted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        raw__assembler = RawAssembler()

        self.assertIsNone(
            raw__assembler.tracker.echo_tracker,
            msg="'tracker.echo_tracker' must be None when no echo tracker is provided.",
        )

    def test__raw__assembler__eq__same_payload(self) -> None:
        """
        Ensure two Raw assemblers with the same payload are equal under
        the Proto '__eq__' contract (which compares '__repr__').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            RawAssembler(raw__payload=b"abc"),
            RawAssembler(raw__payload=b"abc"),
            msg="Two Raw assemblers with the same payload must compare equal.",
        )

    def test__raw__assembler__eq__different_payload(self) -> None:
        """
        Ensure two Raw assemblers with different payloads are not equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            RawAssembler(raw__payload=b"abc"),
            RawAssembler(raw__payload=b"xyz"),
            msg="Two Raw assemblers with different payloads must not compare equal.",
        )

    def test__raw__assembler__eq__different_type(self) -> None:
        """
        Ensure a Raw assembler does not compare equal to an unrelated
        object even if '__repr__' happens to match (the Proto '__eq__'
        short-circuits on 'isinstance').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            RawAssembler(raw__payload=b"abc"),
            "RawAssembler(raw__payload=b'abc')",
            msg="A Raw assembler must not compare equal to a non-Proto object.",
        )

    def test__raw__assembler__hash__matches_eq(self) -> None:
        """
        Ensure equal Raw assemblers share a hash so they are usable as
        dict/set keys.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            hash(RawAssembler(raw__payload=b"abc")),
            hash(RawAssembler(raw__payload=b"abc")),
            msg="Equal Raw assemblers must share a hash.",
        )
