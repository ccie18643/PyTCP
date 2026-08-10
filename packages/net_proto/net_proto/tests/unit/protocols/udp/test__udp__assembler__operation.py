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
This module contains tests for the UDP protocol packet assembling functionality.

net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Buffer
from net_proto import UDP__HEADER__LEN, Tracker, UdpAssembler, UdpHeader
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "UDP packet with no payload, maximum port values.",
            "_kwargs": {
                "udp__sport": 65535,
                "udp__dport": 65535,
                "udp__payload": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "UDP 65535 > 65535, len 8 (8+0)",
                "__repr__": "UdpAssembler(header=UdpHeader(sport=65535, dport=65535, plen=8, cksum=0), payload=b'')",
                # UDP wire frame (8 bytes, header-only):
                #   Bytes 0-1 : 0xffff -> sport=65535
                #   Bytes 2-3 : 0xffff -> dport=65535
                #   Bytes 4-5 : 0x0008 -> plen=8 (UDP__HEADER__LEN)
                #   Bytes 6-7 : 0xfff7 -> cksum (computed by assemble())
                "__bytes__": b"\xff\xff\xff\xff\x00\x08\xff\xf7",
                "sport": 65535,
                "dport": 65535,
                "plen": 8,
                "cksum": 0,
                "header": UdpHeader(
                    sport=65535,
                    dport=65535,
                    plen=8,
                    cksum=0,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "UDP packet with 16-byte ASCII payload.",
            "_kwargs": {
                "udp__sport": 12345,
                "udp__dport": 54321,
                "udp__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "UDP 12345 > 54321, len 24 (8+16)",
                "__repr__": (
                    "UdpAssembler(header=UdpHeader(sport=12345, dport=54321, "
                    "plen=24, cksum=0), payload=b'0123456789ABCDEF')"
                ),
                # UDP wire frame (24 bytes = 8-byte header + 16-byte payload):
                #   Bytes 0-1  : 0x3039 -> sport=12345
                #   Bytes 2-3  : 0xd431 -> dport=54321
                #   Bytes 4-5  : 0x0018 -> plen=24
                #   Bytes 6-7  : 0x2ca6 -> cksum (computed by assemble())
                #   Bytes 8-23 : b"0123456789ABCDEF" (ASCII payload)
                "__bytes__": (
                    b"\x30\x39\xd4\x31\x00\x18\x2c\xa6\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "sport": 12345,
                "dport": 54321,
                "plen": 24,
                "cksum": 0,
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=24,
                    cksum=0,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "UDP packet with maximum 65527-byte payload (total 65535).",
            "_kwargs": {
                "udp__sport": 11111,
                "udp__dport": 22222,
                "udp__payload": b"X" * 65527,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "UDP 11111 > 22222, len 65535 (8+65527)",
                "__repr__": (
                    "UdpAssembler(header=UdpHeader(sport=11111, dport=22222, "
                    f"plen=65535, cksum=0), payload=b'{'X' * 65527}')"
                ),
                # UDP wire frame (65535 bytes = 8-byte header + 65527-byte payload):
                #   Bytes 0-1 : 0x2b67 -> sport=11111
                #   Bytes 2-3 : 0x56ce -> dport=22222
                #   Bytes 4-5 : 0xffff -> plen=65535 (UINT_16__MAX)
                #   Bytes 6-7 : 0xb357 -> cksum (computed by assemble())
                #   Bytes 8+  : 65527 bytes of 'X'
                "__bytes__": b"\x2b\x67\x56\xce\xff\xff\xb3\x57" + b"X" * 65527,
                "sport": 11111,
                "dport": 22222,
                "plen": 65535,
                "cksum": 0,
                "header": UdpHeader(
                    sport=11111,
                    dport=22222,
                    plen=65535,
                    cksum=0,
                ),
                "payload": b"X" * 65527,
            },
        },
    ]
)
class TestUdpAssemblerOperation(TestCase):
    """
    The UDP packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the UDP packet assembler from the parametrized kwargs.
        """

        self._udp__assembler = UdpAssembler(**self._kwargs)

    def test__udp__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns header + payload bytes.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            len(self._udp__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__udp__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            str(self._udp__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__udp__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            repr(self._udp__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__udp__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            bytes(self._udp__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__udp__assembler__sport(self) -> None:
        """
        Ensure the 'sport' property returns the provided source port.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.sport,
            self._results["sport"],
            msg=f"Unexpected 'sport' for case: {self._description}",
        )

    def test__udp__assembler__dport(self) -> None:
        """
        Ensure the 'dport' property returns the provided destination port.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.dport,
            self._results["dport"],
            msg=f"Unexpected 'dport' for case: {self._description}",
        )

    def test__udp__assembler__plen(self) -> None:
        """
        Ensure the 'plen' property returns the computed packet length
        (UDP__HEADER__LEN + len(payload)).

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.plen,
            self._results["plen"],
            msg=f"Unexpected 'plen' for case: {self._description}",
        )

    def test__udp__assembler__cksum(self) -> None:
        """
        Ensure the 'cksum' property returns 0 on the assembler (the field
        is populated only inside the __bytes__ / assemble() buffer).

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__udp__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed UdpHeader.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__udp__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload bytes.

        Reference: RFC 768 (UDP datagram wire format).
        """

        self.assertEqual(
            self._udp__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__udp__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header and payload in order and the
        concatenation matches '__bytes__'.

        Reference: RFC 768 (UDP datagram wire format).
        """

        buffers: list[Buffer] = []

        self._udp__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__udp__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers — header then
        payload — so downstream code can locate them by index.

        Reference: RFC 768 (UDP datagram wire format).
        """

        buffers: list[Buffer] = []

        self._udp__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg="UdpAssembler.assemble must append header + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            UDP__HEADER__LEN,
            msg="UdpAssembler.assemble must append the 8-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["payload"]),
            msg="UdpAssembler.assemble must append the payload buffer second.",
        )


class TestUdpAssemblerMisc(TestCase):
    """
    The UDP packet assembler miscellaneous functions tests.
    """

    def test__udp__assembler__echo_tracker(self) -> None:
        """
        Ensure the UDP packet assembler stores the provided echo_tracker
        on its internal Tracker.

        Reference: RFC 768 (UDP datagram wire format).
        """

        echo_tracker = Tracker(prefix="RX")

        udp__assembler = UdpAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            udp__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must carry the provided echo_tracker.",
        )

    def test__udp__assembler__assemble__zero_compute_substituted_with_all_ones(self) -> None:
        """
        Ensure 'assemble()' substitutes the wire value 0xFFFF
        when the computed one's-complement checksum is zero, so
        the on-wire 0x0000 unambiguously means 'sender did not
        compute a checksum'.

        Reference: RFC 768 (computed-zero UDP checksum MUST be
        transmitted as all ones).
        """

        assembler = UdpAssembler(udp__sport=12345, udp__dport=80, udp__payload=b"x")
        buffers: list[Buffer] = []

        with patch(
            "net_proto.protocols.udp.udp__assembler.inet_cksum",
            return_value=0,
        ):
            assembler.assemble(buffers)

        cksum_field = int.from_bytes(bytes(buffers[0])[6:8], "big")
        self.assertEqual(
            cksum_field,
            0xFFFF,
            msg=("Computed-zero UDP checksum must be transmitted as 0xFFFF, " f"not 0x0000. Got: 0x{cksum_field:04x}."),
        )

    def test__udp__assembler__assemble__nonzero_compute_passes_through(self) -> None:
        """
        Ensure 'assemble()' writes a non-zero computed checksum
        to the wire verbatim — the substitution rule only fires
        on a computed zero.

        Reference: RFC 768 (only the zero case is substituted).
        """

        assembler = UdpAssembler(udp__sport=12345, udp__dport=80, udp__payload=b"x")
        buffers: list[Buffer] = []

        with patch(
            "net_proto.protocols.udp.udp__assembler.inet_cksum",
            return_value=0x1234,
        ):
            assembler.assemble(buffers)

        cksum_field = int.from_bytes(bytes(buffers[0])[6:8], "big")
        self.assertEqual(
            cksum_field,
            0x1234,
            msg=("Non-zero computed UDP checksum must be transmitted unchanged. " f"Got: 0x{cksum_field:04x}."),
        )

    def test__udp__base__bytes__zero_compute_substituted_with_all_ones(self) -> None:
        """
        Ensure 'bytes(assembler)' (the single-buffer __buffer__
        path on Udp base) applies the same RFC 768 zero-to-all-
        ones substitution as the multi-buffer 'assemble()' path.

        Reference: RFC 768 (computed-zero UDP checksum MUST be
        transmitted as all ones — applies on every TX path).
        """

        assembler = UdpAssembler(udp__sport=12345, udp__dport=80, udp__payload=b"x")

        with patch(
            "net_proto.protocols.udp.udp__base.inet_cksum",
            return_value=0,
        ):
            wire = bytes(assembler)

        cksum_field = int.from_bytes(wire[6:8], "big")
        self.assertEqual(
            cksum_field,
            0xFFFF,
            msg=(
                "Computed-zero UDP checksum from __buffer__ must be transmitted as 0xFFFF, "
                f"not 0x0000. Got: 0x{cksum_field:04x}."
            ),
        )

    def test__udp__base__bytes__nonzero_compute_passes_through(self) -> None:
        """
        Ensure 'bytes(assembler)' writes a non-zero computed
        checksum verbatim — the substitution only fires on a
        computed zero.

        Reference: RFC 768 (only the zero case is substituted).
        """

        assembler = UdpAssembler(udp__sport=12345, udp__dport=80, udp__payload=b"x")

        with patch(
            "net_proto.protocols.udp.udp__base.inet_cksum",
            return_value=0xABCD,
        ):
            wire = bytes(assembler)

        cksum_field = int.from_bytes(wire[6:8], "big")
        self.assertEqual(
            cksum_field,
            0xABCD,
            msg=(
                "Non-zero computed UDP checksum from __buffer__ must be transmitted unchanged. "
                f"Got: 0x{cksum_field:04x}."
            ),
        )

    def test__udp__assembler__defaults(self) -> None:
        """
        Ensure the assembler with no arguments produces a minimal valid
        8-byte zeroed-out UDP header with an empty payload.

        Reference: RFC 768 (UDP datagram wire format).
        """

        assembler = UdpAssembler()

        self.assertEqual(
            assembler.sport,
            0,
            msg="Default 'sport' must be 0.",
        )
        self.assertEqual(
            assembler.dport,
            0,
            msg="Default 'dport' must be 0.",
        )
        self.assertEqual(
            assembler.plen,
            UDP__HEADER__LEN,
            msg="Default 'plen' must be UDP__HEADER__LEN (8).",
        )
        self.assertEqual(
            assembler.cksum,
            0,
            msg="Default 'cksum' must be 0.",
        )
        self.assertEqual(
            bytes(assembler.payload),
            b"",
            msg="Default 'payload' must be empty.",
        )
        self.assertEqual(
            len(assembler),
            UDP__HEADER__LEN,
            msg="Default-constructed assembler must serialize to 8 bytes (header only).",
        )


class TestUdpAssemblerNoCksum(TestCase):
    """
    The UDP assembler RFC 6935 no-checksum (alternative-mode) tests.
    """

    def test__udp__assembler__no_cksum_emits_zero(self) -> None:
        """
        Ensure constructing the assembler with udp__no_cksum=True emits
        the literal wire checksum 0x0000 (the alternative zero-checksum
        mode), bypassing the standard one's-complement computation.

        Reference: RFC 6935 §5 (zero-checksum mode emits literal 0x0000).
        """

        assembler = UdpAssembler(udp__sport=1000, udp__dport=2000, udp__payload=b"hello", udp__no_cksum=True)

        self.assertEqual(
            bytes(assembler)[6:8],
            b"\x00\x00",
            msg="udp__no_cksum=True must emit a literal 0x0000 checksum.",
        )

    def test__udp__assembler__default_computes_nonzero_cksum(self) -> None:
        """
        Ensure the default (udp__no_cksum=False) computes a real
        non-zero checksum for the same datagram, contrasting with the
        zero-checksum mode.

        Reference: RFC 768 (the default UDP checksum is computed over the datagram).
        """

        assembler = UdpAssembler(udp__sport=1000, udp__dport=2000, udp__payload=b"hello")

        self.assertNotEqual(
            bytes(assembler)[6:8],
            b"\x00\x00",
            msg="The default assembler must compute a non-zero checksum for this datagram.",
        )
