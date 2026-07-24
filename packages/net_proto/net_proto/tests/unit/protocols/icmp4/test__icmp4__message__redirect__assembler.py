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
Module contains tests for the ICMPv4 Redirect message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__redirect__assembler.py

ver 3.0.9
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer, Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageRedirect,
    Icmp4RedirectCode,
    Icmp4Type,
)
from net_proto.tests.lib.parameterized import parameterized_class

# Embedded payload — original IPv4 header (20 bytes) + first 8 bytes of
# the triggering UDP datagram, verbatim from the inbound packet per RFC 792.
_EMBEDDED = (
    b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
    b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
    b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Redirect, code 1 (Host), gateway 10.0.1.1, no data.",
            "_kwargs": {
                "code": Icmp4RedirectCode.HOST,
                "gateway": Ip4Address("10.0.1.1"),
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Redirect - Host, gateway 10.0.1.1, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageRedirect(code=<Icmp4RedirectCode.HOST: 1>, "
                    "cksum=0, gateway=Ip4Address('10.0.1.1'), data=b'')"
                ),
                # Type/Code : 5/1, Cksum 0xeffd (computed by assemble()),
                # Gateway 10.0.1.1.
                "__bytes__": b"\x05\x01\xef\xfd\x0a\x00\x01\x01",
                "type": Icmp4Type.REDIRECT,
                "code": Icmp4RedirectCode.HOST,
                "cksum": 0,
                "gateway": Ip4Address("10.0.1.1"),
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Redirect, code 0 (Network), gateway 192.168.1.254, no data.",
            "_kwargs": {
                "code": Icmp4RedirectCode.NETWORK,
                "gateway": Ip4Address("192.168.1.254"),
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Redirect - Network, gateway 192.168.1.254, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageRedirect(code=<Icmp4RedirectCode.NETWORK: 0>, "
                    "cksum=0, gateway=Ip4Address('192.168.1.254'), data=b'')"
                ),
                # Type/Code : 5/0, Cksum 0x3859, Gateway 192.168.1.254.
                "__bytes__": b"\x05\x00\x38\x59\xc0\xa8\x01\xfe",
                "type": Icmp4Type.REDIRECT,
                "code": Icmp4RedirectCode.NETWORK,
                "cksum": 0,
                "gateway": Ip4Address("192.168.1.254"),
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Redirect, code 1 (Host), gateway 10.0.1.1, embedded IP+8 UDP.",
            "_kwargs": {
                "code": Icmp4RedirectCode.HOST,
                "gateway": Ip4Address("10.0.1.1"),
                "data": _EMBEDDED,
            },
            "_results": {
                "__len__": 36,
                "__str__": "ICMPv4 Redirect - Host, gateway 10.0.1.1, len 36 (8+28)",
                "__repr__": (
                    "Icmp4MessageRedirect(code=<Icmp4RedirectCode.HOST: 1>, "
                    "cksum=0, gateway=Ip4Address('10.0.1.1'), "
                    "data=b'E\\x00\\x00!\\x00\\x01\\x00\\x00@\\x11\\xa8l"
                    "\\n\\x00\\x01\\x07\\n\\x00\\x01[\\x03\\xe8\\x07\\xd0"
                    "\\x00\\r\\x124')"
                ),
                # Type/Code : 5/1, Cksum 0x8e02, Gateway 10.0.1.1,
                # then 20-byte IPv4 header + 8 bytes UDP header.
                "__bytes__": b"\x05\x01\x8e\x02\x0a\x00\x01\x01" + _EMBEDDED,
                "type": Icmp4Type.REDIRECT,
                "code": Icmp4RedirectCode.HOST,
                "cksum": 0,
                "gateway": Ip4Address("10.0.1.1"),
                "data": _EMBEDDED,
            },
        },
    ]
)
class TestIcmp4MessageRedirectAssembler(TestCase):
    """
    The ICMPv4 Redirect message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the Redirect message under test in an Icmp4Assembler.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageRedirect(**self._kwargs),
        )

    def test__icmp4__message__redirect__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP4__REDIRECT__LEN plus
        len(data) (after the __post_init__ truncation).

        Reference: RFC 792 (Redirect wire-format length = 8 + data).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical Redirect log line (including
        the human-readable code name and the gateway address).

        Reference: RFC 792 (Redirect codes 0..3, gateway address).
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3 and the gateway address
        at bytes 4-7.

        Reference: RFC 792 (Redirect checksum covers entire ICMP message;
        gateway address occupies bytes 4-7).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp4Type.REDIRECT via the non-init dataclass field).

        Reference: RFC 792 (Redirect type field is 5).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (Redirect code 0..3).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__gateway(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'gateway' field —
        the better-first-hop address the redirect advertises.

        Reference: RFC 792 (Redirect gateway Internet address).
        """

        self.assertEqual(
            cast(Icmp4MessageRedirect, self._icmp4__assembler.message).gateway,
            self._results["gateway"],
            msg=f"Unexpected 'gateway' for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field
        (post-truncation by __post_init__).

        Reference: RFC 792 (Redirect data carries Internet header + first
        8 octets of original datagram).
        """

        self.assertEqual(
            cast(Icmp4MessageRedirect, self._icmp4__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp4__message__redirect__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' yields the same wire bytes as 'bytes()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []
        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(bytes(buffer) for buffer in buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )
