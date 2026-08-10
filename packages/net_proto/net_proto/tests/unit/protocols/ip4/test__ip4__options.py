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
Module contains tests for the IPv4 options support code.

net_proto/tests/unit/protocols/ip4/test__ip4__options.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Ip4IntegrityError,
    Ip4OptionCipso,
    Ip4OptionEol,
    Ip4OptionLsrr,
    Ip4OptionNop,
    Ip4OptionRouterAlert,
    Ip4OptionRr,
    Ip4Options,
    Ip4OptionSsrr,
    Ip4OptionTimestamp,
    Ip4OptionTimestampFlag,
    Ip4OptionType,
    Ip4OptionUnknown,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ip4Options with three Nops and a trailing Eol.",
            "_args": [
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionEol(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "nop, nop, nop, eol",
                "__repr__": "Ip4Options(options=[Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionEol()])",
                # IPv4 options wire format:
                #   Byte 0: 0x01 (Ip4OptionType.NOP)
                #   Byte 1: 0x01 (Ip4OptionType.NOP)
                #   Byte 2: 0x01 (Ip4OptionType.NOP)
                #   Byte 3: 0x00 (Ip4OptionType.EOL)
                "__bytes__": b"\x01\x01\x01\x00",
                "__bool__": True,
            },
        },
        {
            "_description": "Ip4Options with an unknown option followed by Nops.",
            "_args": [
                Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"\xaa\xbb"),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
            ],
            "_results": {
                "__len__": 8,
                "__str__": "unk-255-4, nop, nop, nop, nop",
                "__repr__": (
                    f"Ip4Options(options=[Ip4OptionUnknown(type={Ip4OptionType.from_int(255)!r}, "
                    "len=4, data=b'\\xaa\\xbb'), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop()])"
                ),
                # IPv4 options wire format:
                #   Bytes 0-3: 0xff 0x04 0xaa 0xbb (UNKNOWN_255, len=4, data=0xaabb)
                #   Bytes 4-7: 0x01 0x01 0x01 0x01 (four Ip4OptionType.NOP bytes)
                "__bytes__": b"\xff\x04\xaa\xbb\x01\x01\x01\x01",
                "__bool__": True,
            },
        },
        {
            "_description": "Empty Ip4Options container.",
            "_args": [],
            "_results": {
                "__len__": 0,
                "__str__": "",
                "__repr__": "Ip4Options(options=[])",
                "__bytes__": b"",
                "__bool__": False,
            },
        },
    ]
)
class TestIp4OptionsAssembler(TestCase):
    """
    The Ip4Options container assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the Ip4Options container from the parametrized option list.
        """

        self._ip4_options = Ip4Options(*self._args)

    def test__ip4_options__len(self) -> None:
        """
        Ensure '__len__()' returns the sum of the per-option lengths.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            len(self._ip4_options),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip4_options__str(self) -> None:
        """
        Ensure '__str__()' returns the comma-joined per-option log strings.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            str(self._ip4_options),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip4_options__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            repr(self._ip4_options),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip4_options__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the concatenated wire bytes.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            bytes(self._ip4_options),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip4_options__bool(self) -> None:
        """
        Ensure '__bool__()' is True iff the container is non-empty.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            bool(self._ip4_options),
            self._results["__bool__"],
            msg=f"Unexpected __bool__ for case: {self._description}",
        )


class TestIp4OptionsSequenceProtocol(TestCase):
    """
    The Ip4Options inherited sequence-protocol tests (__iter__,
    __getitem__, __contains__, __eq__, and index).
    """

    @override
    def setUp(self) -> None:
        """
        Build a mixed Nop/Eol fixture so every protocol method has at
        least one present and at least one absent member to probe.
        """

        self._nop = Ip4OptionNop()
        self._eol = Ip4OptionEol()
        self._unknown = Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"")
        self._options = Ip4Options(self._nop, self._nop, self._eol)

    def test__ip4_options__iter(self) -> None:
        """
        Ensure iterating Ip4Options yields the stored options in order.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            list(self._options),
            [self._nop, self._nop, self._eol],
            msg="Iteration must yield stored options in insertion order.",
        )

    def test__ip4_options__getitem(self) -> None:
        """
        Ensure indexing returns the option at the requested position.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            self._options[0],
            self._nop,
            msg="Ip4Options[0] must return the first option.",
        )
        self.assertEqual(
            self._options[-1],
            self._eol,
            msg="Ip4Options[-1] must return the last option.",
        )

    def test__ip4_options__contains__present(self) -> None:
        """
        Ensure 'in' returns True for a present option.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertIn(
            self._eol,
            self._options,
            msg="Ip4Options must report a present Eol option via 'in'.",
        )

    def test__ip4_options__contains__absent(self) -> None:
        """
        Ensure 'in' returns False for an absent option.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertNotIn(
            self._unknown,
            self._options,
            msg="Ip4Options must report an absent unknown option via 'in'.",
        )

    def test__ip4_options__eq(self) -> None:
        """
        Ensure __eq__ compares underlying option lists.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            self._options,
            Ip4Options(self._nop, self._nop, self._eol),
            msg="Equal-content Ip4Options must compare equal.",
        )
        self.assertNotEqual(
            self._options,
            Ip4Options(self._nop, self._eol),
            msg="Unequal-content Ip4Options must compare not equal.",
        )
        self.assertNotEqual(
            self._options,
            [self._nop, self._nop, self._eol],
            msg="Ip4Options must not compare equal to a plain list of options.",
        )

    def test__ip4_options__index(self) -> None:
        """
        Ensure 'index' returns the position of the first matching option.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            self._options.index(self._eol),
            2,
            msg="Ip4Options.index must return the position of a present option.",
        )


@parameterized_class(
    [
        {
            "_description": "Parse three Nops and a trailing Eol.",
            # IPv4 options wire format:
            #   Byte 0: 0x01 (NOP)
            #   Byte 1: 0x01 (NOP)
            #   Byte 2: 0x01 (NOP)
            #   Byte 3: 0x00 (EOL) -> parser stops here
            "_buffer": b"\x01\x01\x01\x00",
            "_expected": Ip4Options(
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionEol(),
            ),
        },
        {
            "_description": "Parse Nops followed by an Eol, trailing padding ignored.",
            # IPv4 options wire format:
            #   Byte 0: 0x01 (NOP)
            #   Byte 1: 0x00 (EOL) -> parser stops here
            #   Bytes 2-3: 0xff 0xff (padding past EOL, never inspected)
            "_buffer": b"\x01\x00\xff\xff",
            "_expected": Ip4Options(Ip4OptionNop(), Ip4OptionEol()),
        },
        {
            "_description": "Parse an unknown option followed by padding Nops.",
            # IPv4 options wire format:
            #   Bytes 0-3: 0xff 0x04 0xaa 0xbb (UNKNOWN_255, len=4, data=0xaabb)
            #   Bytes 4-7: 0x01 0x01 0x01 0x01 (four NOPs)
            "_buffer": b"\xff\x04\xaa\xbb\x01\x01\x01\x01",
            "_expected": Ip4Options(
                Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"\xaa\xbb"),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
            ),
        },
        {
            "_description": "Parse an empty options buffer.",
            "_buffer": b"",
            "_expected": Ip4Options(),
        },
    ]
)
class TestIp4OptionsParser(TestCase):
    """
    The Ip4Options.from_buffer round-trip tests.
    """

    _description: str
    _buffer: bytes
    _expected: Ip4Options

    def test__ip4_options__from_buffer(self) -> None:
        """
        Ensure from_buffer parses the buffer into the expected option
        sequence, stopping at the first Eol and dispatching unknown
        type bytes to Ip4OptionUnknown.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        self.assertEqual(
            Ip4Options.from_buffer(memoryview(self._buffer)),
            self._expected,
            msg=f"Unexpected parse result for case: {self._description}",
        )


class TestIp4OptionsValidateIntegrity(TestCase):
    """
    The Ip4Options.validate_integrity tests. The validator is run by
    Ip4Parser over the *entire* IPv4 header (starting at offset
    IP4__HEADER__LEN = 20) so the fixtures below prepend a 20-byte
    filler to place the options at the expected offset.
    """

    _HEADER_FILLER = b"\x00" * 20

    def test__ip4_options__validate_integrity__happy_path(self) -> None:
        """
        Ensure a well-formed options buffer (Nop-Nop-Eol + padding)
        passes validation without raising.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        # Frame layout: 20 filler header bytes + NOP + NOP + EOL + padding.
        # hlen covers the first 24 bytes, so validator stops at EOL.
        frame = self._HEADER_FILLER + b"\x01\x01\x00\x00"

        Ip4Options.validate_integrity(frame=frame, hlen=24)

    def test__ip4_options__validate_integrity__empty_options(self) -> None:
        """
        Ensure hlen == IP4__HEADER__LEN (no options at all) passes
        validation without raising.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        Ip4Options.validate_integrity(frame=self._HEADER_FILLER, hlen=20)

    def test__ip4_options__validate_integrity__eol_before_end(self) -> None:
        """
        Ensure an Eol byte short-circuits the validator; bytes past the
        Eol are not inspected.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        # The 0xff byte at offset 22 would normally trigger the
        # "option length must be greater than 1" branch (0x00 at
        # offset 23 is the putative length byte) — the Eol at offset
        # 20 short-circuits before the validator looks at them.
        frame = self._HEADER_FILLER + b"\x00\xff\x00\x00"

        Ip4Options.validate_integrity(frame=frame, hlen=24)

    def test__ip4_options__validate_integrity__option_length_too_small(self) -> None:
        """
        Ensure the validator raises Ip4IntegrityError when an unknown
        option declares a length less than 2.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        # Options: 0xff 0x01 0x00 0x00 -> unknown option, len=1 (<2).
        frame = self._HEADER_FILLER + b"\xff\x01\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Options.validate_integrity(frame=frame, hlen=24)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 option length must be greater than 1. Got: 1.",
            msg="Unexpected integrity-error message for option length < 2.",
        )

    def test__ip4_options__validate_integrity__option_overruns_header(self) -> None:
        """
        Ensure the validator raises Ip4IntegrityError when an unknown
        option declares a length that extends past the header.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        # Options: 0xff 0x05 ... -> declared len=5 starting at offset
        # 20, which would reach offset 25 > hlen=24.
        frame = self._HEADER_FILLER + b"\xff\x05\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Options.validate_integrity(frame=frame, hlen=24)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 option length must not extend past the header length. "
            "Got: offset=25, hlen=24",
            msg="Unexpected integrity-error message for option overrun.",
        )


class TestIp4OptionCopyFlag(TestCase):
    """
    The 'Ip4Option.copy_flag' property tests — RFC 791 §3.1
    "copy flag" (high bit of the option-type byte) drives the
    per-option preservation rule on fragmentation.
    """

    def test__copy_flag__eol__false(self) -> None:
        """
        Ensure End-of-Option-List (type 0) reports
        copy_flag=False — type byte high bit is 0.

        Reference: RFC 791 §3.1 (option-type copy flag = bit 0
        of the option-type byte; type 0 = 0b00000000).
        """

        self.assertFalse(
            Ip4OptionEol().copy_flag,
            msg="EOL (type 0) must have copy_flag=False.",
        )

    def test__copy_flag__nop__false(self) -> None:
        """
        Ensure No-Operation (type 1) reports copy_flag=False.

        Reference: RFC 791 §3.1 (option-type copy flag; type 1 = 0b00000001).
        """

        self.assertFalse(
            Ip4OptionNop().copy_flag,
            msg="NOP (type 1) must have copy_flag=False.",
        )

    def test__copy_flag__rr__false(self) -> None:
        """
        Ensure Record Route (type 7) reports copy_flag=False —
        the RR data only belongs in the first fragment, not
        replicated across the chain.

        Reference: RFC 791 §3.1 (option-type copy flag; type 7 = 0b00000111).
        """

        option = Ip4OptionRr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertFalse(
            option.copy_flag,
            msg="RR (type 7) must have copy_flag=False.",
        )

    def test__copy_flag__timestamp__false(self) -> None:
        """
        Ensure Timestamp (type 68) reports copy_flag=False.

        Reference: RFC 791 §3.1 (option-type copy flag; type 68 = 0b01000100).
        """

        from net_proto.protocols.ip4.options.ip4__option__timestamp import Ip4TimestampEntry

        option = Ip4OptionTimestamp(
            pointer=5,
            overflow=0,
            flag=Ip4OptionTimestampFlag.TS_ONLY,
            entries=[Ip4TimestampEntry(timestamp=0)],
        )
        self.assertFalse(
            option.copy_flag,
            msg="Timestamp (type 68) must have copy_flag=False.",
        )

    def test__copy_flag__lsrr__true(self) -> None:
        """
        Ensure Loose Source and Record Route (type 131)
        reports copy_flag=True — source-route information must
        appear on every fragment for the routing decision to
        work.

        Reference: RFC 791 §3.1 (option-type copy flag; type 131 = 0b10000011).
        """

        option = Ip4OptionLsrr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertTrue(
            option.copy_flag,
            msg="LSRR (type 131) must have copy_flag=True.",
        )

    def test__copy_flag__ssrr__true(self) -> None:
        """
        Ensure Strict Source and Record Route (type 137)
        reports copy_flag=True.

        Reference: RFC 791 §3.1 (option-type copy flag; type 137 = 0b10001001).
        """

        option = Ip4OptionSsrr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertTrue(
            option.copy_flag,
            msg="SSRR (type 137) must have copy_flag=True.",
        )

    def test__copy_flag__router_alert__true(self) -> None:
        """
        Ensure Router Alert (type 148) reports copy_flag=True —
        every fragment of a router-alert datagram must trigger
        the every-hop slow-path examination, so the option must
        propagate.

        Reference: RFC 791 §3.1 (option-type copy flag; type 148 = 0b10010100).
        Reference: RFC 2113 (Router Alert defined with copy_flag=1).
        """

        self.assertTrue(
            Ip4OptionRouterAlert().copy_flag,
            msg="Router Alert (type 148) must have copy_flag=True.",
        )

    def test__copy_flag__cipso__true(self) -> None:
        """
        Ensure CIPSO (type 134) reports copy_flag=True — the
        security label must appear on every fragment for a
        labelling-aware receiver to enforce policy.

        Reference: RFC 791 §3.1 (option-type copy flag; type 134 = 0b10000110).
        """

        option = Ip4OptionCipso(doi=1, tags=[])
        self.assertTrue(
            option.copy_flag,
            msg="CIPSO (type 134) must have copy_flag=True.",
        )

    def test__copy_flag__unknown_high_bit_set__true(self) -> None:
        """
        Ensure an unknown option type with the high bit set
        reports copy_flag=True — the rule applies to ALL
        options including ones PyTCP does not natively type,
        consistent with the on-the-wire encoding.

        Reference: RFC 791 §3.1 (copy flag applies to every option type).
        """

        # Unknown type 0x80 = 128 with high bit set.
        option = Ip4OptionUnknown(type=Ip4OptionType.from_int(0x80), data=b"")
        self.assertTrue(
            option.copy_flag,
            msg="Unknown option with high-bit-set type must have copy_flag=True.",
        )

    def test__copy_flag__unknown_high_bit_clear__false(self) -> None:
        """
        Ensure an unknown option type with the high bit clear
        reports copy_flag=False.

        Reference: RFC 791 §3.1 (copy flag applies to every option type).
        """

        # Unknown type 0x40 = 64 with high bit clear.
        option = Ip4OptionUnknown(type=Ip4OptionType.from_int(0x40), data=b"")
        self.assertFalse(
            option.copy_flag,
            msg="Unknown option with high-bit-clear type must have copy_flag=False.",
        )


class TestIp4OptionsWithCopyFlag(TestCase):
    """
    The 'Ip4Options.with_copy_flag' filter tests — used by the
    TX fragmenter to compute the copy-flag-1 subset that needs
    to appear on every fragment per RFC 791 §3.1.
    """

    def _build_mixed_options(self) -> Ip4Options:
        """Construct an Ip4Options instance with mixed copy-flag values."""

        return Ip4Options(
            Ip4OptionLsrr(pointer=4, route=[Ip4Address("0.0.0.0")]),  # copy=True
            Ip4OptionRr(pointer=4, route=[Ip4Address("0.0.0.0")]),  # copy=False
            Ip4OptionRouterAlert(),  # copy=True
            Ip4OptionNop(),  # copy=False
        )

    def test__with_copy_flag__true__returns_copy_true_options(self) -> None:
        """
        Ensure 'with_copy_flag(True)' returns an Ip4Options
        containing only the options whose copy_flag is True —
        the subset that the TX fragmenter must place on every
        fragment beyond the first.

        Reference: RFC 791 §3.1 (copy flag = 1 → propagate on every fragment).
        """

        filtered = self._build_mixed_options().with_copy_flag(True)

        self.assertEqual(
            [type(o).__name__ for o in filtered],
            ["Ip4OptionLsrr", "Ip4OptionRouterAlert"],
            msg="with_copy_flag(True) must return only copy=True options in source order.",
        )

    def test__with_copy_flag__false__returns_copy_false_options(self) -> None:
        """
        Ensure 'with_copy_flag(False)' returns the
        complementary subset — the options that only belong
        on the first fragment.

        Reference: RFC 791 §3.1 (copy flag = 0 → first fragment only).
        """

        filtered = self._build_mixed_options().with_copy_flag(False)

        self.assertEqual(
            [type(o).__name__ for o in filtered],
            ["Ip4OptionRr", "Ip4OptionNop"],
            msg="with_copy_flag(False) must return only copy=False options in source order.",
        )

    def test__with_copy_flag__empty_input__empty_output(self) -> None:
        """
        Ensure an empty 'Ip4Options' filtered by either flag
        value returns an empty 'Ip4Options' — boundary case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        empty = Ip4Options()
        self.assertEqual(
            len(empty.with_copy_flag(True)),
            0,
            msg="with_copy_flag(True) on empty must return empty.",
        )
        self.assertEqual(
            len(empty.with_copy_flag(False)),
            0,
            msg="with_copy_flag(False) on empty must return empty.",
        )

    def test__with_copy_flag__returns_new_instance(self) -> None:
        """
        Ensure 'with_copy_flag' returns a new 'Ip4Options'
        rather than mutating the source — the filter must be
        non-destructive so the TX fragmenter can keep the
        full original options for the first fragment.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = self._build_mixed_options()
        source_repr_before = repr(source)

        _ = source.with_copy_flag(True)

        self.assertEqual(
            repr(source),
            source_repr_before,
            msg="with_copy_flag must not mutate the source Ip4Options.",
        )


class TestIp4OptionsLookupProperties(TestCase):
    """
    The Ip4Options container lookup-property tests.
    """

    def _options_with(self, *options: Any) -> Ip4Options:
        """
        Build an Ip4Options carrying the supplied options.
        """

        return Ip4Options(*options)

    def test__ip4_options__lsrr__present(self) -> None:
        """
        Ensure the 'lsrr' property returns the first Lsrr option from
        the container when present.

        Reference: RFC 791 §3.1 (Loose Source and Record Route).
        """

        option = Ip4OptionLsrr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertIs(
            self._options_with(Ip4OptionNop(), option).lsrr,
            option,
            msg="Ip4Options.lsrr must return the Lsrr option when present.",
        )

    def test__ip4_options__ssrr__present(self) -> None:
        """
        Ensure the 'ssrr' property returns the first Ssrr option from
        the container when present.

        Reference: RFC 791 §3.1 (Strict Source and Record Route).
        """

        option = Ip4OptionSsrr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertIs(
            self._options_with(option).ssrr,
            option,
            msg="Ip4Options.ssrr must return the Ssrr option when present.",
        )

    def test__ip4_options__router_alert__present(self) -> None:
        """
        Ensure the 'router_alert' property returns the first Router
        Alert option from the container when present.

        Reference: RFC 2113 (Router Alert option).
        """

        option = Ip4OptionRouterAlert()
        self.assertIs(
            self._options_with(option).router_alert,
            option,
            msg="Ip4Options.router_alert must return the option when present.",
        )

    def test__ip4_options__rr__present(self) -> None:
        """
        Ensure the 'rr' property returns the first Record Route option
        from the container when present.

        Reference: RFC 791 §3.1 (Record Route).
        """

        option = Ip4OptionRr(pointer=4, route=[Ip4Address("0.0.0.0")])
        self.assertIs(
            self._options_with(option).rr,
            option,
            msg="Ip4Options.rr must return the Rr option when present.",
        )

    def test__ip4_options__timestamp__present(self) -> None:
        """
        Ensure the 'timestamp' property returns the first Timestamp
        option from the container when present.

        Reference: RFC 791 §3.1 (Timestamp).
        """

        from net_proto.protocols.ip4.options.ip4__option__timestamp import Ip4TimestampEntry

        option = Ip4OptionTimestamp(
            pointer=5, overflow=0, flag=Ip4OptionTimestampFlag.TS_ONLY, entries=[Ip4TimestampEntry(timestamp=0)]
        )
        self.assertIs(
            self._options_with(option).timestamp,
            option,
            msg="Ip4Options.timestamp must return the Timestamp option when present.",
        )

    def test__ip4_options__cipso__present(self) -> None:
        """
        Ensure the 'cipso' property returns the first CIPSO option from
        the container when present.

        Reference: FIPS-188 §A (Commercial IP Security Option).
        """

        option = Ip4OptionCipso(doi=1, tags=[])
        self.assertIs(
            self._options_with(option).cipso,
            option,
            msg="Ip4Options.cipso must return the Cipso option when present.",
        )

    def test__ip4_options__lookup__none_when_absent(self) -> None:
        """
        Ensure every lookup property returns None on a container that
        carries no matching option.

        Reference: RFC 791 §3.1 (IPv4 options block).
        """

        empty = self._options_with(Ip4OptionNop())
        for name in ("lsrr", "ssrr", "router_alert", "rr", "timestamp", "cipso"):
            with self.subTest(prop=name):
                self.assertIsNone(
                    getattr(empty, name),
                    msg=f"Ip4Options.{name} must be None when the option is absent.",
                )
