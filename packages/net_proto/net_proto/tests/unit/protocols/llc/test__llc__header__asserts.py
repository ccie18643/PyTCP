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
Constructor-assertion unit tests for the IEEE 802.2 LLC
U-frame header dataclass.

net_proto/tests/unit/protocols/llc/test__llc__header__asserts.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto import LLC__HEADER__LEN, LlcControl, LlcHeader, LlcSap


class TestLlcHeaderAsserts(TestCase):
    """
    The 'LlcHeader.__post_init__' assertions.
    """

    def test__llc__header__defaults_accepted(self) -> None:
        """
        Ensure a minimum-valid LlcHeader (NULL SAPs + UI
        Control) constructs successfully and reports the
        canonical 3-byte length.

        Reference: IEEE 802.2 §3 LLC frame format.
        """

        header = LlcHeader(dsap=LlcSap.NULL, ssap=LlcSap.NULL, control=LlcControl.UI)

        self.assertEqual(
            len(header),
            LLC__HEADER__LEN,
            msg="A valid LlcHeader must report length LLC__HEADER__LEN (3 bytes).",
        )

    def test__llc__header__dsap_not_llc_sap(self) -> None:
        """
        Ensure the 'dsap' field rejects a non-LlcSap value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as ctx:
            LlcHeader(
                dsap="0xAA",  # type: ignore[arg-type]
                ssap=LlcSap.NULL,
                control=LlcControl.UI,
            )

        self.assertIn(
            "must be a LlcSap",
            str(ctx.exception),
            msg="dsap non-LlcSap value must raise an assert citing the LlcSap requirement.",
        )

    def test__llc__header__ssap_not_llc_sap(self) -> None:
        """
        Ensure the 'ssap' field rejects a non-LlcSap value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as ctx:
            LlcHeader(
                dsap=LlcSap.NULL,
                ssap=0xAA,  # type: ignore[arg-type]
                control=LlcControl.UI,
            )

        self.assertIn(
            "must be a LlcSap",
            str(ctx.exception),
            msg="ssap non-LlcSap value must raise an assert citing the LlcSap requirement.",
        )

    def test__llc__header__control_not_llc_control(self) -> None:
        """
        Ensure the 'control' field rejects a non-LlcControl
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as ctx:
            LlcHeader(
                dsap=LlcSap.NULL,
                ssap=LlcSap.NULL,
                control=0x03,  # type: ignore[arg-type]
            )

        self.assertIn(
            "must be a LlcControl",
            str(ctx.exception),
            msg="control non-LlcControl value must raise an assert citing the LlcControl requirement.",
        )

    def test__llc__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent LLC
        header — locks in pack/unpack symmetry across the three
        single-byte fields (DSAP / SSAP / Control).

        Reference: IEEE 802.2 §3 LLC frame format.
        """

        original = LlcHeader(
            dsap=LlcSap.SNAP,
            ssap=LlcSap.SNAP,
            control=LlcControl.UI,
        )

        rebuilt = LlcHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
