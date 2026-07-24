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
Unit tests for the shared 'malpi' echo-reply helper used by the TCP / UDP
echo server examples — the plain-echo behaviour (RFC 862) and the
ASCII-art monkey easter-egg selection ('malpka' / 'malpa' / 'malpi').

pytcp/tests/unit/examples/test__examples__malpi.py

ver 3.0.8
"""

from unittest import TestCase

from examples.lib.malpi import echo_reply, malpa, malpi, malpka


class TestMalpiPayloads(TestCase):
    """
    The 'malpi' easter-egg ASCII-art payload tests.
    """

    def test__malpi__payloads_are_non_empty_and_distinct(self) -> None:
        """
        Ensure the three monkey payloads are non-empty and distinct from one
        another, so each request name maps to its own art.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for name, payload in [("malpka", malpka), ("malpa", malpa), ("malpi", malpi)]:
            with self.subTest(monkey=name):
                self.assertGreater(len(payload), 0, msg=f"The '{name}' payload must be non-empty.")

        self.assertEqual(
            len({malpka, malpa, malpi}),
            3,
            msg="The three monkey payloads must be distinct.",
        )


class TestMalpiEchoReply(TestCase):
    """
    The 'malpi' echo-reply selector tests.
    """

    def test__malpi__plain_message_is_echoed_verbatim(self) -> None:
        """
        Ensure a message that names no monkey is echoed back byte-for-byte,
        including surrounding whitespace (the reply is the original,
        unstripped, message).

        Reference: RFC 862 (Echo Protocol — return the data received).
        """

        self.assertEqual(
            echo_reply(b"hello world\n"),
            b"hello world\n",
            msg="A non-monkey message must be echoed back verbatim (unstripped).",
        )

    def test__malpi__monkey_names_select_the_matching_art(self) -> None:
        """
        Ensure each monkey name in a request selects the matching ASCII-art
        payload, case-insensitively and ignoring surrounding whitespace.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for request, expected, label in [
            (b"malpka", malpka, "malpka"),
            (b"malpa", malpa, "malpa"),
            (b"malpi", malpi, "malpi"),
            (b"  MALPI\n", malpi, "malpi upper/space"),
            (b"please send malpka", malpka, "malpka embedded"),
        ]:
            with self.subTest(case=label):
                self.assertEqual(
                    echo_reply(request),
                    expected,
                    msg=f"Request {request!r} must select the {label} payload.",
                )

    def test__malpi__earlier_name_wins_when_multiple_present(self) -> None:
        """
        Ensure that when a request names more than one monkey, the earlier
        name in the fixed 'malpa' -> 'malpi' test order is the one selected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            echo_reply(b"malpa and malpi"),
            malpa,
            msg="With both names present, 'malpa' must win over 'malpi'.",
        )
