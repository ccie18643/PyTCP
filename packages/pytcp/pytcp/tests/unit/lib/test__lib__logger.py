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
This module contains tests for the 'log' function.

pytcp/tests/unit/lib/test__lib__logger.py

ver 3.0.8
"""

import io
import time
from unittest import TestCase
from unittest.mock import patch

from pytcp.lib.logger import LOG__START_TIME, log


class TestLoggerStartTime(TestCase):
    """
    The 'logger.LOG__START_TIME' module constant tests.
    """

    def test__logger__start_time_is_float(self) -> None:
        """
        Ensure 'LOG__START_TIME' was captured as a float at import time,
        so timestamp deltas computed inside 'log()' stay numeric.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            LOG__START_TIME,
            float,
            msg="logger.LOG__START_TIME must be a float captured at module import.",
        )

    def test__logger__start_time_not_in_future(self) -> None:
        """
        Ensure 'LOG__START_TIME' is not set in the future relative to
        the current wall-clock reading — guards against a typo that
        would swap 'time.time()' for some other arithmetic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertLessEqual(
            LOG__START_TIME,
            time.time(),
            msg="logger.LOG__START_TIME must be <= the current wall-clock time.",
        )


class TestLoggerChannelGate(TestCase):
    """
    The 'log()' channel-gating tests.
    """

    def test__logger__channel_not_in_log_channel__returns_false(self) -> None:
        """
        Ensure 'log()' returns False and writes nothing when the channel
        is not in 'LOG__CHANNEL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stream = io.StringIO()

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", stream),
        ):
            result = log("disabled-channel", "irrelevant message")

        self.assertFalse(
            result,
            msg="log() must return False when the channel is disabled.",
        )
        self.assertEqual(
            stream.getvalue(),
            "",
            msg="log() must not write to the output stream when the channel is disabled.",
        )

    def test__logger__channel_in_log_channel__returns_true(self) -> None:
        """
        Ensure 'log()' returns True and writes a non-empty line when the
        channel is enabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stream = io.StringIO()

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", stream),
        ):
            result = log("stack", "hello")

        self.assertTrue(
            result,
            msg="log() must return True when the channel is enabled.",
        )
        self.assertNotEqual(
            stream.getvalue(),
            "",
            msg="log() must write to the output stream when the channel is enabled.",
        )


class TestLoggerPlainOutput(TestCase):
    """
    The 'log()' non-debug output-formatting tests.
    """

    def setUp(self) -> None:
        """
        Build a StringIO sink for each test and patch the three stack
        configuration constants before the call.
        """

        self._stream = io.StringIO()

    def test__logger__plain_message_ends_with_newline(self) -> None:
        """
        Ensure 'log()' uses 'print()' semantics — the written payload
        ends with a trailing newline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "hello")

        self.assertTrue(
            self._stream.getvalue().endswith("\n"),
            msg="log() output must end with a newline (it uses print()).",
        )

    def test__logger__plain_message_contains_channel_upper(self) -> None:
        """
        Ensure the channel name is rendered upper-cased and padded to
        seven characters — the canonical '<b>{channel.upper():7}</>'
        format in the source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "hello")

        self.assertIn(
            "STACK  ",
            self._stream.getvalue(),
            msg="log() must render the channel name upper-cased and padded to width 7.",
        )

    def test__logger__plain_message_contains_message(self) -> None:
        """
        Ensure the caller-supplied message text appears verbatim in the
        emitted line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "hello world sentinel")

        self.assertIn(
            "hello world sentinel",
            self._stream.getvalue(),
            msg="log() must render the caller-supplied message verbatim.",
        )

    def test__logger__plain_message_replaces_style_tokens(self) -> None:
        """
        Ensure all style tokens (e.g. '<g>', '</>') are replaced by their
        ANSI escape sequences before output.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "styled")

        output = self._stream.getvalue()

        self.assertNotIn(
            "<g>",
            output,
            msg="log() must substitute the '<g>' style token before output.",
        )
        self.assertNotIn(
            "</>",
            output,
            msg="log() must substitute the '</>' style token before output.",
        )
        self.assertIn(
            "\33[32m",
            output,
            msg="log() must emit the ANSI green escape for the '<g>' style token.",
        )
        self.assertIn(
            "\33[0m",
            output,
            msg="log() must emit the ANSI reset escape for the '</>' style token.",
        )

    def test__logger__plain_message_substitutes_caller_message_styles(self) -> None:
        """
        Ensure style tokens embedded in the caller's message are also
        substituted (the replacement loop covers the whole line, not just
        the header).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "<WARN>pay attention</>")

        output = self._stream.getvalue()

        self.assertNotIn(
            "<WARN>",
            output,
            msg="log() must substitute in-message style tokens before output.",
        )
        self.assertIn(
            "\33[1m\33[93m",
            output,
            msg="log() must emit the ANSI escape for an in-message '<WARN>' token.",
        )

    def test__logger__plain_message_omits_caller_info(self) -> None:
        """
        Ensure the non-debug path does not include the 'ClassName.method'
        caller segment that the debug path would add.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", False),
            patch("pytcp.stack.LOG__OUTPUT", self._stream),
        ):
            log("stack", "payload")

        self.assertNotIn(
            "TestLoggerPlainOutput.",
            self._stream.getvalue(),
            msg="Non-debug log() output must not include a 'ClassName.method' caller segment.",
        )


class TestLoggerDebugOutput(TestCase):
    """
    The 'log()' debug-mode output-formatting tests.
    """

    def test__logger__debug_includes_caller_class_and_method(self) -> None:
        """
        Ensure the debug path formats a 'ClassName.methodName' segment
        using 'inspect.stack()' — the caller must be an instance method
        so the inspected frame has 'self' in its locals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stream = io.StringIO()

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", True),
            patch("pytcp.stack.LOG__OUTPUT", stream),
        ):
            log("stack", "debug-payload")

        output = stream.getvalue()

        self.assertIn(
            "TestLoggerDebugOutput.test__logger__debug_includes_caller_class_and_method",
            output,
            msg="Debug-mode log() must include the caller 'ClassName.methodName' segment.",
        )
        self.assertIn(
            "debug-payload",
            output,
            msg="Debug-mode log() must still render the caller-supplied message.",
        )

    def test__logger__debug_inspect_depth_can_be_tuned(self) -> None:
        """
        Ensure the 'inspect_depth' keyword lets a wrapper push the frame
        lookup one level deeper. The canonical use case is a thin helper
        that still wants the real caller's class/method in the log line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stream = io.StringIO()

        def _wrapper() -> None:
            """
            Forward to 'log()' with depth+1 so the inspected frame points
            at this test method, not the wrapper itself.
            """

            log("stack", "depth-payload", inspect_depth=2)

        with (
            patch("pytcp.stack.LOG__CHANNEL", {"stack"}),
            patch("pytcp.stack.LOG__DEBUG", True),
            patch("pytcp.stack.LOG__OUTPUT", stream),
        ):
            _wrapper()

        output = stream.getvalue()

        self.assertIn(
            "TestLoggerDebugOutput.test__logger__debug_inspect_depth_can_be_tuned",
            output,
            msg="inspect_depth=2 must make 'log()' look past its immediate caller.",
        )


class TestLoggerSignature(TestCase):
    """
    The 'log()' public signature tests.
    """

    def test__logger__channel_and_message_are_positional_only(self) -> None:
        """
        Ensure 'channel' and 'message' are positional-only (they appear
        before the '/' in the signature). Passing them as keywords must
        raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            log(channel="stack", message="bad")  # type: ignore[call-arg]

    def test__logger__inspect_depth_is_keyword_only(self) -> None:
        """
        Ensure 'inspect_depth' is keyword-only (after the '*'). Passing
        it positionally must raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            log("stack", "msg", 1)  # type: ignore[misc]
