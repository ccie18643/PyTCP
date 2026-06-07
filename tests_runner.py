#!/usr/bin/env python3

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
Testslide-style 'unittest' runner for the PyTCP test suites. Mirrors
the on-screen layout testslide used while it was the project's
runner: bold class path, colour-coded indented method names (no
"PASS"/"FAIL" word — colour is the indicator), and a summary block
listing successful / failed / skipped counts.

Colour styling goes through 'click.secho', which is already a runtime
dependency (used by 'net_addr' CLI helpers). ANSI emission is gated
on a TTY check plus the 'NO_COLOR' environment variable.

tests_runner.py

ver 3.0.6
"""

import os
import sys
import time
import unittest
from collections.abc import Callable
from typing import Any, override

import click

# Map outcome -> 'click.style' kwargs for the indented method-name line.
_OUTCOME_STYLES: dict[str, dict[str, Any]] = {
    "pass": {"fg": "green"},
    "fail": {"fg": "red"},
    "error": {"fg": "red"},
    "skip": {"fg": "yellow"},
    "xfail": {"fg": "yellow"},
    "xpass": {"fg": "magenta"},
}


class TestslideStyleResult(unittest.TextTestResult):
    """
    'unittest.TextTestResult' that prints testslide-style two-line
    output per test (bold class path, colour-coded method name) and
    a testslide-style summary block at the end of the run.
    """

    _color: bool
    _current_class_path: str | None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Detect whether the output stream supports ANSI colour (TTY
        check plus 'NO_COLOR' env var) and seed the per-class
        deduplication state used by '_emit'.
        """

        super().__init__(*args, **kwargs)
        self._color = "NO_COLOR" not in os.environ and hasattr(self.stream, "isatty") and bool(self.stream.isatty())
        self._current_class_path = None

    def _secho(self, text: str = "", **kwargs: Any) -> None:
        """
        Write 'text' to 'self.stream' via 'click.secho'. Forwards the
        cached colour decision so click strips ANSI when colour is
        disabled (NO_COLOR or non-TTY) and emits it otherwise.
        """

        click.secho(text, file=self.stream, color=self._color, **kwargs)  # type: ignore[arg-type]

    def _emit(self, test: unittest.TestCase, outcome: str, suffix: str = "") -> None:
        """
        Print one test in the testslide two-line layout: a bold class
        path on a class transition, followed by an indented coloured
        method name (with optional trailing ': <error>' for failures).
        """

        full_id = test.id()
        class_path, _, method = full_id.rpartition(".")

        if class_path != self._current_class_path:
            self._secho(class_path, bold=True)
            self._current_class_path = class_path

        self._secho(f"  {method}{suffix}", **_OUTCOME_STYLES[outcome])
        self.stream.flush()

    @staticmethod
    def _format_exception_short(err: Any) -> str:
        """
        Render an exc_info triple as "<ExceptionType>: <message>" for
        the trailing fragment on a failed-test line.
        """

        exc_type, exc_value, _ = err
        return f"{exc_type.__name__}: {exc_value}"

    @override
    def startTest(self, test: unittest.TestCase) -> None:
        """
        Bypass the base class's "<method> ... " prefix print; the
        per-status hooks below are responsible for all output.
        """

        unittest.TestResult.startTest(self, test)

    @override
    def addSuccess(self, test: unittest.TestCase) -> None:
        """
        Record a passing test and emit a green method-name line.
        """

        unittest.TestResult.addSuccess(self, test)
        self._emit(test, "pass")

    @override
    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record a failing test and emit a red method-name line with
        the trailing exception summary.
        """

        unittest.TestResult.addFailure(self, test, err)
        self._emit(test, "fail", suffix=f": {self._format_exception_short(err)}")

    @override
    def addError(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an unexpected-exception test and emit a red
        method-name line with the trailing exception summary.
        """

        unittest.TestResult.addError(self, test, err)
        self._emit(test, "error", suffix=f": {self._format_exception_short(err)}")

    @override
    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        """
        Record a skipped test and emit a yellow method-name line.
        """

        unittest.TestResult.addSkip(self, test, reason)
        self._emit(test, "skip")

    @override
    def addExpectedFailure(self, test: unittest.TestCase, err: Any) -> None:
        """
        Record an expected-failure test and emit a yellow
        method-name line.
        """

        unittest.TestResult.addExpectedFailure(self, test, err)
        self._emit(test, "xfail")

    @override
    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        """
        Record an unexpected-success test and emit a magenta
        method-name line.
        """

        unittest.TestResult.addUnexpectedSuccess(self, test)
        self._emit(test, "xpass")

    def print_summary(self, elapsed: float) -> None:
        """
        Emit the testslide-style end-of-run summary block: bold
        'Executed N examples in T.Ts:' followed by colour-coded
        Successful / Failed / Skipped / Not executed counters
        (dimmed when zero).
        """

        successful = (
            self.testsRun
            - len(self.failures)
            - len(self.errors)
            - len(self.skipped)
            - len(self.expectedFailures)
            - len(self.unexpectedSuccesses)
        )
        failed = len(self.failures) + len(self.errors)
        skipped = len(self.skipped) + len(self.expectedFailures)
        unexpected = len(self.unexpectedSuccesses)

        def _line(label: str, count: int, color: str) -> None:
            text = f"  {label}: {count}"
            if count:
                self._secho(text, fg=color)
            else:
                self._secho(text, dim=True)

        self._secho()
        self._secho(
            f"Executed {self.testsRun} examples in {elapsed:.1f}s:",
            bold=True,
        )
        _line("Successful", successful, "green")
        _line("Failed", failed, "red")
        _line("Skipped", skipped, "yellow")
        _line("Not executed", 0, "white")
        if unexpected:
            _line("Unexpected pass", unexpected, "magenta")
        self.stream.flush()

    @override
    def printErrors(self) -> None:
        """
        Print a testslide-style 'Failures:' block listing every
        failure / error with its exception summary and traceback.
        Replaces the default unittest dashed-section format.
        """

        if not (self.failures or self.errors):
            return

        self._secho()
        self._secho("Failures:", fg="red")
        self._secho()

        index = 0
        for test, formatted_tb in self.failures + self.errors:
            index += 1
            class_path, _, method = test.id().rpartition(".")
            self._secho(f"  {index}) {class_path}: {method}", bold=True)
            tb_lines = formatted_tb.rstrip("\n").splitlines()
            exception_line = tb_lines[-1] if tb_lines else ""
            self._secho(f"    {index}) {exception_line}", fg="red")
            # Drop the boilerplate 'Traceback (most recent call last):'
            # header — testslide prints just the frame lines.
            frame_lines = tb_lines[:-1]
            if frame_lines and frame_lines[0].startswith("Traceback"):
                frame_lines = frame_lines[1:]
            for line in frame_lines:
                self._secho(line)
            self._secho()

        self.stream.flush()


class TestslideStyleRunner(unittest.TextTestRunner):
    """
    'unittest.TextTestRunner' wired to 'TestslideStyleResult' and a
    testslide-style summary printer. Always runs at verbosity 2 so
    the per-test output is emitted regardless of the caller's flags.
    """

    # Keep the base 'TextTestRunner.resultclass' invariant type
    # ('Callable[..., TextTestResult]') so the narrower concrete
    # subclass is not a covariant override of the mutable attribute.
    resultclass: Callable[..., unittest.TextTestResult] = TestslideStyleResult

    def __init__(self, *args: object, **kwargs: object) -> None:
        """
        Force verbosity=2 so the per-test summary is always emitted.
        """

        kwargs["verbosity"] = 2
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    @override
    def run(self, test: Any) -> Any:
        """
        Run the test suite, then print the testslide-style summary
        block in place of the default 'OK' / 'FAILED (...)' line.
        """

        result = self.resultclass(self.stream, self.descriptions, 2)
        unittest.signals.registerResult(result)
        result.failfast = self.failfast
        result.buffer = self.buffer
        result.tb_locals = self.tb_locals

        start = time.perf_counter()
        try:
            test(result)
        finally:
            elapsed = time.perf_counter() - start

        if isinstance(result, TestslideStyleResult):
            result.printErrors()
            result.print_summary(elapsed)

        return result


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Run the given test files with testslide-style output. "
        "TESTS may be file paths (e.g. 'pytcp/tests/integration/...') "
        "or dotted module names that 'unittest' can import."
    ),
)
@click.argument("tests", nargs=-1, required=True)
@click.option(
    "--failfast",
    "-f",
    is_flag=True,
    default=False,
    help="Stop the run on the first failure or error.",
)
@click.option(
    "--pattern",
    "-k",
    "pattern",
    default=None,
    metavar="PATTERN",
    help="Only run tests whose dotted name contains PATTERN (forwarded to 'unittest -k').",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable ANSI colour output even when stdout is a TTY.",
)
def main(
    *,
    tests: tuple[str, ...],
    failfast: bool,
    pattern: str | None,
    no_color: bool,
) -> None:
    """
    Parse runner-level options and invoke 'unittest.TestProgram' with
    the testslide-style runner. The remaining arguments are the test
    files / modules to run.
    """

    if no_color:
        os.environ["NO_COLOR"] = "1"

    argv: list[str] = [sys.argv[0]]
    if failfast:
        argv.append("--failfast")
    if pattern is not None:
        argv.extend(["-k", pattern])
    argv.extend(tests)

    unittest.TestProgram(
        module=None,
        argv=argv,
        testRunner=TestslideStyleRunner,
        exit=True,
    )


if __name__ == "__main__":
    main()
