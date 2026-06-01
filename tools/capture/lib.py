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
This module contains the shared capture harness: configuration,
process lifecycle, readiness waits, tshark capture/decode, and the
host-side IPv6 peer helper used by every scenario command.

tools/capture/lib.py

ver 3.0.8
"""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

_ROOT = Path(__file__).resolve().parents[2]

# Filtered out of the stack-log highlight view: per-packet ring
# tracing and the raw Ethernet line that every frame emits.
_LOG_NOISE = re.compile(r"RX-RING|TX-RING|^ *[0-9.]+ \| ETHER")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# The service-scenario stack-log highlight pattern (TCP/UDP echo).
SERVICE_LOG_RE = (
    r"Starting the service|Socket created, bound|bind\(\) call failed|"
    r"listening mode|Inbound connection|Received [0-9]+ bytes|"
    r"Sent [0-9]+ bytes|DROPPED__|Failed to send|Unable to sent"
)


class CaptureError(click.ClickException):
    """
    A capture precondition or readiness wait failed.
    """


@dataclass(kw_only=True, slots=True)
class Config:
    """
    Resolved runtime configuration for a single capture run.
    """

    iface: str
    ip4: str
    gw4: str
    ip6: str
    gw6: str
    port: int
    peer: str
    peer6: str
    claim_timeout: int
    bind_timeout: int
    raw: bool
    keep: bool
    loss: float | None
    delay_ms: float | None
    reorder: float | None
    duplicate: float | None
    corrupt: float | None
    expect_log: tuple[str, ...]
    expect_wire: tuple[str, ...]
    expect_client: tuple[str, ...]

    @property
    def ip4_addr(self) -> str:
        """
        Get the bare IPv4 address (no prefix length).
        """

        return self.ip4.split("/", 1)[0]

    @property
    def ip6_addr(self) -> str:
        """
        Get the bare IPv6 address (no prefix length).
        """

        return self.ip6.split("/", 1)[0]


def common_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Stack the shared, env-var-backed click options every scenario
    accepts onto the decorated command callback.
    """

    options = [
        click.option("--iface", envvar="IFACE", default="tap7", show_default=True),
        click.option("--ip4", envvar="IP4", default="192.168.1.77/24", show_default=True),
        click.option("--gw4", envvar="GW4", default="192.168.1.1", show_default=True),
        click.option("--ip6", envvar="IP6", default="fd00:1::77/64", show_default=True),
        click.option("--gw6", envvar="GW6", default="", show_default=True),
        click.option("--port", envvar="PORT", type=int, default=7, show_default=True),
        click.option("--peer", envvar="PEER", default="", help="Host-side IPv4 (icmp); auto-detected if empty."),
        click.option("--peer6", envvar="PEER6", default="fd00:1::1", show_default=True),
        click.option("--claim-timeout", envvar="CLAIM_TIMEOUT", type=int, default=60, show_default=True),
        click.option("--bind-timeout", envvar="BIND_TIMEOUT", type=int, default=90, show_default=True),
        click.option("--raw", is_flag=True, default=False, help="Dump the full unfiltered tshark summary."),
        click.option("--keep", is_flag=True, default=False, help="Keep the pcap and print its path."),
    ]
    # Note: the tc netem impairment (--loss/--delay-ms/...) and the
    # e2e expectation assertions (--expect-*) are run-wide concerns
    # and live as GLOBAL group options (see tools/capture/__main__);
    # make_config() merges them from the click context.
    for option in reversed(options):
        func = option(func)
    return func


def make_config(**kwargs: Any) -> Config:
    """
    Build a Config from the per-scenario common options merged
    with the run-wide global options (impairment / expectations)
    stashed on the click context by the top-level group.
    """

    ctx = click.get_current_context(silent=True)
    run_options: dict[str, Any] = dict(ctx.obj) if ctx is not None and ctx.obj else {}
    kwargs = {**kwargs, **run_options}
    fields = {
        "iface",
        "ip4",
        "gw4",
        "ip6",
        "gw6",
        "port",
        "peer",
        "peer6",
        "claim_timeout",
        "bind_timeout",
        "raw",
        "keep",
        "loss",
        "delay_ms",
        "reorder",
        "duplicate",
        "corrupt",
        "expect_log",
        "expect_wire",
        "expect_client",
    }
    return Config(**{key: value for key, value in kwargs.items() if key in fields})


class Harness:
    """
    The capture harness: owns the example + tshark subprocesses,
    the temp workspace, and the host-side IPv6 peer address, and
    tears all of them down on context exit.
    """

    def __init__(self, config: Config, /) -> None:
        """
        Initialize the harness for a single capture run.
        """

        self._cfg = config
        self._tmp = Path(tempfile.mkdtemp(prefix="pytcp-cap-"))
        self._pcap = self._tmp / "cap.pcap"
        self._log = self._tmp / "stack.log"
        self._out = self._tmp / "client.out"
        self._svc: subprocess.Popen[bytes] | None = None
        self._cap: subprocess.Popen[bytes] | None = None
        self._host_if: str | None = None
        self._host_v6_added = False
        self._netem_if: str | None = None
        # Captured transcript text, keyed by section, for the
        # --expect-* assertions evaluated on context exit.
        self._captured: dict[str, str] = {"log": "", "wire": "", "client": ""}

    # -- lifecycle --------------------------------------------------

    def __enter__(self) -> "Harness":
        """
        Run preflight checks and enter the capture context.
        """

        if os.geteuid() != 0:
            raise CaptureError("must run as root (packet capture + TAP need it)")
        if shutil.which("tshark") is None:
            raise CaptureError("tshark not installed")
        if not (_ROOT / "venv" / "bin" / "python").exists():
            raise CaptureError("venv python not found (run: make venv)")
        if subprocess.run(["ip", "link", "show", self._cfg.iface], capture_output=True).returncode != 0:
            raise CaptureError(f"interface {self._cfg.iface} missing (run: make tap7)")
        self._apply_netem()
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        """
        Tear down every subprocess and the temp workspace, then —
        if the scenario body did not raise — evaluate the
        --expect-* assertions (universal across all scenarios; no
        per-scenario wiring needed).
        """

        self._kill(self._svc, signal.SIGINT, hard_after=1.0)
        self._kill(self._cap, signal.SIGTERM, hard_after=1.0)
        subprocess.run(["pkill", "-9", "-f", r"examples\."], capture_output=True)
        if self._host_v6_added and self._host_if is not None:
            subprocess.run(
                ["ip", "-6", "addr", "del", f"{self._cfg.peer6}/64", "dev", self._host_if],
                capture_output=True,
            )
        if self._netem_if is not None:
            subprocess.run(
                ["tc", "qdisc", "del", "dev", self._netem_if, "root"],
                capture_output=True,
            )
        if self._cfg.keep:
            keep = Path(tempfile.gettempdir()) / self._pcap.name
            shutil.copy2(self._pcap, keep)
            click.echo(f"\n[kept pcap: {keep}]")
        shutil.rmtree(self._tmp, ignore_errors=True)
        if exc_type is None:
            self.check_or_exit()

    @staticmethod
    def _kill(proc: subprocess.Popen[bytes] | None, sig: int, /, *, hard_after: float) -> None:
        """
        Signal a process, then SIGKILL it if it does not exit.
        """

        if proc is None or proc.poll() is not None:
            return
        proc.send_signal(sig)
        try:
            proc.wait(timeout=hard_after)
        except subprocess.TimeoutExpired:
            proc.kill()

    def _host_iface(self) -> str:
        """
        Auto-detect the host-side interface (the one carrying the
        host's own non-loopback IPv4); cached after first lookup.
        """

        if self._host_if is not None:
            return self._host_if
        probe = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
        ).stdout
        for line in probe.splitlines():
            parts = line.split()
            if len(parts) > 1 and parts[1] != "lo":
                self._host_if = parts[1]
                return self._host_if
        raise CaptureError("could not determine the host-side interface")

    def _apply_netem(self) -> None:
        """
        Install a tc netem qdisc on the host interface if any
        impairment option was given; reversed on context exit.
        """

        cfg = self._cfg
        spec: list[str] = []
        if cfg.delay_ms is not None or cfg.reorder is not None:
            # netem reorder requires a (non-zero) delay to act on.
            spec += ["delay", f"{cfg.delay_ms if cfg.delay_ms is not None else 10}ms"]
        if cfg.reorder is not None:
            spec += ["reorder", f"{cfg.reorder}%"]
        if cfg.loss is not None:
            spec += ["loss", f"{cfg.loss}%"]
        if cfg.duplicate is not None:
            spec += ["duplicate", f"{cfg.duplicate}%"]
        if cfg.corrupt is not None:
            spec += ["corrupt", f"{cfg.corrupt}%"]
        if not spec:
            return
        if shutil.which("tc") is None:
            raise CaptureError("tc not installed (iproute2) — needed for --loss/--delay/...")
        iface = self._host_iface()
        result = subprocess.run(
            ["tc", "qdisc", "add", "dev", iface, "root", "netem", *spec],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise CaptureError(f"failed to apply netem on {iface}: {result.stderr.strip()}")
        self._netem_if = iface
        click.echo(f"=== netem on {iface}: {' '.join(spec)} ===")

    # -- subprocess control ----------------------------------------

    def start_capture(self, bpf: str, /) -> None:
        """
        Start tshark as the capture engine writing the pcap; it is
        flushed and closed by a graceful SIGTERM on teardown.
        """

        self._cap = subprocess.Popen(
            ["tshark", "-i", self._cfg.iface, "-f", bpf, "-w", str(self._pcap)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)

    def start_example(self, *module_args: str) -> None:
        """
        Spawn an example module (the stack or an echo service),
        redirecting its combined output to the run's log file.
        """

        env = os.environ | {"PYTHONPATH": str(_ROOT)}
        with self._log.open("wb") as log:
            self._svc = subprocess.Popen(
                [str(_ROOT / "venv" / "bin" / "python"), "-u", "-m", *module_args],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )

    def stop_example(self) -> None:
        """
        Stop the example, then the capture (SIGTERM so tshark
        flushes and closes the savefile cleanly).
        """

        self._kill(self._svc, signal.SIGINT, hard_after=2.0)
        self._svc = None
        self._kill(self._cap, signal.SIGTERM, hard_after=1.0)
        self._cap = None

    # -- readiness / output ----------------------------------------

    def wait_for(self, pattern: str, timeout: int, /) -> None:
        """
        Block until a line matching 'pattern' appears in the stack
        log, or fail after 'timeout' seconds.
        """

        rx = re.compile(pattern)
        for _ in range(timeout):
            if self._log.exists() and rx.search(self._log.read_text(errors="replace")):
                return
            time.sleep(1)
        raise CaptureError(f"timed out after {timeout}s waiting for: {pattern}")

    def log_highlights(self, pattern: str, max_lines: int = 18, /) -> None:
        """
        Print the matching, de-noised, ANSI-stripped stack-log
        lines under a section header.
        """

        click.echo("=== stack log ===")
        rx = re.compile(pattern)
        shown = 0
        for line in self._log.read_text(errors="replace").splitlines():
            line = _ANSI.sub("", line)
            if rx.search(line) and not _LOG_NOISE.search(line):
                click.echo(line)
                shown += 1
                if shown >= max_lines:
                    break
        # Expectations evaluate against the FULL log, not just the
        # highlighted subset, so an --expect-log can assert on any
        # line the stack emitted.
        self._captured["log"] = self._log.read_text(errors="replace")

    def print_client_output(self, header: str, /) -> None:
        """
        Print the captured client (nc / ping) output verbatim.
        """

        click.echo(f"=== {header} ===")
        if self._out.exists():
            text = self._out.read_text(errors="replace")
            self._captured["client"] = text
            click.echo(text.rstrip("\n"))

    def wire(self, *tshark_args: str) -> None:
        """
        Decode the captured pcap with tshark and print it; '--raw'
        forces the full unfiltered packet summary instead.
        """

        click.echo()
        click.echo(f"=== wire capture ({self._cfg.iface}) ===")
        args = ["tshark", "-r", str(self._pcap)]
        if not self._cfg.raw:
            args += list(tshark_args)
        out = subprocess.run(args, capture_output=True, text=True).stdout.strip()
        if not out:
            out = subprocess.run(
                ["tshark", "-r", str(self._pcap)],
                capture_output=True,
                text=True,
            ).stdout.strip()
        self._captured["wire"] = out
        click.echo(out or "(no packets captured)")

    # -- drivers ----------------------------------------------------

    def add_host_v6(self) -> None:
        """
        Add a ULA peer address to the auto-detected host interface
        so the host can reach the stack's static IPv6; removed on
        context exit.
        """

        iface = self._host_iface()
        existing = subprocess.run(
            ["ip", "-6", "-o", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
        ).stdout
        if self._cfg.peer6 not in existing:
            subprocess.run(
                ["ip", "-6", "addr", "add", f"{self._cfg.peer6}/64", "dev", iface],
                check=True,
            )
            self._host_v6_added = True
            time.sleep(2)

    def detect_peer4(self) -> str:
        """
        Return the configured host-side IPv4, or auto-detect the
        host's own non-loopback IPv4 when none was supplied.
        """

        if self._cfg.peer:
            return self._cfg.peer
        probe = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
        ).stdout
        for line in probe.splitlines():
            parts = line.split()
            if len(parts) > 3 and parts[1] != "lo":
                return parts[3].split("/", 1)[0]
        return "?"

    def ping(self, target: str, /, *, ipv6: bool, count: int, size: int | None = None) -> str:
        """
        Run 'ping' at the target, capture its output to the run
        file, and return the host-side summary line.
        """

        cmd = ["ping", "-6" if ipv6 else "-4", "-c", str(count), "-W", "1"]
        if size is not None:
            cmd += ["-s", str(size)]
        cmd.append(target)
        result = subprocess.run(cmd, capture_output=True, text=True)
        self._out.write_text(result.stdout + result.stderr)
        return result.stdout + result.stderr

    def drive_monkeys(
        self,
        target: str,
        /,
        *,
        ipv6: bool,
        udp: bool,
        payload: str,
        graceful: bool,
    ) -> None:
        """
        Drive the ASCII-monkeys exchange against the echo service
        with 'nc'. TCP uses a graceful service-initiated close by
        sending 'payload' and 'quit' as separate messages; the
        '--no-graceful' variant coalesces them to reproduce the
        idle-timeout RST. UDP is a single connectionless datagram.
        """

        base = ["nc"]
        if ipv6:
            base.append("-6")
        if udp:
            stdin = f"{payload}\n".encode()
            cmd = ["timeout", "12", *base, "-u", "-w8", target, str(self._cfg.port)]
        elif graceful:
            stdin = b""  # fed via a shell pipeline below for the sleep gap
            cmd = ["timeout", "18", *base, "-w12", target, str(self._cfg.port)]
        else:
            stdin = f"{payload}\nquit\n".encode()
            cmd = ["timeout", "12", *base, "-w8", target, str(self._cfg.port)]

        if not udp and graceful:
            script = f"printf '{payload}\\n'; sleep 3; printf 'quit\\n'; sleep 3"
            pipeline = subprocess.Popen(
                ["bash", "-c", f"{{ {script}; }} | " + " ".join(cmd)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            data = pipeline.communicate()[0]
        else:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            data = proc.communicate(input=stdin)[0]
        self._out.write_bytes(data or b"")

    # -- assertions -------------------------------------------------

    def check_or_exit(self) -> None:
        """
        Evaluate the --expect-log / --expect-wire / --expect-client
        regexes against the captured transcript. Print one PASS/FAIL
        line per expectation and raise SystemExit(1) if any failed.
        A run with no expectations is a no-op (pure capture mode).
        """

        checks: list[tuple[str, str]] = (
            [("log", pattern) for pattern in self._cfg.expect_log]
            + [("wire", pattern) for pattern in self._cfg.expect_wire]
            + [("client", pattern) for pattern in self._cfg.expect_client]
        )
        if not checks:
            return
        click.echo()
        click.echo("=== expectations ===")
        failed = False
        for section, pattern in checks:
            ok = re.search(pattern, self._captured.get(section, "")) is not None
            click.echo(f"[{'PASS' if ok else 'FAIL'}] {section}: /{pattern}/")
            if not ok:
                failed = True
        if failed:
            raise SystemExit(1)
