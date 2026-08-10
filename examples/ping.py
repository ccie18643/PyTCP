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
This module contains a ping (ICMP Echo) tool for the PyTCP daemon. It is
a thin Click veneer over the shared ICMP Echo engine in
'pytcp.cli.cli__ping' (the same engine the 'pytcp ping' subcommand uses),
adding coloured output: timeouts in yellow, a green / red loss line.

The destination may be an IPv4 / IPv6 address — classified directly via
'net_addr' — or a hostname, resolved through the daemon's DNS resolver;
the IP version drives ICMPv4 (Echo 8/0) vs ICMPv6 (Echo 128/129). Socket
selection mirrors Linux 'ping': by default it uses the unprivileged ICMP
datagram socket and falls back to a raw socket if that is refused;
'-e IDENTIFIER' forces a raw socket (a custom id needs SOCK_RAW, since the
kernel owns the id on a ping socket).

Needs a running daemon (it owns the TAP interface), e.g.:

    sudo make tap7 && sudo make bridge
    pytcp stack start -i tap7

examples/ping.py

ver 3.0.9
"""

from typing import override

import click

from pytcp.cli.cli__ping import (
    TIMESTAMP__LEN,
    default_identifier,
    icmp_echo_profile,
    open_ping_socket,
    resolve_destination,
    run_ping,
)

BANNER: str = "PyTCP ping tool — ICMP Echo (ping) over the PyTCP daemon"


class _BannerCommand(click.Command):
    """
    A Click command whose '--help' is framed by a leading blank line, a
    bright-green banner, and a trailing blank line.
    """

    @override
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write("\n")
        formatter.write(click.style(BANNER, fg="bright_green", bold=True))
        formatter.write("\n\n")
        super().format_help(ctx, formatter)

    @override
    def get_help(self, ctx: click.Context) -> str:
        # Click rstrips trailing newlines from the help, so append one
        # here for the trailing blank line ('echo' adds the final newline).
        return super().get_help(ctx) + "\n"


@click.command(cls=_BannerCommand, context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("destination")
@click.option(
    "-e",
    "--identifier",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    metavar="ID",
    help="ICMP identifier; implies a raw (SOCK_RAW) socket.",
)
@click.option("-c", "--count", type=click.IntRange(min=1), default=None, help="Stop after COUNT requests.")
@click.option("-i", "--interval", type=float, default=1.0, show_default=True, help="Seconds between requests.")
@click.option("-W", "--timeout", type=float, default=1.0, show_default=True, help="Seconds to wait per reply.")
@click.option(
    "-s",
    "--size",
    type=click.IntRange(min=TIMESTAMP__LEN),
    default=56,
    show_default=True,
    help="Payload size in bytes.",
)
def ping(
    destination: str, identifier: int | None, count: int | None, interval: float, timeout: float, size: int
) -> None:
    """
    Send ICMP Echo Requests to DESTINATION (an IPv4 / IPv6 address or
    hostname) and report the replies, in the style of the 'ping' utility.
    """

    is_ipv6, address = resolve_destination(destination)
    profile = icmp_echo_profile(is_ipv6=is_ipv6)
    icmp_id = default_identifier(identifier)
    sock, use_cmsg, match_identifier = open_ping_socket(
        is_ipv6=is_ipv6,
        force_raw=identifier is not None,
        identifier=icmp_id,
    )

    transmitted = 0
    received = 0
    round_trips: list[float] = []

    click.echo(f"PING {destination} ({address}): {size} data bytes")
    try:
        for outcome in run_ping(
            sock,
            profile,
            address=address,
            identifier=icmp_id,
            count=count,
            interval=interval,
            timeout=timeout,
            size=size,
            use_cmsg=use_cmsg,
            match_identifier=match_identifier,
        ):
            transmitted += 1
            if outcome.timed_out:
                click.secho(f"Request timeout for icmp_seq {outcome.sequence}", fg="yellow")
                continue
            received += 1
            assert outcome.rtt_ms is not None  # a non-timed-out outcome always carries an RTT
            round_trips.append(outcome.rtt_ms)
            ttl_text = "?" if outcome.ttl is None else str(outcome.ttl)
            click.echo(
                f"{size + 8} bytes from {address}: "
                f"icmp_seq={outcome.sequence} ttl={ttl_text} time={outcome.rtt_ms:.2f} ms"
            )
    except KeyboardInterrupt:
        click.echo()
    finally:
        sock.close()

    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    click.echo(f"\n--- {destination} ping statistics ---")
    click.secho(
        f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss",
        fg="green" if loss == 0.0 else "red",
    )
    if round_trips:
        average = sum(round_trips) / len(round_trips)
        click.echo(f"rtt min/avg/max = {min(round_trips):.2f}/{average:.2f}/{max(round_trips):.2f} ms")


if __name__ == "__main__":
    ping()  # pylint: disable=no-value-for-parameter  # click injects the arguments
