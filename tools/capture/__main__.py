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
This module contains the top-level click group for the capture
tool; it registers every scenario command from the registry.

tools/capture/__main__.py

ver 3.0.9
"""

from typing import Any

import click

from tools.capture.scenarios import COMMANDS


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "PyTCP example-capture / e2e-scenario runner. Brings a "
        "scenario up on a TAP interface, waits for real readiness, "
        "drives the exchange, captures the wire with tshark, and "
        "prints a README-ready transcript. Run as root with the "
        "TAP/bridge set up (make tap7 && make bridge) and the venv "
        "built (make venv). The impairment / assertion options are "
        "global — pass them before the scenario, e.g. "
        "`capture --loss 15 ip4-tcp-monkeys`."
    ),
)
# Run-wide concerns (apply to every scenario): tc netem impairment
# on the host interface and the e2e expectation assertions. Global
# group options, so they come BEFORE the scenario name.
@click.option("--loss", type=float, default=None, help="netem packet loss %% on the host iface.")
@click.option("--delay-ms", type=float, default=None, help="netem one-way delay (ms).")
@click.option("--reorder", type=float, default=None, help="netem reorder %% (implies a small delay).")
@click.option("--duplicate", type=float, default=None, help="netem duplicate %%.")
@click.option("--corrupt", type=float, default=None, help="netem corrupt %%.")
@click.option("--expect-log", multiple=True, help="Regex that MUST match the stack log (repeatable).")
@click.option("--expect-wire", multiple=True, help="Regex that MUST match the wire decode (repeatable).")
@click.option("--expect-client", multiple=True, help="Regex that MUST match client output (repeatable).")
@click.pass_context
def cli(ctx: click.Context, **run_options: Any) -> None:
    """
    PyTCP capture tool command group.
    """

    # Stash the run-wide options so every scenario's make_config()
    # can merge them in regardless of which subcommand ran.
    ctx.obj = run_options


for _command in COMMANDS:
    cli.add_command(_command)


if __name__ == "__main__":
    cli()
