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
This module contains the PyTCP daemon command-line entry point.

Invoked as 'python -m pytcp.daemon' (or the 'pytcpd' console script), it
parses the interface / addressing / socket-path options with stdlib
'argparse' (the stack is zero-dependency — no Click here) and hands them
to 'run_daemon'. Needs a TAP/TUN interface and the privileges to open it.

pytcp/daemon/__main__.py

ver 3.0.8
"""

import argparse

from net_addr import (
    Ip4IfAddr,
    Ip6IfAddr,
    MacAddress,
    NetAddrError,
)
from pytcp.daemon.daemon import default_socket_path, run_daemon


def _ip4_ifaddr(value: str, /) -> Ip4IfAddr:
    """
    Parse an IPv4 'address/mask' argument into an 'Ip4IfAddr'.
    """

    try:
        return Ip4IfAddr(value)
    except NetAddrError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _ip6_ifaddr(value: str, /) -> Ip6IfAddr:
    """
    Parse an IPv6 'address/mask' argument into an 'Ip6IfAddr'.
    """

    try:
        return Ip6IfAddr(value)
    except NetAddrError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _mac_address(value: str, /) -> MacAddress:
    """
    Parse a MAC-address argument into a 'MacAddress'.
    """

    try:
        return MacAddress(value)
    except NetAddrError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def build_parser() -> argparse.ArgumentParser:
    """
    Build the daemon's argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="pytcp.daemon",
        description="Run the PyTCP stack as a daemon serving out-of-process clients over an AF_UNIX control socket.",
    )
    parser.add_argument(
        "--ipc-socket",
        default=default_socket_path(),
        help="AF_UNIX control-socket path (default: $XDG_RUNTIME_DIR/pytcp.sock).",
    )
    parser.add_argument(
        "--interface",
        default="tap7",
        help="TAP/TUN interface to bind the stack to (default: tap7).",
    )
    parser.add_argument(
        "--mac-address",
        type=_mac_address,
        default=None,
        help="MAC address to assign to the interface.",
    )
    parser.add_argument(
        "--ip4-address",
        type=_ip4_ifaddr,
        default=None,
        help="IPv4 address/mask to assign (omit to autoconfigure via DHCPv4).",
    )
    parser.add_argument(
        "--ip6-address",
        type=_ip6_ifaddr,
        default=None,
        help="IPv6 address/mask to assign (omit to autoconfigure via SLAAC).",
    )
    parser.add_argument(
        "--no-ip4",
        action="store_false",
        dest="ip4_support",
        help="Disable IPv4 support.",
    )
    parser.add_argument(
        "--no-ip6",
        action="store_false",
        dest="ip6_support",
        help="Disable IPv6 support.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """
    Parse the command line and run the daemon until SIGINT / SIGTERM.
    """

    args = build_parser().parse_args(argv)

    run_daemon(
        socket_path=args.ipc_socket,
        interface_name=args.interface,
        mac_address=args.mac_address,
        ip4_support=args.ip4_support,
        ip4_host=args.ip4_address,
        ip6_support=args.ip6_support,
        ip6_host=args.ip6_address,
        on_ready=lambda path: print(f"PyTCP daemon listening on {path}", flush=True),
    )


if __name__ == "__main__":
    main()
