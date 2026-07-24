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
This module contains the tiny text wire format shared by the multicast
service-discovery examples ('mcast_announce.py' / 'mcast_discover.py'). An
announcement is a single UTF-8 line — a real-world analog of an SSDP NOTIFY
or an mDNS record, kept deliberately simple:

    PyTCP-DISCOVER v1 service=<name> host=<ip> port=<port>

examples/mcast_proto.py

ver 3.0.8
"""

from dataclasses import dataclass

ANNOUNCEMENT__MAGIC: str = "PyTCP-DISCOVER"
ANNOUNCEMENT__VERSION: str = "v1"


@dataclass(frozen=True, kw_only=True, slots=True)
class Announcement:
    """
    A discovered service: its name plus the host / port it lives on.
    """

    service: str
    host: str
    port: int


def format_announcement(announcement: Announcement, /) -> bytes:
    """
    Render an 'Announcement' as its one-line wire form (UTF-8, LF-terminated).
    """

    return (
        f"{ANNOUNCEMENT__MAGIC} {ANNOUNCEMENT__VERSION} "
        f"service={announcement.service} "
        f"host={announcement.host} "
        f"port={announcement.port}\n"
    ).encode("utf-8")


def parse_announcement(data: bytes, /) -> Announcement | None:
    """
    Parse an announcement line into an 'Announcement', or None when the
    datagram is not a well-formed 'PyTCP-DISCOVER v1' announcement (wrong
    magic / version, non-UTF-8, missing field, or a non-integer port).
    """

    try:
        tokens = data.decode("utf-8").strip().split()
    except UnicodeDecodeError:
        return None

    if len(tokens) < 2 or tokens[0] != ANNOUNCEMENT__MAGIC or tokens[1] != ANNOUNCEMENT__VERSION:
        return None

    fields: dict[str, str] = {}
    for token in tokens[2:]:
        key, separator, value = token.partition("=")
        if separator:
            fields[key] = value

    try:
        return Announcement(service=fields["service"], host=fields["host"], port=int(fields["port"]))
    except KeyError, ValueError:
        return None
