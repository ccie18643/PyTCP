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
This module contains the test monkeys used as easter-egg payloads in the
echo examples (a 'malpa' / 'malpka' / 'malpi' request is answered with the
matching ASCII-art monkey) plus the shared 'echo_reply' selector both the
UDP and TCP echo servers use. Carried over from the legacy examples.

examples/lib/malpi.py

ver 3.0.8
"""

malpka: bytes = (
    b"\n                                       \n"
    b"                                       \n"
    b"                                       \n"
    b"                                       \n"
    b'               .="=.                   \n'
    b"             _/.-.-.\\_    _            \n"
    b"            ( ( o o ) )   ))           \n"
    b'             |/  "  \\|   //            \n'
    b"              \\'---'/   //             \n"
    b"              /`---`\\  ((              \n"
    b"             / /_,_\\ \\  \\\\             \n"
    b"             \\_\\_'__/ \\  ))            \n"
    b"             /`  /`~\\  |//             \n"
    b"            /   /    \\  /              \n"
    b"        ,--`,--'\\/\\    /               \n"
    b"         '-- \"--'  '--'                \n"
    b"                                       \n"
    b"                                       \n"
    b"                                       \n"
    b"                                       \n"
    b"                                       \n"
)

malpa: bytes = (
    b"\n______AAAA_______________AAAA______\n"
    b"      VVVV               VVVV       \n"
    b"      (__)               (__)       \n"
    b"       \\ \\               / /        \n"
    b"        \\ \\              / /         \n"
    b'         > \\   .="=.   / <          \n'
    b"          > \\ /     \\ / <           \n"
    b"           > \\\\_o_o_// <            \n"
    b"            > ( (_) ) <             \n"
    b"             >|     |<              \n"
    b"            / |\\___/| \\             \n"
    b"            / \\_____/ \\             \n"
    b"            /         \\             \n"
    b"             /   o   \\              \n"
    b"              ) ___ (               \n"
    b"             / /   \\ \\              \n"
    b"            ( /     \\ )             \n"
    b"            ><       ><             \n"
    b"           ///\\     /\\\\\\            \n"
    b"           '''       '''            \n"
)


malpi: bytes = b"".join([_ + __ + b"\n" for _, __ in zip(malpka.split(b"\n"), malpa.split(b"\n"))])


def echo_reply(message: bytes, /) -> bytes:
    """
    Build the echo reply for 'message': the message itself, unless it names
    a monkey ('malpka' / 'malpa' / 'malpi'), in which case the matching
    ASCII-art monkey is returned instead. The three names are tested in
    'malpka' -> 'malpa' -> 'malpi' order, matching the legacy echo service.
    Matching is case-insensitive and ignores surrounding whitespace; the
    echoed bytes for a non-monkey message are the original, unstripped.
    """

    lowered = message.strip().lower()
    if b"malpka" in lowered:
        return malpka
    if b"malpa" in lowered:
        return malpa
    if b"malpi" in lowered:
        return malpi
    return message
