#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# examples/lib/malpi.py - Module contains test monkeys used by various services.
#
# ver 2.7
#


from __future__ import annotations

malpka: bytes = (
    b"\n                                       \n"
    + b"                                       \n"
    + b"                                       \n"
    + b"                                       \n"
    + b'               .="=.                   \n'
    + b"             _/.-.-.\\_    _            \n"
    + b"            ( ( o o ) )   ))           \n"
    + b'             |/  "  \\|   //            \n'
    + b"              \\'---'/   //             \n"
    + b"              /`---`\\  ((              \n"
    + b"             / /_,_\\ \\  \\\\             \n"
    + b"             \\_\\_'__/ \\  ))            \n"
    + b"             /`  /`~\\  |//             \n"
    + b"            /   /    \\  /              \n"
    + b"        ,--`,--'\\/\\    /               \n"
    + b"         '-- \"--'  '--'                \n"
    + b"                                       \n"
    + b"                                       \n"
    + b"                                       \n"
    + b"                                       \n"
    + b"                                       \n"
)

malpa: bytes = (
    b"\n______AAAA_______________AAAA______\n"
    + b"      VVVV               VVVV       \n"
    + b"      (__)               (__)       \n"
    + b"       \\ \\               / /        \n"
    + b"        \\ \\              / /         \n"
    + b'         > \\   .="=.   / <          \n'
    + b"          > \\ /     \\ / <           \n"
    + b"           > \\\\_o_o_// <            \n"
    + b"            > ( (_) ) <             \n"
    + b"             >|     |<              \n"
    + b"            / |\\___/| \\             \n"
    + b"            / \\_____/ \\             \n"
    + b"            /         \\             \n"
    + b"             /   o   \\              \n"
    + b"              ) ___ (               \n"
    + b"             / /   \\ \\              \n"
    + b"            ( /     \\ )             \n"
    + b"            ><       ><             \n"
    + b"           ///\\     /\\\\\\            \n"
    + b"           '''       '''            \n"
)


malpi: bytes = b"".join(
    [_ + __ + b"\n" for _, __ in zip(malpka.split(b"\n"), malpa.split(b"\n"))]
)
