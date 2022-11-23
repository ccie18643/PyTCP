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


"""
Module contains methods supporting logging.

pytcp/lib/logger.py

ver 2.7
"""


from __future__ import annotations

import inspect
import time

from pytcp import config

STYLES = {
    "</>": "\33[0m",
    "<WARN>": "\33[1m\33[93m",
    "<CRIT>": "\33[41m",
    "<INFO>": "\33[1m",
    "<B>": "\33[1m",
    "<I>": "\33[3m",
    "<U>": "\33[4m",
    "<r>": "\33[31m",
    "<lr>": "\33[91m",
    "<g>": "\33[32m",
    "<lg>": "\33[92m",
    "<y>": "\33[33m",
    "<ly>": "\33[93m",
    "<b>": "\33[34m",
    "<lb>": "\33[94m",
    "<c>": "\33[36m",
    "<lc>": "\33[96m",
    "<v>": "\33[35m",
    "<lv>": "\33[95m",
}


START_TIME = time.time()


def log(channel: str, message: str, inspect_depth: int = 1) -> bool:
    """
    Log message if channel and severity match configured values.
    """

    if channel in config.LOG_CHANEL:
        if config.LOG_DEBUG:
            frame_info = inspect.stack()[inspect_depth]
            caller_class = frame_info.frame.f_locals["self"].__class__.__name__
            caller_method = frame_info.function
            caller_info = f"{caller_class}.{caller_method}"
            output = (
                f" <g>{(time.time() - START_TIME):07.02f}</> | "
                f"<b>{channel.upper():7}</> | <c>{caller_info}</> | "
                f"{message}"
            )
        else:
            output = (
                f" <g>{(time.time() - START_TIME):07.02f}</> | "
                f"<b>{channel.upper():7}</> | {message}"
            )

        for key, value in STYLES.items():
            output = output.replace(key, value)

        print(output)

        return True

    return False
