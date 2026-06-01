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
This module contains the methods supporting the stack logging.

pytcp/lib/logger.py

ver 3.0.8
"""

import inspect
import time

LOG__START_TIME = time.time()


def _apply_styles(s: str, /) -> str:
    """
    Substitute every supported style token in 's' with its ANSI escape.

    Hardcoded chain of 'str.replace' calls. Faster than iterating a
    {token: escape} dict because each '.replace' is a single C call.
    """

    return (
        s.replace("</>", "\33[0m")
        .replace("<WARN>", "\33[1m\33[93m")
        .replace("<CRIT>", "\33[41m")
        .replace("<INFO>", "\33[1m")
        .replace("<B>", "\33[1m")
        .replace("<I>", "\33[3m")
        .replace("<U>", "\33[4m")
        .replace("<r>", "\33[31m")
        .replace("<lr>", "\33[91m")
        .replace("<g>", "\33[32m")
        .replace("<lg>", "\33[92m")
        .replace("<y>", "\33[33m")
        .replace("<ly>", "\33[93m")
        .replace("<b>", "\33[34m")
        .replace("<lb>", "\33[94m")
        .replace("<c>", "\33[36m")
        .replace("<lc>", "\33[96m")
        .replace("<v>", "\33[35m")
        .replace("<lv>", "\33[95m")
    )


def log(
    channel: str,
    message: str,
    /,
    *,
    inspect_depth: int = 1,
) -> bool:
    """
    Log a message if the channel matches one of the configured channels.
    """

    from pytcp.stack import LOG__CHANNEL, LOG__DEBUG, LOG__OUTPUT

    if channel not in LOG__CHANNEL:
        return False

    prefix = f" <g>{(time.time() - LOG__START_TIME):07.02f}</> | <b>{channel.upper():7}</>"

    if LOG__DEBUG:
        frame_info = inspect.stack()[inspect_depth]
        caller_self = frame_info.frame.f_locals.get("self")
        if caller_self is not None:
            caller_info = f"{caller_self.__class__.__name__}.{frame_info.function}"
        else:
            caller_info = frame_info.function
        output = f"{prefix} | <c>{caller_info}</> | {message}"
    else:
        output = f"{prefix} | {message}"

    print(_apply_styles(output), file=LOG__OUTPUT)

    return True
