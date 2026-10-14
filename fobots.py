#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
#
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version. It is distributed WITHOUT
# ANY WARRANTY; see the file LICENSE or <https://www.gnu.org/licenses/>.
"""Launcher. In a clone it is run as ./fobots.py; installed, it is the command `fobots`
(/usr/local/sbin or /usr/sbin) and the code is in the fobots/ package, found next to it
or in /opt/fobots."""
import os
import sys

for _dir in (os.path.dirname(os.path.realpath(__file__)), "/opt/fobots"):
    if os.path.isdir(os.path.join(_dir, "fobots")):
        sys.path.insert(0, _dir)
        break

from fobots.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
