#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
#
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version. It is distributed WITHOUT
# ANY WARRANTY; see the file LICENSE or <https://www.gnu.org/licenses/>.
"""Launcher: the code lives in the fobots/ package next to this file."""
import sys

from fobots.cli import main

if __name__ == "__main__":
    sys.exit(main())
