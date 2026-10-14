# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Paths shared by the daemon and the installer."""
import os


# Directory holding fobots.py, the examples and the fobots/ package (the repository root, or
# /opt/fobots once installed).
SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONF_DIR = "/etc/fobots"      # configuration and welcome list (decided by the administrator)

STATE_DIR = "/var/lib/fobots"  # RDAP cache and findings (written by the daemon)

INSTALL_DIR = "/opt/fobots"  # the fobots/ package (modules) is installed here

BIN_PATH = "/usr/local/sbin/fobots"  # the command: the launcher, installed without .py

UNIT_PATH = "/etc/systemd/system/fobots.service"

SERVICE_USER = "fobots"
