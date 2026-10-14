# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Installation on Debian/Ubuntu (fobots.py install)."""
import os
import re
import shutil
import subprocess
import sys

from .constants import CONF_DIR, INSTALL_DIR, SERVICE_USER, SRC_DIR, STATE_DIR, UNIT_PATH
from .nft import Nft


class Installer:
    """Installation on Debian/Ubuntu: nftables, user, directories, program, configuration, unit."""

    def __init__(self, args):
        self.args = args
        self.dry = args.dry_run
        self.dest = args.destdir  # test prefix: writes the files without touching the system
        self.system = not self.dest and not self.dry

    def path(self, p):
        return os.path.join(self.dest, p.lstrip("/")) if self.dest else p

    def say(self, status, msg):
        if self.dry and status == "ok":  # nothing is done: do not claim otherwise
            status, msg = "..", f"(simulated) {msg}"
        print(f"[{status}] {msg}")

    def said_done(self, msg):
        """System action (apt, useradd…): "ok" only if it really took place."""
        self.say("ok" if self.system or self.dry else "..",
                 msg if self.system or self.dry else f"{msg} (not done: --destdir)")

    def confirm(self, question):
        if self.args.yes or self.dry:
            return True
        if sys.stdin.isatty():
            return input(f"{question} [y/N] ").strip().lower() in ("y", "yes", "o", "oui")
        sys.exit(f"{question}: cannot answer outside a terminal, run again with --yes")

    def run(self, cmd, check=True):
        """System command; with --dry-run or --destdir, it is only printed."""
        if not self.system:
            note = "" if self.dry else "   (ignored: --destdir)"
            print(f"  $ {' '.join(cmd)}{note}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            sys.exit(f"{' '.join(cmd)} failed:\n{r.stderr.strip()}")
        return r

    def ensure_dir(self, path, mode, owner=None):
        if self.dry:
            print(f"  create {path} (mode {mode:o})")
            return
        real = self.path(path)
        os.makedirs(real, exist_ok=True)
        os.chmod(real, mode)
        if owner and self.system:
            shutil.chown(real, *owner)

    def write(self, path, content, mode):
        if self.dry:
            print(f"  write {path} (mode {mode:o})")
            return
        real = self.path(path)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        tmp = real + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, real)

    @staticmethod
    def template(name):
        p = os.path.join(SRC_DIR, name)
        if not os.path.exists(p):
            sys.exit(f"{name} not found in {SRC_DIR}: "
                     "run the installation from a clone of the repository")
        with open(p) as f:
            return f.read()

    def read(self, path):
        try:
            with open(self.path(path)) as f:
                return f.read()
        except OSError:
            return None

    def check_python(self):
        v = sys.version_info
        if v < (3, 7):
            sys.exit(f"Python 3.7 or later required (found {v.major}.{v.minor})")
        self.say("ok", f"Python {v.major}.{v.minor}.{v.micro}")

    def ensure_nft(self):
        binary = self.args.nft_bin
        found = shutil.which(binary)
        if found:
            self.say("ok", f"nft: {found}")
            return
        if not shutil.which("apt-get"):
            self.say("!!", "nft not found and apt-get absent: install the nftables package by hand")
            if self.system:
                sys.exit(1)
            return
        if not self.confirm("nft is missing. Install the nftables package with apt-get?"):
            sys.exit("nftables is required")
        self.run(["apt-get", "install", "-y", "nftables"])
        self.said_done("nftables installed")

    def selftest(self):
        if not self.system:
            self.say("..", "nft test (interval sets with timeouts): done at the real installation")
            return
        ok, expires, msg = Nft(self.args.nft_bin).selftest()
        if not ok:
            sys.exit(f"[!!] nft is not suitable: {msg}\n"
                     "     (kernel without nf_tables, nftables package too old, or permissions?)")
        self.say("ok", "nft: interval sets with timeouts, readable JSON output")
        if not expires:
            self.say("..", "this version of nft does not show the remaining time of bans "
                     "(`bans` and `watched` therefore do not show it)")

    def ensure_user(self):
        import pwd
        try:
            pwd.getpwnam(SERVICE_USER)
            self.say("ok", f"user {SERVICE_USER} exists")
        except KeyError:
            self.run(["useradd", "--system", "--user-group", "--no-create-home",
                      "--shell", "/usr/sbin/nologin", SERVICE_USER])
            self.said_done(f"user {SERVICE_USER} created")

    def log_paths(self):
        if self.args.log:
            return [self.args.log]
        text = self.read(os.path.join(CONF_DIR, "fobots.conf")) or self.template("fobots.conf.example")
        return re.findall(r"(?m)^\s*log\s*=\s*(\S+)", text)

    @staticmethod
    def group_for(log_file):
        """Group giving access to this log if it is not public (and not root), otherwise adm."""
        import grp
        try:
            st = os.stat(log_file)
            name = grp.getgrgid(st.st_gid).gr_name
            if not st.st_mode & 0o004 and name != "root":
                return name
        except (OSError, KeyError, TypeError):
            pass
        return "adm"

    def log_groups(self):
        """Access groups for all the logs (--log-group imposes its own)."""
        if self.args.log_group:
            return [self.args.log_group]
        groups = []
        for log_file in self.log_paths():
            g = self.group_for(log_file)
            if g not in groups:
                groups.append(g)
        return groups or ["adm"]

    @staticmethod
    def program_files():
        """[(path relative to SRC_DIR, mode)]: the launcher and the modules of the package."""
        files = [("fobots.py", 0o755)]
        pkg = os.path.join(SRC_DIR, "fobots")
        files += [(os.path.join("fobots", n), 0o644) for n in sorted(os.listdir(pkg)) if n.endswith(".py")]
        return files

    def install_files(self):
        self.ensure_dir(INSTALL_DIR, 0o755)
        if os.path.abspath(SRC_DIR) == os.path.abspath(self.path(INSTALL_DIR)):
            self.say("ok", f"program already in place: {INSTALL_DIR}")
        else:
            for rel, mode in self.program_files():
                with open(os.path.join(SRC_DIR, rel)) as f:
                    self.write(os.path.join(INSTALL_DIR, rel), f.read(), mode)
            self.say("ok", f"program: {INSTALL_DIR}/fobots.py and {INSTALL_DIR}/fobots/")

        self.ensure_dir(CONF_DIR, 0o755)
        conf = os.path.join(CONF_DIR, "fobots.conf")
        if self.read(conf) is not None:
            self.say("ok", f"{conf} exists: kept as is")
            if self.args.log:
                self.say("!!", f"--log ignored: edit the `log =` line of {conf} by hand")
        else:
            text = self.template("fobots.conf.example")
            if self.args.log:
                text = re.sub(r"(?m)^log\s*=.*$", lambda m: f"log = {self.args.log}", text)
            self.write(conf, text, 0o644)
            self.say("ok", f"configuration: {conf}")
        wl = os.path.join(CONF_DIR, "welcome.txt")
        if self.read(wl) is None:
            self.write(wl, "# Ranges never to ban, one CIDR per line.\n"
                       "# Add with: fobots.py welcome add CIDR (also removes the bans concerned)\n", 0o644)
            self.say("ok", f"welcome list: {wl}")

        self.ensure_dir(STATE_DIR, 0o750, (SERVICE_USER, SERVICE_USER))
        self.say("ok", f"state directory: {STATE_DIR}")

        unit = re.sub(r"(?m)^SupplementaryGroups=.*$", f"SupplementaryGroups={' '.join(self.log_groups())}",
                      self.template("fobots.service.example"))
        if self.read(UNIT_PATH) == unit:
            self.say("ok", f"systemd unit up to date: {UNIT_PATH}")
        else:
            self.write(UNIT_PATH, unit, 0o644)
            self.say("ok", f"systemd unit: {UNIT_PATH} (log access groups: {' '.join(self.log_groups())})")
            self.run(["systemctl", "daemon-reload"])

    def check_log_access(self):
        logs = self.log_paths()
        if not logs:
            self.say("..", "no log configured: the daemon will read stdin")
            return
        for log_file in logs:
            if not self.system:
                self.say("..", f"access of {SERVICE_USER} to {log_file}: checked at the real installation")
                continue
            if not os.path.exists(log_file):
                self.say("!!", f"{log_file} does not exist yet (the daemon will wait for it): check the path")
                continue
            group = self.args.log_group or self.group_for(log_file)
            r = self.run(["runuser", "-u", SERVICE_USER, "-g", group, "--",
                          "test", "-r", log_file], check=False)
            if r.returncode == 0:
                self.say("ok", f"{SERVICE_USER} can read {log_file}")
            else:
                self.say("!!", f"{SERVICE_USER} cannot read {log_file}: grant access, e.g. "
                         f"`setfacl -m u:{SERVICE_USER}:r {log_file}` (and x on the parent directories), "
                         "or --log-group")

    def run_all(self):
        if self.system and os.geteuid() != 0:
            sys.exit("the installation needs root rights: sudo ./fobots.py install")
        if self.dry:
            print("--dry-run: nothing is modified, here is what would be done\n")
        self.check_python()
        self.ensure_nft()
        self.selftest()
        self.ensure_user()
        self.install_files()
        self.check_log_access()
        if self.args.start:
            self.run(["systemctl", "enable", "--now", "fobots"])
            self.said_done("service enabled and started")
        elif self.args.enable:
            self.run(["systemctl", "enable", "fobots"])
            self.said_done("service enabled at boot (not started)")
        print(f"""
Next steps:
  1. check / adapt {CONF_DIR}/fobots.conf (log, thresholds)
  2. add your networks to {CONF_DIR}/welcome.txt (administrators, CI, monitoring)
  3. trial without banning anything: {INSTALL_DIR}/fobots.py run --dry-run
  4. start: systemctl enable --now fobots      follow: journalctl -u fobots -f""")
