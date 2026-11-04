# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""`fobots init`: finds the access logs in the Apache and nginx configuration, reads their last
lines to check that fobots understands them, and writes a fobots.conf in observation mode."""
import glob
import ipaddress
import os
import re
import shlex
import subprocess
from datetime import datetime

from .analyse import FULL_RE, duration_field

APACHE_CONFS = ("/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf")

NGINX_CONFS = ("/etc/nginx/nginx.conf",)

NGINX_DEFAULT_LOG = "/var/log/nginx/access.log"  # compiled-in path of the Debian package

SAMPLE_BYTES = 256 * 1024  # read at the end of each log

SAMPLE_LINES = 1000

MAX_FILES = 1000  # included files followed (protection against an include loop)

VAR_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")



class Found:
    """A log written by the web server, with the hosts that write it."""

    def __init__(self, server, path, where):
        self.server, self.path, self.where = server, path, where  # where: the directive (file:line)
        self.names, self.blocks, self.notes = [], [], []  # blocks: <VirtualHost *:443>…
        self.default = False  # nginx: path of no access_log (compiled-in), not written in the conf
        self.public = False   # nginx: one of its server blocks listens beyond the loopback

    def add_names(self, names):
        for n in names:
            if n not in self.names and n not in ("_", "localhost") and "*" not in n:
                self.names.append(n)



def expand(text, env):
    return VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), ""), text)


def read_envvars(path):
    """`export NAME=value` of Apache's envvars (Debian: APACHE_LOG_DIR); an unknown variable is
    empty (the SUFFIX of a second instance)."""
    env = {}
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r"\s*export\s+(\w+)=(.*)$", line)
                if m:
                    value = m.group(2).split(" #")[0].strip().strip("'\"")
                    env[m.group(1)] = expand(value, env)
    except OSError:
        pass
    return env


def apache_lines(path):
    """(line number, words) of the directives of a file, continuations joined."""
    with open(path, errors="replace") as f:
        text = f.read()
    number, pending = 0, ""
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending:
            number = i
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line, pending = (pending + line).strip(), ""
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line, comments=False, posix=True)
        except ValueError:
            words = line.split()
        if words:
            yield number, words


def included(pattern, root):
    """Files of an Include: a glob, or a directory (all its files)."""
    if not os.path.isabs(pattern):
        pattern = os.path.join(root, pattern)
    out = []
    for p in sorted(glob.glob(pattern)):
        if os.path.isdir(p):
            out += sorted(os.path.join(d, n) for d, _, names in os.walk(p) for n in names)
        else:
            out.append(p)
    return out


def apache_logs(conf, warnings=None, envvars=None):
    """[Found] of an Apache configuration: one per CustomLog of each <VirtualHost>; a vhost
    without its own CustomLog writes in those of the main server (Debian:
    other_vhosts_access.log). A log piped to a program goes to `warnings`."""
    warnings = [] if warnings is None else warnings
    if not os.path.isfile(conf):
        return []
    env = read_envvars(envvars or os.path.join(os.path.dirname(conf), "envvars"))
    state = {"root": os.path.dirname(conf), "files": 0}
    main = {"names": [], "logs": []}
    vhosts, stack = [], []

    def walk(path):
        state["files"] += 1
        if state["files"] > MAX_FILES or path in stack:
            return
        stack.append(path)
        try:
            lines = list(apache_lines(path))
        except OSError:
            lines = []
        for number, words in lines:
            words = [expand(w, env) for w in words]
            d, args = words[0].lower(), words[1:]
            here = vhosts[-1] if vhosts and vhosts[-1]["open"] else main
            if d == "serverroot" and args:
                state["root"] = args[0]
            elif d == "define" and args:
                env[args[0]] = args[1] if len(args) > 1 else ""
            elif d in ("include", "includeoptional") and args:
                for p in included(args[0], state["root"]):
                    walk(p)
            elif d.startswith("<virtualhost"):
                vhosts.append({"open": True, "addr": " ".join(args).rstrip(">"), "names": [], "logs": []})
            elif d == "</virtualhost>" and vhosts:
                vhosts[-1]["open"] = False
            elif d in ("servername", "serveralias"):
                here["names"] += [re.sub(r"^\w+://", "", a).split(":")[0].split("/")[0] for a in args]
            elif d in ("customlog", "transferlog") and args:
                here["logs"].append((args[0], args[1:], f"{path}:{number}"))
        stack.pop()

    walk(conf)
    found = {}

    def add(path, extra, where, names, block):
        if path.startswith("|"):
            note = f"apache: CustomLog {path} ({where}): piped to a program, cannot be followed"
            if note not in warnings:
                warnings.append(note)
            return
        if not os.path.isabs(path):
            path = os.path.join(state["root"], path)
        f = found.setdefault(path, Found("apache", path, where))
        f.add_names(names)
        if block and block not in f.blocks:
            f.blocks.append(block)
        note = "conditional (env=/expr=): some requests are not logged"
        if any(a.startswith(("env=", "expr=")) for a in extra) and note not in f.notes:
            f.notes.append(note)

    for v in vhosts:
        for path, extra, where in v["logs"] or main["logs"]:
            add(path, extra, where, v["names"], f"<VirtualHost {v['addr']}>")
    if not vhosts:
        for path, extra, where in main["logs"]:
            add(path, extra, where, main["names"], None)
    return list(found.values())



def nginx_tokens(path):
    """(word, line) of an nginx file: `;`, `{` and `}` are words of their own."""
    with open(path, errors="replace") as f:
        text = f.read()
    for m in re.finditer(r'#[^\n]*|"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|([;{}])|([^\s;{}"\'#]+)', text):
        if m.group(0).startswith("#"):
            continue
        word = next(g for g in m.groups() if g is not None)
        yield word, text.count("\n", 0, m.start()) + 1


def loopback(listen):
    """Does this `listen` of nginx only accept the machine itself (127.0.0.1:8060, localhost,
    [::1]:80, unix:…)? A port alone or *:80 listens on every address."""
    if listen.startswith("unix:"):
        return True
    host = listen[1:listen.find("]")] if listen.startswith("[") else \
        listen.rsplit(":", 1)[0] if ":" in listen else listen
    if host.isdigit():
        return False  # a port alone
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def nginx_logs(conf, warnings=None):
    """[Found] of an nginx configuration: the access_log of each server block, otherwise those of
    the http block, otherwise the compiled-in default. A log that cannot be followed (variable in
    the path, syslog) goes to `warnings`."""
    warnings = [] if warnings is None else warnings
    if not os.path.isfile(conf):
        return []
    root = os.path.dirname(conf)
    state = {"files": 0}
    http = {"logs": [], "own": False}
    servers, blocks, stack = [], [], []

    def walk(path):
        state["files"] += 1
        if state["files"] > MAX_FILES or path in stack:
            return
        stack.append(path)
        words = []
        try:
            tokens = list(nginx_tokens(path))
        except OSError:
            tokens = []
        for word, line in tokens:
            if word not in (";", "{", "}"):
                words.append((word, line))
                continue
            if word == "}":
                if blocks:
                    blocks.pop()
                words = []
                continue
            if not words:
                continue
            name, args, number = words[0][0], [w for w, _ in words[1:]], words[0][1]
            words = []
            if word == "{":
                blocks.append(name)
                if name == "server" and "http" in blocks:
                    servers.append({"names": [], "logs": [], "own": False, "where": f"{path}:{number}",
                                    "listen": []})
                continue
            here = None
            if blocks and blocks[-1] == "server" and servers:
                here = servers[-1]
            elif blocks and blocks[-1] == "http":
                here = http
            if name == "include" and args:
                for p in included(args[0], root):
                    walk(p)
            elif name == "server_name" and here is not None and here is not http:
                here["names"] += args
            elif name == "listen" and here is not None and here is not http and args:
                here["listen"].append(args[0])
            elif name == "access_log" and here is not None and args:
                here["own"] = True  # replaces the inherited ones, even when it cannot be followed
                if args[0] == "off":
                    continue
                if "$" in args[0] or args[0].startswith("syslog:"):
                    warnings.append(f"nginx: access_log {args[0]} ({path}:{number}): variable or "
                                    "syslog, cannot be followed")
                else:
                    here["logs"].append((args[0], args[1:], f"{path}:{number}"))
        stack.pop()

    walk(conf)
    found = {}
    for s in servers:
        logs = s["logs"] if s["own"] else http["logs"] if http["own"] else \
            [(NGINX_DEFAULT_LOG, [], f"{s['where']} (default)")]
        for path, extra, where in logs:
            if not os.path.isabs(path):
                path = os.path.join(root, path)
            f = found.get(path)
            if f is None:
                f = found[path] = Found("nginx", path, where)
                f.default = path == NGINX_DEFAULT_LOG and not (s["own"] or http["own"])
            elif s["own"] or http["own"]:
                f.default = False  # also written explicitly by another block
            f.add_names(s["names"])
            f.public = f.public or not s["listen"] or not all(map(loopback, s["listen"]))
            block = f"server {{listen {', '.join(s['listen']) or '80'}}}"
            if block not in f.blocks:
                f.blocks.append(block)
            if any(a.startswith("if=") for a in extra):
                note = "conditional (if=): some requests are not logged"
                if note not in f.notes:
                    f.notes.append(note)
    return list(found.values())



def sample(path):
    """What fobots understands of the last lines of a log: {lines, ok, public, duration, error}."""
    info = {"lines": 0, "ok": 0, "public": 0, "duration": 0, "error": None}
    try:
        with open(path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - SAMPLE_BYTES))
            data = f.read()
    except FileNotFoundError:
        info["error"] = "absent (the daemon will wait for it)"
        return info
    except OSError as e:
        info["error"] = f"unreadable: {e.strerror}"
        return info
    lines = data.decode("utf-8", "replace").splitlines()
    if size > SAMPLE_BYTES:
        lines = lines[1:]  # the first one is cut
    for line in lines[-SAMPLE_LINES:]:
        info["lines"] += 1
        m = FULL_RE.match(line)
        if not m:
            continue
        info["ok"] += 1
        info["duration"] += duration_field(m.group(8)) is not None
        try:
            info["public"] += ipaddress.ip_address(m.group(1)).is_global
        except ValueError:
            pass
    return info


def verdict(info):
    """None if the log can be followed, otherwise why it is left commented out."""
    n = info["lines"]
    if n and info["ok"] < n / 2:
        return "format not recognised (combined, or vhost_combined, is expected)"
    if info["ok"] >= 20 and not info["public"]:
        return ("no public client address: behind a proxy? The log must hold the real client "
                "(mod_remoteip, real_ip_header)")
    return None


def describe(info):
    if info["error"]:
        return info["error"]
    n = info["lines"]
    if not n:
        return "empty for now"
    pct = lambda k: round(100 * info[k] / n)  # noqa: E731
    return (f"last {n} line{'s' if n > 1 else ''}: {pct('ok')} % recognised, {pct('public')} % public clients, "
            f"duration at the end: {'yes' if info['duration'] else 'no'}")



def section_names(found):
    """A distinct [site:NAME] per log: its first host name, otherwise the file name."""
    used, out = set(), []
    for f in found:
        base = f.names[0] if f.names else \
            re.sub(r"(\.access)?\.log$|access\.log$", "", os.path.basename(f.path)).strip("._-") or f.server
        base = re.sub(r"[^\w.-]", "_", base)
        name, i = base, 2
        while name in used:
            name, i = f"{base}-{i}", i + 1
        used.add(name)
        out.append(name)
    return out


def discover(apache_confs=APACHE_CONFS, nginx_confs=NGINX_CONFS):
    """([Found], [configuration files read], [warnings]); each log once, with its sample."""
    found, read, seen, warnings = [], [], set(), []
    for confs, fn in ((apache_confs, apache_logs), (nginx_confs, nginx_logs)):
        for conf in confs:
            if os.path.isfile(conf):
                read.append(conf)
                for f in fn(conf, warnings):
                    real = os.path.realpath(f.path)
                    if real not in seen:
                        seen.add(real)
                        found.append(f)
                break  # the first configuration present of each server
    for f in found:
        f.info = sample(f.path)
        f.reason = verdict(f.info)
        if f.reason is None and f.server == "nginx" and not f.public:
            f.reason = "its server blocks only listen on the loopback (status page, internal service)"
        if f.reason is None and f.default and not os.path.exists(f.path):
            f.reason = (f"no access_log in these server blocks, and {f.path} (nginx's default "
                        "path on Debian) does not exist: they probably log elsewhere or nothing")
    return found, read, warnings


def config_text(found, read, warnings=(), today=None):
    today = today or datetime.now().strftime("%Y-%m-%d")
    out = [f"# Written by `fobots init` on {today}, from: {', '.join(read) or 'nothing'}.",
           "# All the options: /usr/share/doc/fobots/fobots.conf.example (or the README)."]
    out += [f"# Not followed: {w}" for w in warnings]
    out += ["[fobots]",
           "# Observation: nothing is banned, the journal shows what would be",
           "# (journalctl -u fobots). After a few days, remove this line and restart",
           "# (systemctl restart fobots).",
           "dry_run = yes",
           "",
           "threshold = 5        # req/s of a range above which it is banned (see `fobots analyse`)",
           "sustain = 5          # consecutive seconds above the threshold",
           "window = 60",
           "ban_time = 1h",
           "# ignore_path = ^/(assets/|favicon|robots\\.txt)   # cheap static pages, see `fobots analyse`",
           "# load_signal = probe   # check the URL first: fobots probe --url HOST@https://127.0.0.1/page",
           "# load_probe_url = HOST@https://127.0.0.1/some-dynamic-page"]
    for f, name in zip(found, section_names(found)):
        prefix = "# " if f.reason else ""
        out += ["", f"{prefix}[site:{name}]",
                f"# {f.server}: {f.where}" + (f", {' '.join(f.blocks[:4])}" if f.blocks else "")]
        if f.names:
            out.append(f"# hosts: {', '.join(f.names[:8])}{' …' if len(f.names) > 8 else ''}")
        out.append(f"# {describe(f.info)}")
        out += [f"# {n}" for n in f.notes]
        if f.reason:
            out.append(f"# LEFT OUT: {f.reason}")
        out.append(f"{prefix}log = {f.path}")
    return "\n".join(out) + "\n"



def own_addresses():
    """Public addresses of the machine (`ip -o addr`): never to ban (a probe or a cron job that
    requests the public name comes from them)."""
    try:
        r = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = []
    for m in re.finditer(r"\binet6? ([0-9a-fA-F.:]+)/\d+", r.stdout):
        try:
            a = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if a.is_global and a not in out:
            out.append(a)
    return out


def admin_address(environ=None):
    """Address of the administrator's SSH session (SSH_CONNECTION, otherwise `who -m`: sudo
    removes the variable)."""
    environ = os.environ if environ is None else environ
    text = (environ.get("SSH_CONNECTION") or environ.get("SSH_CLIENT") or "").split()[:1]
    if not text:
        try:
            r = subprocess.run(["who", "-m", "--ips"], capture_output=True, text=True, timeout=5)
            m = re.search(r"\(([0-9a-fA-F.:]+)\)", r.stdout) or re.search(r"\s([0-9a-fA-F.:]{7,})\s*$", r.stdout)
            text = [m.group(1)] if m else []
        except (OSError, subprocess.TimeoutExpired):
            text = []
    try:
        a = ipaddress.ip_address(text[0]) if text else None
    except ValueError:
        return None
    return a if a is not None and a.is_global else None


def welcome_additions(existing, own=None, admin=None):
    """Lines to add to the welcome list: the machine and the administrator, unless covered."""
    today = datetime.now().strftime("%Y-%m-%d")
    lines = []
    for addr, why in [(a, "this machine") for a in (own or [])] + \
            ([(admin, "administrator's SSH session")] if admin else []):
        net = ipaddress.ip_network(addr)
        if any(net.version == n.version and net.subnet_of(n) for n in existing):
            continue
        existing = list(existing) + [net]
        lines.append(f"{net}  # {why} (fobots init, {today})")
    return lines
