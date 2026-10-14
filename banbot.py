#!/usr/bin/env python3
"""banbot : démon qui bannit (nftables) les plages d'IP trop agressives.

Lit en continu un access log au format « combined » (nginx / Apache / GitLab),
compte les requêtes par plage d'IP et par seconde, et ajoute la plage fautive au
set nftables dès que le seuil est dépassé. Les bans expirent seuls (timeout nft).

  banbot.py run                      # suit le log indiqué dans banbot.conf
  tail -F /var/log/gitlab/nginx/gitlab_access.log | banbot.py run -t 5 -
  banbot.py setup                    # crée table, sets et règles nft (idempotent)
  banbot.py bans                     # bans actifs avec temps restant
  banbot.py welcome add 17.0.0.0/8 # liste welcome + retrait des bans concernés
  banbot.py welcome list

Les plages viennent de RDAP (successeur de whois), interrogé en tâche de fond
seulement pour un préfixe /16 (IPv6 : /32) qui dépasse déjà --prefix-threshold,
avec un budget horaire. Les plages trouvées sont conservées sur disque.
L'état des bans est lu dans nft : on peut relancer le démon sans rien perdre.
Configuration : banbot.conf (voir banbot.conf.example), cherché dans le dossier
courant puis dans /etc/banbot/, ou donné par -f. La ligne de commande l'emporte.
Signaux : SIGUSR1 affiche les plages les plus actives, SIGTERM/SIGINT arrêtent.
"""
import argparse
import configparser
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime
from functools import lru_cache

log = logging.getLogger("banbot")

LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\]')
# Fin d'une ligne « combined » : "METHODE /chemin PROTO" statut taille "referer" "user-agent"
REQ_RE = re.compile(r'"[A-Z]+ (\S+)[^"]*" \d+ \S+ "[^"]*" "([^"]*)"\s*$')
# Première chaîne entre guillemets : la ligne de requête (format common ou combined)
PATH_RE = re.compile(r'"[A-Z]+ (\S+)')
RDAP_URL = "https://rdap.org/ip/{}"  # redirige vers le RIR compétent
SETS = {4: "banned4", 6: "banned6"}
# Une réponse RDAP plus large que ça est rejetée (garde-fou contre 0.0.0.0/0).
MIN_PREFIX = {4: 8, 6: 16}
CONF_DIR = "/etc/banbot"      # configuration et liste welcome (décidées par l'administrateur)
STATE_DIR = "/var/lib/banbot"  # cache RDAP et constats (écrits par le démon)
INSTALL_DIR = "/opt/banbot"
UNIT_PATH = "/etc/systemd/system/banbot.service"
SERVICE_USER = "banbot"
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
RECENT_BAN_SECS = 60  # pas de nouvelle tentative pour une plage juste bannie
MAX_WATCHED = 5000    # IP « surveillées » gardées en mémoire (opt-in --watch-*)
WATCH_RETENTION = 3600  # secondes (temps du log) pendant lesquelles on s'en souvient
WATCH_FILE_KEEP = 30 * 86400  # le fichier des constats est élagué au-delà (au démarrage)
WATCH_EVENT_IPS = 200         # IP enregistrées au plus par ban
# ban_scope = observed : les IP vues (fenêtre `window`) sont regroupées en groupes d'étendue
# bornée ; on bannit les plus actifs, jusqu'à couvrir cette part des requêtes de l'allocation.
OBSERVED_COVERAGE = 0.8
OBSERVED_MAX_GROUPS = 4       # au-delà : trop dispersé, on bannit l'allocation entière
OBSERVED_MAX_IPS = 200_000    # IP suivies au plus (mémoire)
OBSERVED_PREFIX6 = 48         # largeur maximale d'un groupe en IPv6 (réglable en IPv4)
OBSERVED_WIDE6 = 32           # largeur maximale d'un ban de repli en IPv6 (réglable en IPv4)
SCOPES = ("allocation", "observed")

NFT_SETUP = """\
add table inet banbot
add set inet banbot banned4 { type ipv4_addr; flags interval,timeout; }
add set inet banbot banned6 { type ipv6_addr; flags interval,timeout; }
add chain inet banbot input { type filter hook input priority -10; policy accept; }
add rule inet banbot input tcp dport { 80, 443 } ip saddr @banned4 drop
add rule inet banbot input tcp dport { 80, 443 } ip6 saddr @banned6 drop
"""


# --- utilitaires -------------------------------------------------------------

@lru_cache(maxsize=4096)
def parse_ts(s):
    return int(datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp())


def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd])", s)
    if not m:
        raise argparse.ArgumentTypeError(f"durée invalide : {s!r} (ex. 30m, 1h, 1d)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def addr_cls(ver):
    return ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address


def range_nets(r):
    ver, start, end = r
    return list(ipaddress.summarize_address_range(addr_cls(ver)(start), addr_cls(ver)(end)))


def fmt_range(r):
    nets = range_nets(r)
    if len(nets) == 1:
        return str(nets[0])
    return f"{addr_cls(r[0])(r[1])}-{addr_cls(r[0])(r[2])}"


def prefix_of(addr):
    return ipaddress.ip_network((addr, 16 if addr.version == 4 else 32), strict=False)


def cluster_ips(ips, span):
    """Groupes d'IP : [(adresse entière, requêtes)] -> [[début, fin, requêtes, nb d'IP]].
    Balayage glouton : un groupe s'étend tant que son étendue reste sous `span` adresses ;
    il est borné par ses IP extrêmes (intervalle observé), pas par un préfixe CIDR, donc
    deux IP voisines de part et d'autre d'une frontière de bloc restent ensemble."""
    out = []
    for a, n in sorted(ips):
        if out and a - out[-1][0] < span:
            c = out[-1]
            c[1], c[2], c[3] = a, c[2] + n, c[3] + 1
        else:
            out.append([a, a, n, 1])
    return out


def pick_groups(groups, coverage, max_groups):
    """Les groupes les plus actifs qui couvrent `coverage` des requêtes, ou None si il en
    faudrait plus de `max_groups`."""
    total = sum(g[2] for g in groups)
    picked, got = [], 0
    for g in sorted(groups, key=lambda g: -g[2]):
        picked.append(g)
        got += g[2]
        if got >= coverage * total:
            break
    return picked if len(picked) <= max_groups else None


def wide_blocks(ips, lo, hi, shift, coverage):
    """Repli quand le trafic est dispersé : les blocs alignés de 2**shift adresses (découpés aux
    bornes [lo, hi] de l'allocation) qui portent `coverage` des requêtes -> [(début, fin)]."""
    per = Counter()
    for a, n in ips:
        per[a >> shift] += n
    total, got, out = sum(per.values()), 0, []
    for b, n in per.most_common():
        out.append((max(b << shift, lo), min(((b + 1) << shift) - 1, hi)))
        got += n
        if got >= coverage * total:
            break
    return sorted(out)


def subtract(net, welcome):
    """Morceaux de `net` qui ne touchent pas la liste welcome (CIDR : inclus ou disjoint)."""
    for w in welcome:
        if w.version == net.version and net.overlaps(w):
            if net.subnet_of(w):
                return []
            pieces = []
            for piece in net.address_exclude(w):
                pieces += subtract(piece, welcome)
            return pieces
    return [net]


# --- plages RDAP -------------------------------------------------------------

class RangeStore:
    """Plages (version, début, fin) connues, persistées en JSON (écriture atomique)."""

    def __init__(self, path):
        self.path = path
        self.version = 0  # incrémenté à chaque ajout (invalide les mémos)
        self._lock = threading.Lock()
        self.ranges = ()
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    # tolère l'ancien format (version, début, fin, nom)
                    self.ranges = tuple({tuple(r[:3]) for r in json.load(f)})
            except (OSError, ValueError) as e:
                log.warning("cache %s illisible (%s), on repart de zéro", path, e)

    def find(self, addr):
        """Plage la plus précise contenant addr, ou None."""
        a, best = int(addr), None
        for r in self.ranges:
            if r[0] == addr.version and r[1] <= a <= r[2]:
                if best is None or r[2] - r[1] < best[2] - best[1]:
                    best = r
        return best

    def add(self, r):
        with self._lock:
            if r in self.ranges:
                return
            self.ranges = self.ranges + (r,)
            self.version += 1
            if self.path:
                tmp = self.path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.ranges, f)
                os.replace(tmp, self.path)


class RdapError(Exception):
    def __init__(self, msg, retry=1800, pause=0):
        super().__init__(msg)
        self.retry = retry  # secondes avant de retenter ce préfixe
        self.pause = pause  # secondes de pause globale (429)


def fetch_rdap(ip):
    req = urllib.request.Request(RDAP_URL.format(ip),
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": "banbot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        return (ipaddress.ip_address(data["startAddress"]),
                ipaddress.ip_address(data["endAddress"]))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            ra = e.headers.get("Retry-After", "")
            pause = int(ra) if ra.isdigit() else 600
            raise RdapError("HTTP 429", retry=pause, pause=pause)
        raise RdapError(f"HTTP {e.code}", retry=1800)
    except (OSError, ValueError, KeyError) as e:
        raise RdapError(f"{type(e).__name__}: {e}", retry=300)


class Rdap(threading.Thread):
    """Interroge RDAP en tâche de fond, avec délai, budget horaire et pause sur 429."""

    def __init__(self, store, delay, per_hour, fetch=None):
        super().__init__(daemon=True, name="rdap")
        self.store, self.delay, self.per_hour = store, delay, per_hour
        self.fetch = fetch or fetch_rdap
        self.q = queue.Queue()
        self.pending = set()  # préfixes en attente (un seul à la fois)
        self.retry = {}       # préfixe -> instant (monotonic) avant nouvelle tentative
        self.times = deque()  # instants des dernières requêtes
        self.paused_until = 0.0

    def request(self, addr, prefix):
        if prefix in self.pending or self.retry.get(prefix, 0) > time.monotonic():
            return
        self.pending.add(prefix)
        self.q.put((addr, prefix))

    def _wait_budget(self):
        now = time.monotonic()
        if now < self.paused_until:
            time.sleep(self.paused_until - now)
        while True:
            now = time.monotonic()
            while self.times and now - self.times[0] > 3600:
                self.times.popleft()
            if len(self.times) < self.per_hour:
                break
            time.sleep(self.times[0] + 3600 - now + 1)
        if self.times:
            wait = self.times[-1] + self.delay - now
            if wait > 0:
                time.sleep(wait)
        self.times.append(time.monotonic())

    def run(self):
        while True:
            addr, prefix = self.q.get()
            try:
                self._wait_budget()
                start, end = self.fetch(str(addr))
                ver = addr.version
                if not int(start) <= int(addr) <= int(end):
                    raise RdapError("la plage ne contient pas l'IP", retry=3600)
                if int(end) - int(start) + 1 > 2 ** (addr.max_prefixlen - MIN_PREFIX[ver]):
                    raise RdapError(f"plage trop large ({start}-{end})", retry=3600)
                r = (ver, int(start), int(end))
                self.store.add(r)
                log.info("RDAP %s -> %s", addr, fmt_range(r))
            except RdapError as e:
                log.warning("RDAP %s : %s", addr, e)
                self.retry[prefix] = time.monotonic() + e.retry
                if e.pause:
                    self.paused_until = time.monotonic() + e.pause
                    log.warning("RDAP en pause %d s", e.pause)
            except Exception:
                log.exception("RDAP %s : erreur inattendue", addr)
                self.retry[prefix] = time.monotonic() + 300
            finally:
                self.pending.discard(prefix)


# --- nftables ----------------------------------------------------------------

class NftError(Exception):
    pass


def val_nets(val):
    if isinstance(val, str):
        return [ipaddress.ip_network(val, strict=False)]
    if "prefix" in val:
        p = val["prefix"]
        return [ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)]
    if "range" in val:
        a, b = (ipaddress.ip_address(x) for x in val["range"])
        return list(ipaddress.summarize_address_range(a, b))
    return []


def parse_elems(data):
    """[(réseau, secondes restantes ou None)] depuis la sortie de `nft -j list set`."""
    out = []
    for item in data.get("nftables", []):
        for e in (item.get("set") or {}).get("elem", []):
            expires = None
            if isinstance(e, dict) and "elem" in e:
                expires, e = e["elem"].get("expires"), e["elem"]["val"]
            out += [(n, expires) for n in val_nets(e)]
    return out


class Nft:
    """Appels à nft ; en dry-run, affiche les scripts et simule les sets en mémoire."""

    def __init__(self, binary="nft", dry_run=False):
        self.binary, self.dry_run = binary, dry_run
        self.sim = {4: [], 6: []}

    def _run(self, args, stdin=None):
        try:
            return subprocess.run([self.binary, *args], input=stdin, capture_output=True,
                                  text=True, timeout=15)
        except FileNotFoundError:
            raise NftError(f"commande {self.binary!r} introuvable : installer nftables "
                           "(ex. apt install nftables) ou donner --nft-bin")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NftError(f"{self.binary} : {e}")

    def table_exists(self):
        return self._run(["list", "table", "inet", "banbot"]).returncode == 0

    def setup(self):
        r = self._run(["-f", "-"], NFT_SETUP)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def selftest(self):
        """Vérifie sur une table jetable que nft gère les sets d'intervalles avec expiration
        et que `nft -j` se lit comme le démon l'attend. -> (ok, expires_visible, message)."""
        t, net = "banbot_selftest", ipaddress.ip_network("10.99.0.0/16")
        self._run(["delete", "table", "inet", t])  # reste d'un essai précédent
        try:
            r = self._run(["-f", "-"], f"add table inet {t}\n"
                          f"add set inet {t} s {{ type ipv4_addr; flags interval,timeout; }}\n"
                          f"add element inet {t} s {{ {net} timeout 30s }}\n")
            if r.returncode:
                return False, False, r.stderr.strip() or "création de la table d'essai refusée"
            r = self._run(["-j", "list", "set", "inet", t, "s"])
            if r.returncode:
                return False, False, "nft -j non disponible : " + (r.stderr.strip() or "échec")
            try:
                found = [(n, e) for n, e in parse_elems(json.loads(r.stdout))]
            except ValueError:
                return False, False, "sortie de nft -j illisible"
            if not any(n == net for n, _ in found):
                return False, False, "élément ajouté mais absent de la sortie JSON de nft"
            return True, any(e is not None for _, e in found), ""
        finally:
            self._run(["delete", "table", "inet", t])

    def elements(self, ver):
        if self.dry_run:
            return list(self.sim[ver])
        r = self._run(["-j", "list", "set", "inet", "banbot", SETS[ver]])
        if r.returncode:
            raise NftError(r.stderr.strip() or "set introuvable (lancer `setup` ?)")
        return parse_elems(json.loads(r.stdout))

    def _script(self, script):
        if self.dry_run:
            print(script, end="", flush=True)
            return
        r = self._run(["-f", "-"], script)
        if r.returncode:
            raise NftError(r.stderr.strip())

    def apply(self, ver, deletes, adds, restore=()):
        """Retraits puis ajouts [(réseau, timeout en s)], en deux transactions : nft 0.9.x refuse
        qu'une même transaction retire des éléments puis en ajoute un qui les recouvre
        (« interval overlaps with an existing one »). Si l'ajout échoue, `restore`
        [(réseau, timeout)] remet les éléments retirés."""
        name = SETS[ver]
        if deletes:
            self._script(f"delete element inet banbot {name} "
                         f"{{ {', '.join(str(n) for n in deletes)} }}\n")
            if self.dry_run:
                gone = set(deletes)
                self.sim[ver] = [(n, e) for n, e in self.sim[ver] if n not in gone]
        if adds:
            try:
                self._add(ver, adds)
            except NftError:
                if restore:
                    try:
                        self._add(ver, restore)
                    except NftError as e:
                        log.error("bans retirés non rétablis : %s", e)
                raise

    def _add(self, ver, adds):
        elems = ", ".join(f"{n} timeout {max(1, int(t))}s" for n, t in adds)
        self._script(f"add element inet banbot {SETS[ver]} {{ {elems} }}\n")
        if self.dry_run:
            self.sim[ver] += [(n, t) for n, t in adds]


# --- liste welcome et bans ---------------------------------------------------

class Welcome:
    """Liste de CIDR relue automatiquement quand le fichier change."""

    def __init__(self, path):
        self.path, self.nets, self.mtime = path, [], "unset"
        self.reload()

    def reload(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            mtime = None
        if mtime == self.mtime:
            return
        self.mtime, nets = mtime, []
        if mtime is not None:
            with open(self.path) as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        log.warning("liste welcome : ligne ignorée %r", line)
        self.nets = nets
        log.info("liste welcome : %d plage(s) dans %s%s", len(nets), os.path.abspath(self.path),
                 "" if mtime is not None else " (fichier absent)")

    @staticmethod
    def append(path, nets):
        with open(path, "a") as f:
            for n in nets:
                f.write(f"{n}  # ajouté le {datetime.now():%Y-%m-%d %H:%M}\n")


class Banner:
    def __init__(self, nft, welcome, ban_seconds):
        self.nft, self.welcome, self.ban_seconds = nft, welcome, ban_seconds

    def ban(self, rng, reason, seconds=None):
        """Bannit la plage (hors liste welcome, sans doublon ni conflit nft)."""
        seconds = seconds or self.ban_seconds
        self.welcome.reload()
        ver = rng[0]
        pieces = []
        for n in range_nets(rng):
            pieces += subtract(n, self.welcome.nets)
        pieces = list(ipaddress.collapse_addresses(pieces))
        if not pieces:
            log.info("%s : entièrement dans la liste welcome, pas de ban", fmt_range(rng))
            return False
        for attempt in (1, 2):
            elems = self.nft.elements(ver)
            existing = [n for n, _ in elems]
            adds, deletes = [], set()
            for p in pieces:
                if any(p.subnet_of(e) for e in existing):
                    continue  # déjà couvert
                adds.append((p, seconds))
                deletes.update(e for e in existing if e.subnet_of(p))
            if not adds:
                log.debug("%s : déjà banni", fmt_range(rng))
                return False
            try:
                restore = [(n, e or seconds) for n, e in elems if n in deletes]
                self.nft.apply(ver, sorted(deletes, key=lambda n: n.network_address), adds, restore)
                break
            except NftError as e:
                # souvent un élément expiré entre la lecture et le retrait : on relit
                log.warning("nft a refusé (tentative %d) : %s", attempt, e)
                if attempt == 2:
                    raise
        log.info("BAN %s pour %d s (%s)%s", ", ".join(str(a) for a, _ in adds),
                 seconds, reason,
                 f", {len(deletes)} ban(s) inclus remplacé(s)" if deletes else "")
        return True


def welcome_add(nft, net, ban_seconds):
    """Retire des sets les bans qui touchent `net` ; garde le reste des plus larges."""
    ver = net.version
    existing = nft.elements(ver)
    deletes, adds, restore = [], [], []
    for e, exp in existing:
        if not e.overlaps(net):
            continue
        deletes.append(e)
        restore.append((e, exp or ban_seconds))
        if not e.subnet_of(net):  # `net` est strictement dans e : on regarde le reste
            adds += [(p, exp or ban_seconds) for p in e.address_exclude(net)]
    if deletes:
        nft.apply(ver, deletes, adds, restore)
    return deletes, adds


# --- constats « surveillés » (fichier JSON lignes) ---------------------------

def append_event(path, event):
    try:
        with open(path, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("écriture de %s impossible : %s", path, e)


def read_events(path, since):
    """Constats plus récents que `since` (epoch) ; les lignes illisibles sont ignorées."""
    out = []
    try:
        f = open(path)
    except OSError:
        return out
    with f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("t", 0) >= since:
                out.append(ev)
    return out


def trim_events(path, keep=WATCH_FILE_KEEP):
    """Retire les constats trop anciens (écriture atomique)."""
    if not os.path.exists(path):
        return
    events = read_events(path, time.time() - keep)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        log.warning("élagage de %s impossible : %s", path, e)


# --- charge du serveur --------------------------------------------------------

LOAD_DEFAULTS = {"psi": (20.0, 50.0), "loadavg": (1.0, 2.0)}  # (tendu, critique)
LEVELS = ("normal", "tendu", "critique")


def read_psi(resource):
    """Pression `some avg10` (en %) : part des 10 dernières secondes passée à attendre."""
    with open(f"/proc/pressure/{resource}") as f:
        for line in f:
            kind, *fields = line.split()
            if kind == "some":
                return float(dict(x.split("=") for x in fields)["avg10"])
    raise OSError(f"/proc/pressure/{resource} : ligne 'some' absente")


def read_load(signal):
    if signal == "psi":
        return max(read_psi("cpu"), read_psi("io"))
    return os.getloadavg()[0] / (os.cpu_count() or 1)


class LoadMonitor(threading.Thread):
    """Mesure la charge toutes les `interval` s et en déduit un niveau (0, 1, 2).

    On monte tout de suite, on redescend d'un niveau seulement après `recover`
    secondes continues sous le palier (hystérésis), pour éviter les oscillations."""

    def __init__(self, signal, tense, critical, recover, factors, sampler=None,
                 interval=5.0, report=300.0):
        super().__init__(daemon=True, name="load")
        self.signal, self.thresholds = signal, (tense, critical)
        self.recover, self.factors = recover, (1.0, *factors)
        self.sampler = sampler or (lambda: read_load(signal))
        self.interval, self.report = interval, report
        self.level, self.value, self.below_since = 0, 0.0, None

    @property
    def factor(self):
        return self.factors[self.level]

    def describe(self):
        return f"{self.signal}={self.value:.2f}, niveau {LEVELS[self.level]} (x{self.factor:g})"

    def step(self, now):
        try:
            self.value = v = self.sampler()
        except (OSError, ValueError) as e:
            log.warning("mesure de charge impossible : %s", e)
            return
        target = sum(v >= t for t in self.thresholds)
        if target >= self.level:
            self.below_since = None
            if target > self.level:
                self.level = target
                log.warning("charge : %s", self.describe())
        elif self.below_since is None:
            self.below_since = now
        elif now - self.below_since >= self.recover:
            self.level -= 1
            self.below_since = None
            log.info("charge : %s", self.describe())

    def run(self):
        last_report = 0.0
        while True:
            now = time.monotonic()
            self.step(now)
            if now - last_report >= self.report:
                last_report = now
                log.info("charge : %s", self.describe())
            time.sleep(self.interval)


class NoLoad:
    """Charge ignorée : seuils et durées de ban inchangés."""
    level, factor = 0, 1.0

    def describe(self):
        return "charge non surveillée"


# --- cibles (un log par hôte) -------------------------------------------------

class Site:
    """Une cible : un log (un par hôte virtuel) et ses règles d'exclusion du comptage.
    Un hôte joignable sous plusieurs noms (CNAME) n'a qu'un log, donc qu'une cible."""

    def __init__(self, name, log_path, prefixes=(), regex=None, all=False):
        self.name, self.log, self.all = name, log_path, all
        self.prefixes = tuple(prefixes)
        self.regex = re.compile(regex) if regex else None
        self.lines = self.ignored = 0  # statistiques (SIGUSR1)

    @property
    def has_path_rules(self):
        return bool(self.prefixes or self.regex)

    def ignores(self, path):
        if self.prefixes and path.startswith(self.prefixes):
            return True
        return self.regex is not None and self.regex.search(path) is not None

    def describe(self):
        if self.all:
            return "tout est exclu"
        parts = []
        if self.prefixes:
            parts.append("préfixes " + ", ".join(self.prefixes))
        if self.regex:
            parts.append(f"regex {self.regex.pattern!r}")
        return "; ".join(parts) or "aucune exclusion propre"


def run_sites(det, sites, from_start, queue_size=200_000):
    """Suit tous les logs (un thread par log) ; un seul fil traite les lignes, donc le
    comptage par plage reste global et sans verrou. La file bornée limite la mémoire :
    si le traitement prend du retard, les lecteurs attendent (rien n'est perdu)."""
    q = queue.Queue(maxsize=queue_size)

    def reader(site):
        for line in follow(site.log, from_start):
            q.put((site, line))

    for site in sites:
        threading.Thread(target=reader, args=(site,), daemon=True, name=f"log-{site.name}").start()
    while True:
        try:
            site, line = q.get(timeout=1)  # timeout : laisse passer les signaux
        except queue.Empty:
            continue
        det.feed_line(line, site)


# --- détection ---------------------------------------------------------------

class Detector:
    def __init__(self, threshold, prefix_threshold, sustain, window, store, banner, rdap,
                 load=None, min_threshold=1.0, min_ban_seconds=60, watch=None,
                 watch_file=None, ignore_path=None, sites=(), scope="allocation",
                 observed_prefix=20, escalate=4, wide_prefix=16):
        self.base_threshold, self.base_prefix_threshold = threshold, prefix_threshold
        self.load, self.min_threshold, self.min_ban = load or NoLoad(), min_threshold, min_ban_seconds
        self.sustain, self.window = sustain, window
        self.store, self.banner, self.rdap = store, banner, rdap
        self.counts = defaultdict(dict)  # clé -> {seconde: n}
        self.over = defaultdict(set)     # plage -> secondes au-dessus du seuil
        self.hits = Counter()
        self.recent_ban = {}
        self.memo, self.memo_version = {}, store.version
        self.latest = self.last_purge = 0
        self.skipped = self.ignored = 0
        self.ignore_path = ignore_path  # regex globale : requêtes non comptées (pages statiques)
        self.sites = tuple(sites)       # cibles (statistiques de SIGUSR1)
        self.observed = scope == "observed"
        self.span4 = 2 ** (32 - observed_prefix)
        self.span6 = 2 ** (128 - OBSERVED_PREFIX6)
        self.wide_shift4 = 32 - wide_prefix if wide_prefix else None  # None : allocation entière
        self.wide_shift6 = 128 - OBSERVED_WIDE6 if wide_prefix else None
        self.escalate = escalate        # bans partiels récents d'une allocation avant de la bannir
        self.ips = {}      # ip -> [requêtes, début, dernière seconde, plage] (mode observed)
        self.partial = {}  # plage -> secondes des bans partiels
        self.watch = watch  # (regex agent ou None, regex chemin ou None) ; None = désactivé
        self.watched = {}   # ip -> [requêtes, dernière seconde vue, chemin exemple]
        self.watch_file = watch_file  # constats écrits ici (relus par `banbot.py watched`)

    def watch_match(self, m):
        """Chemin de la requête (m : REQ_RE) si elle correspond aux motifs surveillés, sinon None.
        Tous les motifs fournis doivent correspondre. Les lignes sont comptées comme les
        autres : on ne fait que garder une trace."""
        agent_re, path_re = self.watch
        if (agent_re is None or agent_re.search(m.group(2))) and \
                (path_re is None or path_re.search(m.group(1))):
            return m.group(1)
        return None

    def record_watched(self, ip, sec, path):
        e = self.watched.get(ip)
        if e:
            e[0] += 1
            e[1] = sec
        elif len(self.watched) < MAX_WATCHED:
            self.watched[ip] = [1, sec, path[:80]]

    def report_watched(self, key, seconds):
        """Journalise les IP surveillées contenues dans la plage qui vient d'être bannie."""
        ver, start, end = key
        hit = []
        for ip, (n, _, path) in self.watched.items():
            a = ipaddress.ip_address(ip)
            if a.version == ver and start <= int(a) <= end:
                hit.append((n, ip, path))
        if not hit:
            return
        hit.sort(reverse=True)
        if self.watch_file:
            append_event(self.watch_file, {
                "t": int(time.time()), "range": fmt_range(key), "seconds": seconds,
                "ips": [[ip, n, path] for n, ip, path in hit[:WATCH_EVENT_IPS]]})
        top = hit[:10]
        log.warning("WATCH %s banni : %d IP surveillée(s), %d requête(s) : %s%s ; "
                    "pour les protéger : banbot.py welcome add %s",
                    fmt_range(key), len(hit), sum(n for n, _, _ in hit),
                    ", ".join(f"{ip} ({n} req, {path})" for n, ip, path in top),
                    f" (+{len(hit) - len(top)} autres)" if len(hit) > len(top) else "",
                    " ".join(str(ipaddress.ip_network(ip)) for _, ip, _ in top))

    @property
    def threshold(self):
        """Seuil effectif : abaissé quand la charge monte, sans passer sous le plancher."""
        return self._scaled(self.base_threshold, self.min_threshold)

    @property
    def prefix_threshold(self):
        return self._scaled(self.base_prefix_threshold, self.min_threshold)

    def _scaled(self, value, floor):
        return min(value, max(floor, value * self.load.factor))

    def ban_seconds(self):
        """Durée effective : raccourcie quand la charge monte (on re-juge plus vite)."""
        return int(self._scaled(self.banner.ban_seconds, self.min_ban))

    def feed_line(self, line, site=None):
        m = LINE_RE.match(line)
        if not m:
            self.skipped += 1
            return
        if site is not None:
            site.lines += 1
            if site.all:  # cible entièrement exclue du comptage
                site.ignored += 1
                self.ignored += 1
                return
        if self.ignore_path is not None or (site is not None and site.has_path_rules):
            pm = PATH_RE.search(line)  # illisible : la ligne est comptée normalement
            if pm:
                path = pm.group(1)
                if (self.ignore_path is not None and self.ignore_path.search(path)) or \
                        (site is not None and site.ignores(path)):
                    self.ignored += 1
                    if site is not None:
                        site.ignored += 1
                    return
        tag = None
        if self.watch:
            rm = REQ_RE.search(line)  # demande aussi l'agent (format combined)
            if rm:
                tag = self.watch_match(rm)
        try:
            sec = parse_ts(m.group(2))
        except ValueError:
            self.skipped += 1
            return
        self.feed(m.group(1), sec, tag)

    def feed(self, ip, sec, tag=None):
        key = self.memo.get(ip)
        if self.memo_version != self.store.version or len(self.memo) > 200_000:
            self.memo.clear()
            self.memo_version, key = self.store.version, None
        addr = None
        if key is None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self.skipped += 1
                return
            if not addr.is_global:
                return
            key = self.store.find(addr) or prefix_of(addr)  # plage connue, sinon préfixe
            self.memo[ip] = key
        if sec > self.latest:
            self.latest = sec
            if sec - self.last_purge >= 10:
                self.purge()
        if tag:
            self.record_watched(ip, sec, tag)
        c = self.counts[key]
        n = c[sec] = c.get(sec, 0) + 1
        self.hits[key] += 1
        if isinstance(key, tuple):
            if self.observed:
                self.note_ip(ip, sec, key)
            if n > self.threshold:
                over = self.over[key]
                over.add(sec)
                over.intersection_update(range(sec - self.window + 1, sec + 1))
                if len(over) >= self.sustain:
                    self.trigger(key, sec, n, ip)
        elif n > self.prefix_threshold:
            self.rdap.request(addr or ipaddress.ip_address(ip), key)

    def note_ip(self, ip, sec, key):
        e = self.ips.get(ip)
        if e is None:
            if len(self.ips) < OBSERVED_MAX_IPS:
                self.ips[ip] = [1, sec, sec, key]
        elif sec - e[1] > self.window:  # fenêtre glissante grossière : on repart de zéro
            e[:] = [1, sec, sec, key]
        else:
            e[0] += 1
            e[2], e[3] = sec, key

    def targets(self, key, sec):
        """(plages à bannir, précision pour le journal) pour une allocation qui a déclenché."""
        if not self.observed:
            return [key], ""
        ver = key[0]
        ips = [(int(ipaddress.ip_address(s)), e[0]) for s, e in self.ips.items()
               if e[3] == key and e[2] >= sec - self.window]
        recent = [t for t in self.partial.get(key, ()) if sec - t < self.banner.ban_seconds]
        groups = cluster_ips(ips, self.span4 if ver == 4 else self.span6)
        picked = None
        why = f"escalade : {len(recent)} bans partiels récents"
        if len(recent) < self.escalate and groups:
            picked = pick_groups(groups, OBSERVED_COVERAGE, OBSERVED_MAX_GROUPS)
            why = f"{len(groups)} groupe(s) d'IP, trop dispersé"
        if picked is None:  # repli : blocs larges (ou l'allocation entière), jamais plus étroit
            self.partial.pop(key, None)
            shift = self.wide_shift4 if ver == 4 else self.wide_shift6
            if shift is None or not ips or (key[2] - key[1] + 1) <= (1 << shift):
                return [key], f", {why} : allocation entière"
            blocks = wide_blocks(ips, key[1], key[2], shift, OBSERVED_COVERAGE)
            return ([(ver, a, b) for a, b in blocks],
                    f", {why} : {len(blocks)} bloc(s) de /{(32 if ver == 4 else 128) - shift} "
                    f"au lieu de l'allocation")
        self.partial[key] = recent + [sec]
        covered = sum(g[2] for g in picked) / sum(g[2] for g in groups)
        return ([(ver, g[0], g[1]) for g in picked],
                f", {len(ips)} IP en {len(groups)} groupe(s), {len(picked)} banni(s) "
                f"({covered:.0%} des requêtes)")

    def trigger(self, key, sec, n, ip):
        if sec - self.recent_ban.get(key, -10**12) < RECENT_BAN_SECS:
            return
        self.recent_ban[key] = sec
        thr = self.threshold
        reason = f"{n} req/s > {thr:g}, vu avec {ip}, {self.hits[key]} requêtes au total"
        if self.load.level:
            reason += f", niveau de charge {LEVELS[self.load.level]}"
        targets, detail = self.targets(key, sec)
        reason += detail
        try:
            seconds = self.ban_seconds()
            for t in targets:
                if self.banner.ban(t, reason, seconds) and self.watched:
                    self.report_watched(t, seconds)
        except NftError as e:
            log.error("ban de %s impossible : %s", fmt_range(key), e)

    def purge(self):
        self.last_purge = cutoff = self.latest
        cutoff -= self.window
        for key in list(self.counts):
            d = self.counts[key]
            for s in [s for s in d if s < cutoff]:
                del d[s]
            if not d:
                del self.counts[key]
        for key in list(self.over):
            self.over[key] = {s for s in self.over[key] if s >= cutoff}
            if not self.over[key]:
                del self.over[key]
        self.recent_ban = {k: s for k, s in self.recent_ban.items() if s >= cutoff}
        if self.observed:
            self.ips = {ip: e for ip, e in self.ips.items() if e[2] >= cutoff}
            keep = self.latest - self.banner.ban_seconds
            self.partial = {k: v for k, v in
                            ((k, [t for t in v if t >= keep]) for k, v in self.partial.items()) if v}
        old = self.latest - WATCH_RETENTION
        for ip in [ip for ip, e in self.watched.items() if e[1] < old]:
            del self.watched[ip]

    def dump(self, top=30):
        log.info("--- %d plages suivies, %d lignes illisibles, %d lignes exclues, "
                 "%d IP surveillées, %s ---", len(self.hits), self.skipped, self.ignored,
                 len(self.watched), self.load.describe())
        for site in self.sites:
            log.info("site %s : %d lignes lues, %d exclues", site.name, site.lines, site.ignored)
        for key, n in self.hits.most_common(top):
            label = fmt_range(key) if isinstance(key, tuple) else f"(non résolu) {key}"
            log.info("%10d  %s", n, label)


# --- lecture du log ----------------------------------------------------------

def follow(path, from_start=False, poll=0.5, grace=2.0):
    """Comme `tail -F` : suit le fichier à travers rotation et troncature.

    Après un renommage (logrotate `create`), le serveur écrit encore dans l'ancien
    fichier jusqu'à ce qu'il le rouvre : on le lit `grace` secondes de plus avant
    de passer au nouveau, pour ne perdre aucune ligne."""
    f, inode, buf, first, rotated_at = None, None, b"", True, None
    while True:
        if f is None:
            try:
                f = open(path, "rb")
            except OSError:
                first = False  # le fichier apparaîtra plus tard : on le lira en entier
                time.sleep(poll)
                continue
            inode = os.fstat(f.fileno()).st_ino
            if first and not from_start:
                f.seek(0, os.SEEK_END)
            first, buf = False, b""
        line = f.readline()
        if line:
            buf += line
            if buf.endswith(b"\n"):  # sinon l'écriture est en cours : on attend la suite
                yield buf.decode(errors="replace")
                buf = b""
            continue
        try:
            st = os.stat(path)
        except OSError:
            st = None
        if st is None or st.st_ino != inode:  # rotation : on passera au nouveau fichier
            now = time.monotonic()
            rotated_at = rotated_at or now
            if now - rotated_at < grace:
                time.sleep(0.1)
                continue
            f.close()
            f, rotated_at = None, None
            if st is None:
                time.sleep(poll)
        elif st.st_size < f.tell():          # troncature (copytruncate)
            f.seek(0)
        else:
            time.sleep(poll)


def stdin_is_feed():
    """stdin est-il un flux exploitable (tube ou fichier) ? Ni terminal, ni /dev/null, ni fermé."""
    try:
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode)


def log_lines(args):
    if args.files:  # fichiers donnés en ligne de commande : lus une fois (- = stdin)
        for path in args.files:
            f = sys.stdin if path == "-" else open(path, errors="replace")
            with f:
                yield from f
    else:
        yield from sys.stdin


# --- commandes ---------------------------------------------------------------

def paths(args):
    """(cache RDAP, liste welcome). La liste welcome se trouve à côté de la conf utilisée,
    sinon dans CONF_DIR : jamais relative au dossier courant."""
    wl_base = os.path.dirname(os.path.abspath(args.config)) if args.config else CONF_DIR
    return (args.cache or os.path.join(args.dir, "ip_ranges.json"),
            args.welcome or os.path.join(wl_base, "welcome.txt"))


def ensure_dir(path):
    """Crée le dossier (0750) s'il manque ; arrêt avec un message clair sinon."""
    try:
        os.makedirs(path, mode=0o750, exist_ok=True)
    except OSError as e:
        sys.exit(f"impossible de créer {path} : {e} (créer le dossier avec les bons droits, "
                 "ou donner --dir)")


def watch_file_path(args):
    return args.watch_file or os.path.join(args.dir, "watched.jsonl")


def cmd_run(args):
    cache, wl_path = paths(args)
    ensure_dir(os.path.dirname(os.path.abspath(cache)))
    ensure_dir(os.path.dirname(os.path.abspath(watch_file_path(args))))
    store, wl = RangeStore(cache), Welcome(wl_path)
    nft = Nft(args.nft_bin, args.dry_run)
    try:
        for ver in (4, 6):
            log.info("IPv%d : %d plage(s) déjà bannie(s)", ver, len(nft.elements(ver)))
    except NftError as e:
        log.error("nft : %s", e)
        return 1
    rdap = Rdap(store, args.delay, args.rdap_per_hour)
    rdap.start()
    load = None
    if args.load_signal not in ("none", "psi", "loadavg"):
        log.error("load_signal invalide : %r (none, psi ou loadavg)", args.load_signal)
        return 1
    if args.load_signal != "none":
        signal_name = args.load_signal
        try:
            read_load(signal_name)
        except (OSError, ValueError) as e:
            if signal_name != "psi":
                log.error("charge : %s", e)
                return 1
            log.warning("PSI indisponible (%s), repli sur loadavg", e)
            signal_name = "loadavg"
        d_tense, d_crit = LOAD_DEFAULTS[signal_name]
        load = LoadMonitor(signal_name,
                           d_tense if args.load_tense is None else args.load_tense,
                           d_crit if args.load_critical is None else args.load_critical,
                           args.load_recover, (args.tense_factor, args.critical_factor))
        load.start()
        log.info("surveillance de la charge : %s, paliers %s, retour après %d s",
                 signal_name, load.thresholds, args.load_recover)
    watch = None
    if args.watch_agent or args.watch_path:
        try:
            watch = (re.compile(args.watch_agent) if args.watch_agent else None,
                     re.compile(args.watch_path) if args.watch_path else None)
        except re.error as e:
            log.error("expression régulière invalide : %s", e)
            return 1
        log.info("surveillance des requêtes : agent=%r chemin=%r (comptées normalement, "
                 "journalisées si leur plage est bannie)", args.watch_agent, args.watch_path)
    ignore_path = None
    if args.ignore_path:
        try:
            ignore_path = re.compile(args.ignore_path)
        except re.error as e:
            log.error("expression régulière invalide pour ignore_path : %s", e)
            return 1
        log.info("requêtes exclues du comptage (chemin) : %r", args.ignore_path)
    sites = [Site(d["name"], d["log"], d["prefixes"], d["regex"], d["all"])
             for d in (getattr(args, "sites", None) or [])]
    if args.log:  # log unique de [banbot] ou --log : une cible sans règle propre
        if any(x.log == args.log for x in sites):
            log.error("le log %s est à la fois dans [banbot] et dans une section [site:…]", args.log)
            return 1
        sites.insert(0, Site("défaut", args.log))
    if args.files:
        sites = []  # fichiers donnés en argument : lecture unique, sans suivi
    for x in sites:
        log.info("cible %s : suivi de %s (%s)", x.name, x.log, x.describe())
    if args.ban_scope not in SCOPES:
        log.error("ban_scope invalide : %r (%s)", args.ban_scope, " ou ".join(SCOPES))
        return 1
    if not 8 <= args.observed_prefix <= 32:
        log.error("observed_prefix doit être entre 8 et 32 (IPv4)")
        return 1
    if args.observed_max_prefix and not 8 <= args.observed_max_prefix <= args.observed_prefix:
        log.error("observed_max_prefix doit être 0 (allocation entière) ou entre 8 et "
                  "observed_prefix (%d)", args.observed_prefix)
        return 1
    if not sites and not args.files and not stdin_is_feed():
        log.error("aucun log à suivre : définir `log =` dans [banbot] ou une section [site:NOM] "
                  "avec `log =` (configuration utilisée : %s), ou passer --log FICHIER ; "
                  "pour lire stdin explicitement : `run -`", args.config or "aucune")
        return 1
    watch_file = watch_file_path(args) if watch else None
    if watch_file:
        trim_events(watch_file)
    det = Detector(args.threshold, args.prefix_threshold or args.threshold, args.sustain,
                   args.window, store, Banner(nft, wl, args.ban_seconds), rdap,
                   load, args.min_threshold, args.min_ban_seconds, watch, watch_file,
                   ignore_path, sites, args.ban_scope, args.observed_prefix, args.observed_escalate,
                   args.observed_max_prefix)
    if det.observed:
        log.info("ban_scope observed : groupes d'IP d'au plus /%d (IPv6 /%d), repli en blocs "
                 "de %s si dispersé ou après %d bans partiels", args.observed_prefix,
                 OBSERVED_PREFIX6,
                 f"/{args.observed_max_prefix} (IPv6 /{OBSERVED_WIDE6})"
                 if args.observed_max_prefix else "l'allocation entière", args.observed_escalate)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGUSR1, lambda *_: det.dump())
    if args.config:
        log.info("configuration : %s", args.config)
    log.info("démon prêt : seuil %s req/s, ban %d s, %d plage(s) en cache dans %s",
             args.threshold, args.ban_seconds, len(store.ranges), os.path.abspath(cache))
    try:
        if sites:
            run_sites(det, sites, args.from_start)
        else:  # fichiers (lus une fois) ou stdin
            for line in log_lines(args):
                det.feed_line(line)
    except KeyboardInterrupt:
        pass
    except OSError as e:  # stdin ou fichier illisible
        log.error("lecture impossible : %s", e)
        return 1
    log.info("arrêt")
    return 0


def cmd_setup(args):
    nft = Nft(args.nft_bin, args.dry_run)
    if args.dry_run:
        print(NFT_SETUP, end="")
    elif nft.table_exists():
        print("table inet banbot déjà en place")
    else:
        nft.setup()
        print("table inet banbot créée")
    return 0


def cmd_bans(args):
    nft = Nft(args.nft_bin, args.dry_run)
    for ver in (4, 6):
        for n, exp in sorted(nft.elements(ver), key=lambda e: e[0].network_address):
            print(f"{str(n):<24} {'' if exp is None else f'{exp} s restantes'}")
    return 0


def cmd_watched(args):
    """IP surveillées prises dans un ban (historique + état actuel), pour repérer les faux positifs."""
    path = watch_file_path(args)
    events = read_events(path, time.time() - args.since)
    if not events:
        print(f"aucun constat dans {path} sur cette période (watch_agent / watch_path "
              "activés dans la conf du démon ?)")
        return 0
    active, known = [], False
    if not args.dry_run:
        try:
            nft = Nft(args.nft_bin)
            active = [(n, e) for ver in (4, 6) for n, e in nft.elements(ver)]
            known = True
        except NftError as e:
            print(f"état des bans indisponible ({e}) : colonne ÉTAT inconnue", file=sys.stderr)
    agg = {}
    for ev in events:
        for ip, n, rpath in ev["ips"]:
            a = agg.setdefault(ip, {"bans": 0, "req": 0, "t": 0, "range": "", "path": ""})
            a["bans"] += 1
            a["req"] += n
            if ev["t"] >= a["t"]:
                a.update(t=ev["t"], range=ev["range"], path=rpath)
    rows = []
    for ip, a in agg.items():
        state = "?"
        if known:
            addr = ipaddress.ip_address(ip)
            left = [e for n, e in active if n.version == addr.version and addr in n]
            state = f"actif ({max(e or 0 for e in left)} s)" if left else "expiré"
        a["state"] = state
        rows.append((ip, a))
    if args.active:
        rows = [r for r in rows if r[1]["state"].startswith("actif")]
    rows.sort(key=lambda r: (not r[1]["state"].startswith("actif"), -r[1]["bans"], -r[1]["req"]))
    if not rows:
        print("aucune IP surveillée dans un ban actif")
        return 0
    cmd = "banbot.py welcome add " + " ".join(str(ipaddress.ip_network(ip)) for ip, _ in rows)
    if args.config:
        cmd += f" -f {args.config}"
    if args.cmd:
        print(cmd)
        return 0
    print(f"{'IP':<40} {'BANS':>4} {'REQ':>6}  {'DERNIER BAN':<16} {'PLAGE':<20} {'ÉTAT':<14} ROUTE")
    for ip, a in rows:
        when = datetime.fromtimestamp(a["t"]).strftime("%Y-%m-%d %H:%M")
        print(f"{ip:<40} {a['bans']:>4} {a['req']:>6}  {when:<16} {a['range']:<20} "
              f"{a['state']:<14} {a['path']}")
    print(f"\n{len(rows)} IP sur {args.since / 86400:g} j. Pour toutes les protéger :\n  {cmd}")
    return 0


class Installer:
    """Installation sur Debian/Ubuntu : nftables, utilisateur, dossiers, programme, conf, unité."""

    def __init__(self, args):
        self.args = args
        self.dry = args.dry_run
        self.dest = args.destdir  # préfixe de test : écrit les fichiers sans toucher au système
        self.system = not self.dest and not self.dry

    def path(self, p):
        return os.path.join(self.dest, p.lstrip("/")) if self.dest else p

    def say(self, status, msg):
        if self.dry and status == "ok":  # rien n'est fait : ne pas affirmer le contraire
            status, msg = "..", f"(simulé) {msg}"
        print(f"[{status}] {msg}")

    def said_done(self, msg):
        """Action système (apt, useradd…) : « ok » seulement si elle a vraiment eu lieu."""
        self.say("ok" if self.system or self.dry else "..",
                 msg if self.system or self.dry else f"{msg} (non fait : --destdir)")

    def confirm(self, question):
        if self.args.yes or self.dry:
            return True
        if sys.stdin.isatty():
            return input(f"{question} [o/N] ").strip().lower() in ("o", "oui", "y", "yes")
        sys.exit(f"{question} : réponse impossible hors terminal, relancer avec --yes")

    def run(self, cmd, check=True):
        """Commande système ; avec --dry-run ou --destdir, elle est seulement affichée."""
        if not self.system:
            note = "" if self.dry else "   (ignoré : --destdir)"
            print(f"  $ {' '.join(cmd)}{note}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            sys.exit(f"échec de {' '.join(cmd)} :\n{r.stderr.strip()}")
        return r

    def ensure_dir(self, path, mode, owner=None):
        if self.dry:
            print(f"  créer {path} (mode {mode:o})")
            return
        real = self.path(path)
        os.makedirs(real, exist_ok=True)
        os.chmod(real, mode)
        if owner and self.system:
            shutil.chown(real, *owner)

    def write(self, path, content, mode):
        if self.dry:
            print(f"  écrire {path} (mode {mode:o})")
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
            sys.exit(f"{name} introuvable à côté de {os.path.abspath(__file__)} : "
                     "lancer l'installation depuis un clone du dépôt")
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
            sys.exit(f"Python 3.7 ou plus requis (trouvé {v.major}.{v.minor})")
        self.say("ok", f"Python {v.major}.{v.minor}.{v.micro}")

    def ensure_nft(self):
        binary = self.args.nft_bin
        found = shutil.which(binary)
        if found:
            self.say("ok", f"nft : {found}")
            return
        if not shutil.which("apt-get"):
            self.say("!!", "nft introuvable et apt-get absent : installer le paquet nftables à la main")
            if self.system:
                sys.exit(1)
            return
        if not self.confirm("nft est absent. Installer le paquet nftables avec apt-get ?"):
            sys.exit("nftables est indispensable")
        self.run(["apt-get", "install", "-y", "nftables"])
        self.said_done("nftables installé")

    def selftest(self):
        if not self.system:
            self.say("..", "test de nft (sets d'intervalles avec expiration) : fait à l'installation réelle")
            return
        ok, expires, msg = Nft(self.args.nft_bin).selftest()
        if not ok:
            sys.exit(f"[!!] nft ne convient pas : {msg}\n"
                     "     (noyau sans nf_tables, paquet nftables trop ancien, ou droits ?)")
        self.say("ok", "nft : sets d'intervalles avec expiration, sortie JSON lisible")
        if not expires:
            self.say("..", "cette version de nft n'indique pas le temps restant des bans "
                     "(`bans` et `watched` ne l'affichent donc pas)")

    def ensure_user(self):
        import pwd
        try:
            pwd.getpwnam(SERVICE_USER)
            self.say("ok", f"utilisateur {SERVICE_USER} existe")
        except KeyError:
            self.run(["useradd", "--system", "--user-group", "--no-create-home",
                      "--shell", "/usr/sbin/nologin", SERVICE_USER])
            self.said_done(f"utilisateur {SERVICE_USER} créé")

    def log_paths(self):
        if self.args.log:
            return [self.args.log]
        text = self.read(os.path.join(CONF_DIR, "banbot.conf")) or self.template("banbot.conf.example")
        return re.findall(r"(?m)^\s*log\s*=\s*(\S+)", text)

    @staticmethod
    def group_for(log_file):
        """Groupe donnant accès à ce log s'il n'est pas public (et pas root), sinon adm."""
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
        """Groupes d'accès à tous les logs (--log-group impose le sien)."""
        if self.args.log_group:
            return [self.args.log_group]
        groups = []
        for log_file in self.log_paths():
            g = self.group_for(log_file)
            if g not in groups:
                groups.append(g)
        return groups or ["adm"]

    def install_files(self):
        self.ensure_dir(INSTALL_DIR, 0o755)
        dst = os.path.join(INSTALL_DIR, "banbot.py")
        src = os.path.abspath(__file__)
        if os.path.abspath(self.path(dst)) == src:
            self.say("ok", f"programme déjà en place : {dst}")
        else:
            with open(src) as f:
                self.write(dst, f.read(), 0o755)
            self.say("ok", f"programme : {dst}")

        self.ensure_dir(CONF_DIR, 0o755)
        conf = os.path.join(CONF_DIR, "banbot.conf")
        if self.read(conf) is not None:
            self.say("ok", f"{conf} existe : conservé tel quel")
            if self.args.log:
                self.say("!!", f"--log ignoré : modifier la ligne `log =` de {conf} à la main")
        else:
            text = self.template("banbot.conf.example")
            if self.args.log:
                text = re.sub(r"(?m)^log\s*=.*$", lambda m: f"log = {self.args.log}", text)
            self.write(conf, text, 0o644)
            self.say("ok", f"configuration : {conf}")
        wl = os.path.join(CONF_DIR, "welcome.txt")
        if self.read(wl) is None:
            self.write(wl, "# Plages à ne jamais bannir, un CIDR par ligne.\n"
                       "# Ajouter avec : banbot.py welcome add CIDR (retire aussi les bans concernés)\n", 0o644)
            self.say("ok", f"liste welcome : {wl}")

        self.ensure_dir(STATE_DIR, 0o750, (SERVICE_USER, SERVICE_USER))
        self.say("ok", f"dossier d'état : {STATE_DIR}")

        unit = re.sub(r"(?m)^SupplementaryGroups=.*$", f"SupplementaryGroups={' '.join(self.log_groups())}",
                      self.template("banbot.service.example"))
        if self.read(UNIT_PATH) == unit:
            self.say("ok", f"unité systemd à jour : {UNIT_PATH}")
        else:
            self.write(UNIT_PATH, unit, 0o644)
            self.say("ok", f"unité systemd : {UNIT_PATH} (groupes d'accès aux logs : {' '.join(self.log_groups())})")
            self.run(["systemctl", "daemon-reload"])

    def check_log_access(self):
        logs = self.log_paths()
        if not logs:
            self.say("..", "aucun log configuré : le démon lira stdin")
            return
        for log_file in logs:
            if not self.system:
                self.say("..", f"accès de {SERVICE_USER} à {log_file} : vérifié à l'installation réelle")
                continue
            if not os.path.exists(log_file):
                self.say("!!", f"{log_file} n'existe pas encore (le démon l'attendra) : vérifier le chemin")
                continue
            group = self.args.log_group or self.group_for(log_file)
            r = self.run(["runuser", "-u", SERVICE_USER, "-g", group, "--",
                          "test", "-r", log_file], check=False)
            if r.returncode == 0:
                self.say("ok", f"{SERVICE_USER} peut lire {log_file}")
            else:
                self.say("!!", f"{SERVICE_USER} ne peut pas lire {log_file} : donner l'accès, par ex. "
                         f"`setfacl -m u:{SERVICE_USER}:r {log_file}` (et x sur les dossiers parents), "
                         "ou --log-group")

    def run_all(self):
        if self.system and os.geteuid() != 0:
            sys.exit("l'installation demande les droits root : sudo ./banbot.py install")
        if self.dry:
            print("--dry-run : rien n'est modifié, voici ce qui serait fait\n")
        self.check_python()
        self.ensure_nft()
        self.selftest()
        self.ensure_user()
        self.install_files()
        self.check_log_access()
        if self.args.start:
            self.run(["systemctl", "enable", "--now", "banbot"])
            self.said_done("service activé et démarré")
        elif self.args.enable:
            self.run(["systemctl", "enable", "banbot"])
            self.said_done("service activé au démarrage (non démarré)")
        print(f"""
Étapes suivantes :
  1. vérifier / adapter {CONF_DIR}/banbot.conf (log, seuils)
  2. ajouter vos réseaux à {CONF_DIR}/welcome.txt (administrateurs, CI, supervision)
  3. essai sans rien bannir : {INSTALL_DIR}/banbot.py run --dry-run
  4. démarrer : systemctl enable --now banbot      suivre : journalctl -u banbot -f""")


def cmd_install(args):
    Installer(args).run_all()
    return 0


def cmd_welcome(args):
    _, wl_path = paths(args)
    if args.action == "list":
        for n in Welcome(wl_path).nets:
            print(n)
        return 0
    nets = []
    for x in args.nets:
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            print(f"plage invalide : {x}", file=sys.stderr)
            return 2
    try:
        os.makedirs(os.path.dirname(os.path.abspath(wl_path)), exist_ok=True)
        Welcome.append(wl_path, nets)  # d'abord : le démon cesse de bannir
    except OSError as e:
        print(f"écriture de {wl_path} impossible : {e} (droits ? lancer avec sudo)",
              file=sys.stderr)
        return 1
    nft = Nft(args.nft_bin, args.dry_run)
    for net in nets:
        try:
            deletes, adds = welcome_add(nft, net, args.ban_seconds)
        except NftError as e:
            print(f"{net} ajoutée à {wl_path}, mais nft a échoué : {e}", file=sys.stderr)
            return 1
        print(f"{net} : liste welcome ; {len(deletes)} ban(s) retiré(s)"
              + (f", {len(adds)} morceau(x) du reste conservé(s)" if adds else ""))
    return 0


CONF_KEYS = {  # clé du fichier -> (destination argparse, conversion)
    "dir": ("dir", str), "cache": ("cache", str), "welcome": ("welcome", str),
    "log": ("log", str), "nft_bin": ("nft_bin", str),
    "ban_time": ("ban_seconds", parse_duration),
    "threshold": ("threshold", float), "prefix_threshold": ("prefix_threshold", float),
    "sustain": ("sustain", int), "window": ("window", int),
    "rdap_per_hour": ("rdap_per_hour", int), "delay": ("delay", float),
    "load_signal": ("load_signal", str), "load_tense": ("load_tense", float),
    "load_critical": ("load_critical", float), "load_recover": ("load_recover", parse_duration),
    "tense_factor": ("tense_factor", float), "critical_factor": ("critical_factor", float),
    "min_threshold": ("min_threshold", float), "min_ban_time": ("min_ban_seconds", parse_duration),
    "ignore_path": ("ignore_path", str),
    "ban_scope": ("ban_scope", str), "observed_prefix": ("observed_prefix", int),
    "observed_escalate": ("observed_escalate", int),
    "observed_max_prefix": ("observed_max_prefix", int),
    "watch_agent": ("watch_agent", str), "watch_path": ("watch_path", str),
    "watch_file": ("watch_file", str),
    "from_start": ("from_start", lambda v: v.lower() in ("1", "true", "yes", "oui", "on")),
}
PATH_KEYS = {"dir", "cache", "welcome", "log", "watch_file"}
# /etc d'abord : le résultat ne dépend pas du dossier courant (./banbot.conf sert au développement)
CONF_SEARCH = (os.path.join(CONF_DIR, "banbot.conf"), "banbot.conf")


SITE_KEYS = ("log", "ignore_prefix", "ignore_path", "ignore_all")
TRUE_VALUES = ("1", "true", "yes", "oui", "on")


def load_config(path):
    """Lit [banbot] et les sections [site:NOM] ; les chemins relatifs le sont par rapport au fichier."""
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    try:
        with open(path) as f:
            cp.read_file(f)
    except (OSError, configparser.Error) as e:
        sys.exit(f"configuration {path} illisible : {e}")
    if not cp.has_section("banbot"):
        sys.exit(f"{path} : section [banbot] absente")
    base = os.path.dirname(os.path.abspath(path))

    def fix_path(v):
        v = os.path.expanduser(v.strip())
        return v if os.path.isabs(v) else os.path.join(base, v)

    out = {}
    for key, val in cp["banbot"].items():
        if key not in CONF_KEYS:
            sys.exit(f"{path} : option inconnue {key!r} (connues : {', '.join(CONF_KEYS)})")
        if not val.strip():
            continue
        dest, conv = CONF_KEYS[key]
        if key in PATH_KEYS:
            val = fix_path(val)
        try:
            out[dest] = conv(val.strip())
        except (ValueError, argparse.ArgumentTypeError) as e:
            sys.exit(f"{path} : valeur invalide pour {key} ({val!r}) : {e}")

    sites, seen = [], {}
    for section in cp.sections():
        if section == "banbot":
            continue
        name = section[5:].strip() if section.startswith("site:") else ""
        if not name:
            sys.exit(f"{path} : section [{section}] inconnue (attendu : [banbot] ou [site:NOM])")
        opts = cp[section]
        for key in opts:
            if key not in SITE_KEYS:
                sys.exit(f"{path} : [{section}] option inconnue {key!r} "
                         f"(connues : {', '.join(SITE_KEYS)})")
        if not opts.get("log", "").strip():
            sys.exit(f"{path} : [{section}] : `log` est obligatoire")
        log_file = fix_path(opts["log"])
        if log_file in seen:
            sys.exit(f"{path} : [{section}] et [site:{seen[log_file]}] suivent le même log {log_file}")
        seen[log_file] = name
        prefixes = [x for x in re.split(r"[,\s]+", opts.get("ignore_prefix", "").strip()) if x]
        for x in prefixes:
            if not x.startswith("/"):
                sys.exit(f"{path} : [{section}] ignore_prefix {x!r} doit commencer par /")
        regex = opts.get("ignore_path", "").strip() or None
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                sys.exit(f"{path} : [{section}] ignore_path invalide : {e}")
        sites.append({"name": name, "log": log_file, "prefixes": prefixes, "regex": regex,
                      "all": opts.get("ignore_all", "").strip().lower() in TRUE_VALUES})
    if out.get("log") in seen:
        sys.exit(f"{path} : le log {out['log']} est à la fois dans [banbot] et dans [site:{seen[out['log']]}]")
    if sites:
        out["sites"] = sites
    return out


def main(argv=None):
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("-f", "--config")
    conf_path = pre.parse_known_args(argv)[0].config
    if conf_path is None:
        conf_path = next((c for c in CONF_SEARCH if os.path.exists(c)), None)
    elif not os.path.exists(conf_path):
        sys.exit(f"configuration introuvable : {conf_path}")
    conf = load_config(conf_path) if conf_path else {}

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--config", help="fichier de configuration "
                        "(défaut: /etc/banbot/banbot.conf, puis ./banbot.conf)")
    common.add_argument("--dir", default=STATE_DIR,
                        help=f"dossier d'état : ip_ranges.json, watched.jsonl (défaut: {STATE_DIR})")
    common.add_argument("-c", "--cache", help="fichier des plages RDAP (défaut: DIR/ip_ranges.json)")
    common.add_argument("-w", "--welcome", help="liste welcome (défaut: welcome.txt à côté de la conf, "
                        f"sinon {CONF_DIR}/welcome.txt)")
    common.add_argument("--watch-file",
                        help="fichier des constats surveillés (défaut: DIR/watched.jsonl)")
    common.add_argument("--ban-time", dest="ban_seconds", type=parse_duration, default=3600,
                        help="durée d'un ban : 30m, 1h, 1d… (défaut: 1h)")
    common.add_argument("--nft-bin", default="nft", help="binaire nft (défaut: nft)")
    common.add_argument("--dry-run", action="store_true",
                        help="n'appelle pas nft : affiche les commandes (sets simulés)")
    common.add_argument("-v", "--verbose", action="store_true")

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", parents=[common], help="démon : lit le log et bannit")
    r.add_argument("files", nargs="*",
                   help="logs lus une fois (- = stdin) ; sinon on suit --log, sinon stdin")
    r.add_argument("-l", "--log", help="log à suivre en continu (rotation gérée, comme tail -F)")
    r.add_argument("--from-start", action="store_true",
                   help="avec --log : lit d'abord le contenu existant (défaut: fin du fichier)")
    r.add_argument("-t", "--threshold", type=float, default=5.0,
                   help="req/s d'une plage au-delà desquelles on bannit (défaut: 5)")
    r.add_argument("-p", "--prefix-threshold", type=float,
                   help="req/s d'un préfixe /16 non résolu qui déclenchent une requête RDAP "
                        "(défaut: = --threshold)")
    r.add_argument("--sustain", type=int, default=1,
                   help="nombre de secondes au-dessus du seuil exigées (défaut: 1)")
    r.add_argument("--window", type=int, default=60,
                   help="fenêtre en secondes pour --sustain (défaut: 60)")
    r.add_argument("--load-signal", choices=["none", "psi", "loadavg"], default="none",
                   help="durcit les règles selon la charge : psi (réactif), loadavg "
                        "(charge/cœurs) ou none (défaut)")
    r.add_argument("--load-tense", type=float,
                   help="valeur du signal au niveau tendu (défaut: 20 %% en psi, 1.0 en loadavg)")
    r.add_argument("--load-critical", type=float,
                   help="valeur au niveau critique (défaut: 50 %% en psi, 2.0 en loadavg)")
    r.add_argument("--load-recover", type=parse_duration, default=300,
                   help="durée sous le palier avant de redescendre d'un niveau (défaut: 5m)")
    r.add_argument("--tense-factor", type=float, default=0.5,
                   help="multiplicateur du seuil ET de la durée de ban au niveau tendu (défaut: 0.5)")
    r.add_argument("--critical-factor", type=float, default=0.25,
                   help="idem au niveau critique (défaut: 0.25)")
    r.add_argument("--min-threshold", type=float, default=1.0,
                   help="plancher du seuil effectif en req/s (défaut: 1)")
    r.add_argument("--min-ban-time", dest="min_ban_seconds", type=parse_duration, default=60,
                   help="plancher de la durée de ban effective (défaut: 1m)")
    r.add_argument("--ignore-path", metavar="REGEX",
                   help="opt-in : ne compte pas les requêtes dont le chemin correspond "
                        "(pages statiques peu coûteuses, ex. ^/(assets|uploads)/)")
    r.add_argument("--watch-agent", metavar="REGEX",
                   help="opt-in : journalise (WATCH) les IP dont l'user-agent correspond quand "
                        "leur plage est bannie (ex. ^gitlab-runner) ; ne change pas le comptage")
    r.add_argument("--watch-path", metavar="REGEX",
                   help="restreint --watch-agent aux chemins correspondants (ex. ^/api/v4/) ; "
                        "si les deux sont donnés, les deux doivent correspondre")
    r.add_argument("--ban-scope", choices=SCOPES, default="allocation",
                   help="allocation : on bannit toute la plage RDAP (défaut) ; observed : seulement "
                        "les groupes d'IP vues, à l'intérieur de l'allocation")
    r.add_argument("--observed-prefix", type=int, default=20,
                   help="ban_scope=observed : largeur maximale d'un groupe d'IP, en préfixe IPv4 "
                        "(défaut: 20, soit 4096 adresses ; IPv6 : /48)")
    r.add_argument("--observed-escalate", type=int, default=4,
                   help="ban_scope=observed : bans partiels d'une même allocation (pendant la durée "
                        "d'un ban) avant de bannir l'allocation entière (défaut: 4)")
    r.add_argument("--observed-max-prefix", type=int, default=16,
                   help="ban_scope=observed : si le trafic est dispersé, on bannit des blocs de cette "
                        "largeur (préfixe IPv4, défaut: 16 ; IPv6 : /32) au lieu de l'allocation "
                        "entière ; 0 = allocation entière")
    r.add_argument("--rdap-per-hour", type=int, default=100,
                   help="budget de requêtes RDAP par heure (défaut: 100)")
    r.add_argument("--delay", type=float, default=2.0,
                   help="secondes minimum entre deux requêtes RDAP (défaut: 2)")
    r.set_defaults(fn=cmd_run)

    sub.add_parser("setup", parents=[common],
                   help="crée la table nft si absente").set_defaults(fn=cmd_setup)
    sub.add_parser("bans", parents=[common], help="liste les bans actifs").set_defaults(fn=cmd_bans)

    ins = sub.add_parser("install", parents=[common],
                         help="installe banbot (nftables, utilisateur, dossiers, conf, unité systemd)")
    ins.add_argument("--log", help="log à suivre, écrit dans la conf créée (défaut: celui de l'exemple)")
    ins.add_argument("--log-group", help="groupe donnant accès au log (défaut: détecté, sinon adm)")
    ins.add_argument("--yes", action="store_true", help="répond oui aux questions (installation d'apt)")
    ins.add_argument("--enable", action="store_true", help="active le service au démarrage")
    ins.add_argument("--start", action="store_true", help="active ET démarre le service")
    ins.add_argument("--destdir", help="écrit les fichiers sous ce préfixe sans toucher au système (test)")
    ins.set_defaults(fn=cmd_install)

    wd = sub.add_parser("watched", parents=[common],
                        help="IP surveillées (watch_*) prises dans un ban : faux positifs possibles")
    wd.add_argument("--since", type=parse_duration, default=7 * 86400,
                    help="période à considérer : 12h, 3d… (défaut: 7d)")
    wd.add_argument("--active", action="store_true", help="seulement celles dont le ban est actif")
    wd.add_argument("--cmd", action="store_true",
                    help="n'affiche que la commande `welcome add` correspondante")
    wd.set_defaults(fn=cmd_watched)

    w = sub.add_parser("welcome", parents=[common], help="gère la liste welcome")
    w.add_argument("action", choices=["add", "list"])
    w.add_argument("nets", nargs="*", help="CIDR à ajouter (add)")
    w.set_defaults(fn=cmd_welcome)

    for p in sub.choices.values():
        p.set_defaults(config=conf_path, **conf)  # ligne de commande > conf > défauts
    args = ap.parse_args(argv)
    if args.cmd == "run":
        for name in ("tense_factor", "critical_factor"):
            if not 0 < getattr(args, name) <= 1:
                ap.error(f"--{name.replace('_', '-')} doit être dans ]0, 1]")
    if args.cmd == "welcome" and args.action == "add" and not args.nets:
        ap.error("welcome add : indiquer au moins une plage")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        return args.fn(args)
    except NftError as e:  # nft absent, refus du noyau, droits insuffisants…
        log.error("nft : %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
