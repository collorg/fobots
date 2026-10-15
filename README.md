# fobots

*[Version française](README.fr.md)*

> *'fo' stands for filter out! What were you thinking?*

A daemon that protects a web server (designed for GitLab behind nginx) from overly
aggressive scrapers. It follows the access log, spots the **IP ranges** whose request rate
exceeds a threshold, and adds them to an **nftables** set with a timeout: the traffic is
dropped by the firewall before it reaches nginx and GitLab.

Plain Python 3.7+ (no dependencies), nftables, Linux. On Ubuntu 20.04 (Python 3.8,
kernel 5.4): `apt install nftables` (version 0.9.3).

> Status: banning has been validated in production on Ubuntu 20.04 (Python 3.8, kernel
> 5.4, nftables 0.9.3): load brought down from over 35 to 0.2. The other features
> (example systemd unit, load-based hardening, IPv6, `watch_*` monitoring) have only been
> tested with a fake `nft`. With nftables 0.9.3 (Ubuntu 20.04), `nft list set` only shows
> `timeout 1h` and never `expires`: `bans` and `watched` therefore do not show the remaining
> time. On more recent versions (Ubuntu 24.04, from a user report), `expires` is shown and
> used by these commands. Start with `--dry-run`.

## How it works

1. Each line of the log (nginx/Apache/GitLab *combined* format) is attached to an IP range:
   the RIR allocation that contains it (obtained through RDAP, the successor of whois).
   The owner's details are not kept: only the range matters.
2. Requests are counted per range and per second. When a range exceeds `threshold` req/s
   (for `sustain` consecutive seconds, 5 by default: a page load is a short burst), it is banned for `ban_time`.
3. Unknown ranges are not looked up at random: RDAP is only called (in the background) for a
   `/16` prefix (`/32` in IPv6) that already exceeds `prefix_threshold` req/s, with an hourly
   budget, a delay between requests and a pause on HTTP 429. The ranges found are saved on
   disk (`ip_ranges.json`) and reused.
4. By default the ban covers the **whole allocation**. With `ban_scope = observed`, it
   narrows down to the IPs actually seen: see "Tight bans" below.
5. A ban is a single nft transaction. A range already covered by a wider ban is ignored; a
   range that encloses others replaces them.
6. The ban state is **in nft** (read at startup): the daemon can be restarted without loss,
   and every ban expires by itself.

## Installation

On Debian/Ubuntu, from a clone of the repository:

```
sudo ./fobots.py install --dry-run            # the plan, nothing is modified
sudo ./fobots.py install --log /var/log/gitlab/nginx/gitlab_access.log
```
The command is **idempotent** (run it again to update the program and the unit) and never
touches an existing configuration or welcome list. It:

1. checks Python (3.7+) and installs `nftables` with apt-get if `nft` is missing (asks for
   confirmation, or `--yes`);
2. **tests nft** on a throwaway table: interval sets with timeouts, readable JSON output
   (stops with a message otherwise); reports if this version does not show the remaining
   time of bans;
3. creates the `fobots` system user if missing;
4. installs the command `/usr/local/sbin/fobots` (the launcher, without `.py`) and its modules in
   `/opt/fobots/fobots/`, the configuration in `/etc/fobots/fobots.conf`
   (with `--log` if given), an empty welcome list `/etc/fobots/welcome.txt`, and the state
   directory `/var/lib/fobots` (0750, owned by `fobots`);
5. installs the systemd unit, with the group that gives access to the log (detected,
   otherwise `adm`; `--log-group` to force it), then runs `systemctl daemon-reload`;
6. checks that the `fobots` user can read the log, and says what to do if not.

The service is **neither enabled nor started** by default: adapt the configuration, fill in
the welcome list, try `fobots run --dry-run`, then
`systemctl enable --now fobots` (or run `install` again with `--enable` / `--start`).
`--destdir DIR` writes the files under a prefix without touching the system (tests,
packaging).

By hand, without `install`:

```
./fobots.py setup                          # creates the nft table (idempotent)
cp fobots.conf.example fobots.conf         # then adapt log, thresholds
./fobots.py run --dry-run -v               # shows the bans without touching nft
./fobots.py run                            # the real daemon
```

For a permanent service, see `fobots.service.example` (dedicated user, `CAP_NET_ADMIN`
only, systemd hardening).

Start carefully: `ban_time = 10m`, a threshold that only targets the obvious cases, and keep
a session open (see "Reset").

### Debian package

```
make                 # builds dist/fobots_0.N_all.deb  (N = number of commits)
make VERSION=1.0.0   # imposes the version
make check           # syntax check
make upgrade         # tests, build, then sudo dpkg -i (restarts a running service)
make lint            # lintian
sudo apt install ./dist/fobots_*_all.deb
```
The package installs the same files as `install` (command `/usr/sbin/fobots`, modules in `/opt/fobots/fobots/`, configuration and
`welcome.txt` in `/etc/fobots` as conffiles, systemd unit) and does not start the service.
An upgrade only restarts a service that is already running; `purge` removes
`/var/lib/fobots` and the `fobots` user.

### Tests

```
make test            # python3 -m unittest discover -s tests  (standard library only, about 1 s)
```
The suite covers range grouping, bans (including the nft overlap workaround), detection with
and without `ban_scope = observed`, load levels, configuration errors, log rotation and the
commands (`run --dry-run`, `welcome`, `watched`, `install --destdir`). None of it needs root or
a real `nft`.

```
make integration     # tests/integration.sh: the real nft and kernel, with fake logs
```
The integration test replays generated logs through the real daemon and checks the real nft
set: whole-allocation and tight bans, a wider ban replacing smaller ones (the case nft 0.9.x
refuses in a single transaction), `welcome add`, IPv6 and the kernel expiry. It runs in a
throwaway user+network namespace (`unshare -Urn`): no root, and the machine's own nft rules
are never touched. Run it on the oldest nft you support (Ubuntu 20.04: 0.9.3).

## Load-based hardening

Disabled by default (`load_signal = none`). When enabled, a thread measures the load every
5 s:

- `psi`: `/proc/pressure` pressure (max of cpu and io, `some avg10`, in %), very reactive;
  automatically falls back to `loadavg` if the kernel does not offer it;
- `loadavg`: 1-minute load divided by the number of cores (slower).

Three levels: *normal*, *tense*, *critical*. It goes up immediately; it goes down one level
only after `load_recover` continuously below the threshold. At each level, **the threshold
and the ban duration are multiplied** by the factor (0.5 then 0.25 by default), without going
below `min_threshold` / `min_ban_time`: stricter rules but shorter bans, so ranges are
re-judged sooner. `prefix_threshold` follows the same factor. Example (base 10 req/s, 1 h):
tense = 5 req/s for 30 min, critical = 2.5 req/s for 15 min.

The default levels are **not calibrated** for your server: first run with `--dry-run -v` and
look at the `load: psi=…` lines (every 5 minutes and at each level change) to choose
`load_tense` / `load_critical`. False positives are fixed with `welcome add`.

## One log per host: rules per target

A well-configured server writes **one log per virtual host**. Each log becomes a *target*,
with its own rules, in `fobots.conf`:

```ini
[site:gitlab]
log = /var/log/gitlab/nginx/gitlab_access.log
ignore_path = ^/(assets/|favicon\.ico|robots\.txt)

[site:showcase]                      # entirely static site
log = /var/log/nginx/showcase.access.log
ignore_all = yes

[site:api]                           # no rules of its own: everything is counted
log = /var/log/nginx/api.access.log
```
- `log` (required), `ignore_path` (regex on the path),
  `ignore_all` (nothing is counted for this target), `watch_agent` / `watch_path` (monitoring,
  see below; they replace the `[fobots]` ones for this target).
- Its own rules **add to** the global `ignore_path` of `[fobots]`.
- CNAME aliases of a host have no effect: they end up in the same log, hence in the same
  target. The host name is never read from the lines.
- **Counting stays global per IP range**: requests from all targets add up, since the
  firewall bans a range for all hosts (ports 80/443).
- One thread follows each log (rotation handled); formats may differ from one log to another
  (the IP, the timestamp and the request line are needed).
- The single `log` of `[fobots]` still works (a "default" target with no rules of its own),
  but cannot name the same file as a `[site:…]` section.
- Files given as arguments (`run file.log`) are read once, without following the targets;
  only the global rule applies.
- `SIGUSR1` prints, per target, the lines read and excluded: handy to check that a rule does
  what is expected. `install` gives the service access to all the logs.

## Static pages: do not count them

Opt-in: `ignore_path` (regex on the request path, global or per target) removes the matching
requests from the count. They count neither for a range's threshold nor for triggering RDAP,
and are not noted by `watch_*` either.

```
ignore_path = ^/(assets/|favicon|robots\.txt)
```
**Why:** a single GitLab page load triggers dozens of asset requests within the same second.
Counting them inflates the rate of legitimate visitors and favours false positives. Once the
static files are excluded, the threshold mostly measures expensive requests, and can be
lowered. The path read is the one in the request line (`GET /path?…`): this also works with
the *common* format.

**Caution:**
- Only exclude what is **cheap to serve**. Anchor the regex on **prefixes** of static
  directories (`^/assets/`), not on extensions: `\.js$` or `\.css$` would also exempt repository files
  (`/-/raw/…/x.js`, `/-/blob/…`), which are dynamic and expensive, and which scrapers love.
- A scraper that only requests excluded paths is never banned (which is intended: it is
  cheap), and lines whose request is unreadable are counted.
- **This is not an access authorisation.** A banned range is dropped by the firewall
  *before* nginx, which does not see the paths: it therefore does not reach the static pages
  either. Serving something to banned ranges would mean redirecting them to another server
  rather than dropping them.

## Spotting legitimate IPs caught in a ban (gitlab-runner…)

Opt-in: `watch_agent` (regex on the user agent) and `watch_path` (regex on the route); if
both are given, both must match. The route belongs to a host, so it goes in the
`[site:NAME]` section of that host (a `[fobots]` value applies to the targets that have none
of their own). Example for runners:

```
[site:gitlab]
log = /var/log/gitlab/nginx/gitlab_access.log
watch_agent = ^gitlab-runner
watch_path  = ^/api/v4/
```
These requests are **counted like the others**: no exemption, so nothing to spoof. When a
range is banned, the daemon records the IPs that matched, in the journal (a `WATCH` line)
**and** in `<dir>/watched.jsonl` (one finding per ban, pruned beyond 30 days at startup). The
command rereads this file, without journalctl, and combines it with the current state of the
bans in nft:

```
fobots watched                 # last 7 days (--since 12h, 3d…)
fobots watched --active        # only those whose ban is active
fobots watched --cmd           # only prints the welcome add command
```
```
IP          BANS  REQ  LAST BAN          RANGE        STATE          ROUTE
40.2.2.2       1    2  2026-10-10 13:40  40.0.0.0/12  active (1234 s) /api/v4/jobs/7/artifacts
20.1.1.1       2    6  2026-10-10 13:40  20.0.0.0/12  expired        /api/v4/jobs/request

To protect them all:
  fobots welcome add 40.2.2.2/32 20.1.1.1/32
```
IPs are aggregated over the period: *BANS* = number of bans they were caught in (an IP caught
several times is a serious suspect). Since bans expire quickly, it is the file's history that
lets you see them after an absence. The "active/expired" state needs access to nft
(otherwise `?`). Nothing is added to the welcome list automatically.

Limits: only requests seen in the hour before the ban are noted (at most 5,000 IPs kept, 200
per finding); private IPs are never counted; lines whose agent cannot be read (another log
format) are not monitored. Job `git clone`s generally carry the `git/…` agent: to see them,
`watch_agent = ^(gitlab-runner|git/)`.

## File locations

The default paths are absolute: the result never depends on the directory a command is run
from, and the daemon, `welcome`, `bans` and `watched` see the same files.

| What | Where | Why |
|---|---|---|
| Configuration, welcome list | `/etc/fobots/` | decided by the administrator; the daemon only reads them |
| RDAP cache, monitoring findings | `/var/lib/fobots/` | state written by the daemon (created if missing, mode 0750) |
| Logs | journald (`journalctl -u fobots`) | no file |
| Command | `/usr/local/sbin/fobots` (package: `/usr/sbin/fobots`) | the launcher, installed without `.py` |
| Modules | `/opt/fobots/fobots/` | the `fobots/` package, found by the command |

**Permissions:** the daemon can run as a dedicated user with only the `CAP_NET_ADMIN`
capability (see `fobots.service.example`). The administration commands (`setup`, `bans`,
`watched`, `welcome add`) must be run **as root (`sudo`)**: they read or modify nft, and
`welcome add` writes to `/etc/fobots/`.

## Configuration

`fobots.conf` (section `[fobots]`), looked up first in `/etc/fobots/`, then in the current
directory (handy for development), or given with `-f`. Relative paths in it are relative to
the configuration file. **The command line overrides the configuration.** See
`fobots.conf.example` for all the keys:

| Key | Default | Role |
|---|---|---|
| `log` | none | log followed continuously (rotation handled); see also the `[site:NAME]` sections |
| `dir` | `/var/lib/fobots` | state directory: `ip_ranges.json`, `watched.jsonl` (created if missing) |
| `cache` | `<dir>/ip_ranges.json` | RDAP range cache |
| `welcome` | `welcome.txt` next to the configuration used, otherwise `/etc/fobots/` | ranges never to ban |
| `threshold` | 5 | req/s of a range above which it is banned |
| `prefix_threshold` | = `threshold` | req/s of an unresolved `/16` that allow RDAP |
| `sustain`, `window` | 5, 60 | consecutive seconds above the threshold required; tracking window (s) |
| `ban_time` | 1h | duration of a ban (`30m`, `1h`, `1d`) |
| `ban_scope` | `allocation` | `allocation`: ban the whole RDAP range; `observed`: only the groups of IPs seen inside it |
| `observed_prefix` | 20 | `observed`: maximum extent of a group of IPs (IPv4 prefix; IPv6: `/48`) |
| `observed_escalate` | 4 | `observed`: partial bans of an allocation, within a ban's duration, before falling back to wide blocks |
| `observed_max_prefix` | 16 | `observed`: width of the blocks banned as a fallback (IPv4 prefix; IPv6: `/32`); `0` = whole allocation |
| `rdap_per_hour`, `delay` | 100, 2 | budget and spacing of RDAP requests |
| `load_signal` | `none` | load-based hardening: `psi`, `loadavg` or `none` |
| `load_tense`, `load_critical` | 20 / 50 (psi), 1.0 / 2.0 (loadavg) | signal levels |
| `load_recover` | 5m | time below the level before going down one level |
| `tense_factor`, `critical_factor` | 0.5, 0.25 | multiplier of the threshold **and** of the ban duration |
| `min_threshold`, `min_ban_time` | 1, 1m | floors of the effective threshold and duration |
| `from_start` | no | first read the existing content of the log |

Without `log` or a `[site:…]` section, the daemon **refuses to start** (clear error), unless
stdin is a pipe or a file (`tail -F file | fobots run`) or `-` is given explicitly. Files
passed as arguments are read once (`-` = stdin), which is useful to replay a log.

If the daemon follows nothing although the configuration looks right, check that it reads the
expected configuration (the `configuration : …` line at startup) and that the installed script
is up to date: an old copy ignores the `[site:…]` sections without saying so. `SIGUSR1` also
reports the number of unreadable lines (unexpected log format, e.g. the `host:port` prefix of
the Apache `vhost_combined` format, which is not supported).

## Commands

```
fobots run [-t THRESHOLD] [-p PREFIX_THRESHOLD] [--log FILE] [files…]   (no argument: follows the logs of the configuration)
fobots install [--dry-run] [--log F] installs nftables, the user, the configuration, the systemd unit
fobots setup                      creates the nft table, sets and rules
fobots bans                       active bans and remaining time
fobots welcome add CIDR…          welcome list + removal of the bans concerned
fobots welcome list
fobots watched [--active] [--cmd]  monitored IPs (watch_*) caught in a ban
```
Common options: `-f CONF`, `--dir`, `-c`, `-w`, `--ban-time`, `--nft-bin`, `--dry-run`,
`-v`. `--dry-run` does not call nft: it prints the commands and simulates the sets in memory.

## Welcome list

```
fobots welcome add 17.0.0.0/8 -f /etc/fobots/fobots.conf
```
The range is added to `welcome.txt` (the daemon immediately stops banning it: it rereads the
file before each ban), then the bans that touch it are removed. If the range is inside a wider
ban, the rest is put back with its remaining time (`17.1.0.0/16` inside `17.0.0.0/8` gives 8
pieces around the `/16`). A banned range that overlaps the welcome list is banned without the
protected part.

## Reset

```
nft flush set inet fobots banned4        # and banned6: all the bans, immediately
nft list set inet fobots banned4         # see what is banned
nft delete element inet fobots banned4 { 47.74.0.0/15 }
nft delete table inet fobots             # remove everything (run `setup` again)
```
The RDAP cache (`ip_ranges.json`) is independent: deleting it only forces the RDAP requests
to be redone.

## Log rotation

Log following works like `tail -F`: renaming (`create`), truncation (`copytruncate`) and the
temporary absence of the file are handled, with no signal to send. After a rename, the old
file is still read for 2 s (the server writes to it until it reopens it). With
`copytruncate`, lines written between the copy and the truncation are lost (a logrotate
limitation). Each log (`[site:…]` sections or the `log` of `[fobots]`) is followed
independently, so each can have its own rotation.

## Signals and journal

Logs go to stderr (the systemd journal when run as a service). Each ban states the range, the
rate, the triggering IP and the total number of requests. `SIGUSR1` prints the most active
ranges since startup; `SIGTERM`/`SIGINT` stop the daemon.

## Tight bans (`ban_scope = observed`)

Disabled by default: the behaviour stays the one described above. RDAP still provides the
**boundary** (the allocation) and decides *when* to ban (same threshold, same counting per
allocation). What changes is *what*: instead of the whole allocation, it bans the IPs seen
during the `window`, grouped as follows:

- IPs are sorted and grouped as long as the group's extent stays under `observed_prefix`
  (4096 addresses by default); a group is bounded by its extreme IPs (an interval, not a
  CIDR: two neighbouring IPs on either side of a block boundary stay together);
- the most active groups are banned until they cover 80% of the allocation's requests; the
  isolated IPs left over (legitimate visitors) are not touched;
- **fallback to wide blocks** if the traffic is too scattered (more than 4 groups needed), or
  after `observed_escalate` partial bans of the same allocation within a ban's duration (the
  scraper changes range). The blocks of `observed_max_prefix` (`/16` by default) that carry
  80% of the requests are then banned, **never wider**, even if the allocation is a `/10`: a
  Google Cloud allocation gives a few `/16`s, not a `/10`. An allocation narrower than the
  block is banned as is; with `observed_max_prefix = 0`, the fallback bans the whole
  allocation.

For each ban the journal states the number of IPs, of groups and the share of requests
covered. To compare safely: `run --dry-run --ban-scope observed` on the same replayed log
(`fobots run --dry-run --ban-scope allocation LOG`, then `observed`).
When a ban replaces others (a `/16` that encloses `/32`s), the daemon removes the old elements
then adds the new one in **two nft transactions**: nft 0.9.x refuses to do it in a single one
("interval overlaps with an existing one"). If the addition fails, the removed elements are
put back.
Memory: at most 200,000 IPs tracked. IPv4 and IPv6 are handled the same way.

## Known limits

- **Range = RIR allocation** by default (see `ban_scope = observed` to narrow it), often very
  wide (`17.0.0.0/8`, `43.0.0.0/9`, `36.128.0.0/10`). A ban hits the whole allocation,
  including legitimate visitors. Safeguard: the ban expires, the welcome list fixes it. RDAP
  answers wider than `/8` (IPv4) or `/16` (IPv6) are rejected.
- **Detection on the log**, therefore *after* the request: nginx only writes a line once the
  response is finished. An already saturated server writes its logs late, and the reaction is
  late too.
- **Counts all requests** the same way, regardless of their cost.
- **No escalation**: a banned scraper comes back at expiry with the same duration. No prior
  HTTP 429 response, no increasing duration.
- **No circuit breaker**: no cap on the number or size of bans (a deliberate choice: the
  welcome list is the safety net). With load-based hardening, thresholds can go down to
  `min_threshold`: watch the first days.
- Unresolved RDAP ranges (budget exhausted, network failure) are never banned; the failure is
  logged and retried later.
- `nftables.service` with `flush ruleset` erases the `fobots` table at each reload (see the
  comments of `fobots.service.example`).

## Files

| File | Role |
|---|---|
| `fobots.py` | launcher: `./fobots.py` in a clone, installed as the command `fobots` |
| `fobots/` | the package: `cli` (commands), `detector`, `nft`, `welcome` (bans), `rdap`, `grouping`, `follow` (logs), `load`, `sites`, `events`, `config`, `install`, `util`, `constants` |
| `fobots.conf.example` | example configuration |
| `fobots.service.example` | example systemd unit |
| `build-deb.sh`, `Makefile` | Debian package, `make test` |
| `tests/test_fobots.py` | unit tests |
| `tests/integration.sh` | integration test (real nft, fake logs) |
| `/etc/fobots/fobots.conf` | configuration |
| `/etc/fobots/welcome.txt` | ranges never to ban, one CIDR per line (created by `welcome add`) |
| `/var/lib/fobots/ip_ranges.json` | RDAP range cache |
| `/var/lib/fobots/watched.jsonl` | "monitored IP caught in a ban" findings (if `watch_*`) |

## License

fobots is free software, distributed under the GNU GPL version 3 or later
(`GPL-3.0-or-later`). Copyright (C) 2026 Joël Maizi. See the `LICENSE` file.
