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
- `loadavg`: 1-minute load divided by the number of cores (slower);
- `probe`: **the response time of the service itself**, the most faithful indicator when what
  you want to protect is a degrading site (a server can be saturated in Apache workers or
  database connections with an idle CPU). One `GET` per URL every 5 s, from the machine:

  ```ini
  load_signal = probe
  load_probe_url = www.example.org@http://127.0.0.1/app/some-dynamic-page
  # load_tense = 1       # seconds (default)
  # load_critical = 3
  # load_probe_timeout = 10s   # a slower answer counts as 10 s
  ```
  `HOST@` sets the `Host` header (virtual host); several URLs are separated by commas, the
  level follows the slowest. Choose a **dynamic page typical of your service**, answering 2xx:
  the daemon refuses to start otherwise (a redirection or a 404 would measure nothing). A
  connection error or an HTTP 5xx only counts as critical after 3 consecutive failures. The
  probe comes from `127.0.0.1`: private, so never counted nor banned. It is chosen by you,
  never taken from the log. `fobots probe` measures the URL for a minute (median, p95, max) to
  help choose the levels; run it again during a slowdown to see what "degraded" looks like.

### Recording what a slowdown looks like (before configuring anything)

`fobots probe` works without any configuration and without installation (`./fobots.py probe …`).
Left running on a machine, it records what the server looks like when the page slows down:

```
./fobots.py probe --url HOST@http://127.0.0.1/app/page --record probe.jsonl      # run by hand (nohup, tmux…)
./fobots.py probe --report probe.jsonl
```

It measures the page every 5 s and keeps the last two minutes of readings in memory (only
`/proc` is read: load, memory available, swap activity, pressure stall, accept queue of ports
80/443, ListenOverflows). When the response time reaches `--load-tense` (default 1 s) it writes
those two minutes, then a full snapshot (with the processes using the most memory, grouped by
name: the backend workers, not only the web server) every 10 s while the slowdown lasts, and
immediately when it gets critical (3 s). A reading of normal times is added every 5 minutes for
comparison. The file is renamed `FILE.1` above 20 MB.

`--report` lists the slowdowns and tells **which reading moved first, and by how long** (columns
*before / same / late / never*, median lead, and the share of normal readings that were already
beyond the value: a false alarm). The values it uses (load ≥ 1 per core, pressure ≥ 20 % (5 %
for memory), memory available ≤ 15 %, swap ≥ 100 pages/s, accept queue ≥ 1) are reference
points, not recommendations: the point is to see, on **your** machine, which signal deserves
to be used. Let it run until a few slowdowns have happened.

The report separates **incidents** (longer than 20 s, or reaching the critical level) from **short
excursions** (jitter of the service: counted and summarised, not listed). Only the incidents are used to compare
the readings and to size the levels. A failed connection has no response time: it counts as the probe timeout,
and `load_critical` is never suggested above half of it, since beyond the timeout the daemon cannot tell
responses apart (a 40 s collapse and a 10 s one look the same).

At the end, `--report` writes a **suggested configuration** from what was recorded: `load_probe_url`
(kept in a header line of the file), `load_tense` (above the normal jitter, and above the short
excursions of 20 s or less that are not slowdowns) and `load_critical` (under the median peak of the real
slowdowns), each line with its justification, and a **replay** of the daemon's rules over the recording
("with 1 s / 3 s you would have been tense 38 % of the time; with 1.5 s / 4 s, 12 %"). If a reading the
daemon can use (`psi`, `loadavg`) moved before the page in at least two thirds of the slowdowns, with at
least 20 s of advance and under 5 % of false alarms, it is offered as an alternative (the daemon takes one
signal); the other readings are only reported as observations. A clean stop (Ctrl-C, SIGTERM) is written to the file and is a pause, not counted in the duration. A silence that
was not asked for is the machine in trouble: a stall of the recorder itself (it comes back by itself) or a run cut
without a stop (killed, machine restarted) are listed as *unexpected interruptions*, stay in the duration, and count
as severe slowdowns when they last 5 s or more.

Nothing is suggested without enough data:
500 normal measures over 2 hours for the levels, or 3 slowdowns of 5 s or more (a machine under attack
will not give hours of normal times), and 3 slowdowns to compare the signals. The values are a
starting point: review them after the first real incident.

Add `--log /var/log/nginx/access.log` (repeatable) to couple the recording with the access logs: each
measure then also stores the requests/s, the share of 5xx answers (a saturated backend) and the number
of distinct IPs that arrived since the previous one, and the report adds two rows: *requests/s ≥ 2×
the normal median* tells a traffic peak from an internal cause (backup, cron, slow database), and
the 5xx share shows when the backend started to fail. The log is only read (from its end), never
taken from the configuration, and a rotation is followed.

Three levels: *normal*, *tense*, *critical*. It goes up immediately; it goes down one level
only after `load_recover` continuously below the threshold. At each level, **the threshold
and the ban duration are multiplied** by the factor (0.5 then 0.25 by default), without going
below `min_threshold` / `min_ban_time`: stricter rules but shorter bans, so ranges are
re-judged sooner. `prefix_threshold` follows the same factor. Example (base 10 req/s, 1 h):
tense = 5 req/s for 30 min, critical = 2.5 req/s for 15 min.

The default levels are **not calibrated** for your server: first run with `--dry-run -v` and
look at the `load: psi=…` lines (every 5 minutes and at each level change) to choose
`load_tense` / `load_critical`. False positives are fixed with `welcome add`.

## Replaying a log to load the server

`fobots replay` replays the `GET` requests of an access log against a server, at a rate you choose that rises
by stages, and measures. It answers *which requests are costly, and at which load does the service give
way*, without waiting for the next incident and without touching the log format.

```
./fobots.py replay /var/log/nginx/access.log --base https://www.example.org --agent 'bot|crawl|spider' \
        --rate 2,5,10,15 --step 3m --probe-url HOST@http://127.0.0.1/app/page
./fobots.py replay --report replay.jsonl        # reads the results again
```

- **The load.** `--rate` is the number of requests per second inflicted on the server, stage by stage (default
  2,5,10,15), evenly spaced; `--step` is the length of a stage (3m). The requests are taken in the order of the
  log from a **random position** (printed with its `--seed`, to repeat a run; `--from/--until` bound the part of
  the log it draws from), and start over at the end of the log: every stage sends the same requests, faster. If a
  stage needs more requests than the log has, the plan says so (the caches get warm). `--agent` and `--exclude`
  (regular expressions) select what to replay, for instance only the robots. Only `GET` requests are replayed
  (a `POST` has no body in the log); a request that would write is refused by the service for lack of a
  session or token.
- **It stops by itself**, finishing the requests in flight, as soon as the median response time of the last
  20 requests reaches `--stop-latency` (3 s), or 20 % of the last 50 failed, or `--max-inflight` (100)
  requests wait for an answer, or the optional probe page (`--probe-url`, else `load_probe_url`) is slow.
  It asks for confirmation (`--yes` to skip it) and prints the plan first.
- **The requests come on top of the real traffic**: choose a quiet hour. Put the IP of the machine that
  replays in the welcome list, or fobots bans it. Replaying from another machine than the server avoids
  taking its CPU and memory.
- **The report** gives, for each stage, the requests/s, the median / p95 / max response time, the failures and
  the highest probe time; where the service gave way; and the **cost by type of request** (the directories,
  as in `fobots analyse`): the p95 of the first and of the last stage.
- **Fidelity.** The log keeps the status and size of every answer. The report compares them with what the
  server answers now: a page refused or redirected for lack of a session is cheaper than the real one, so
  the load measured is then a lower bound. Every request with another status is counted and the most
  frequent changes (`200 -> 302`) are listed. Failures under the load (`200 -> no answer`, 5xx) are told
  apart: that is the server giving way, not a difference of session. The replay sends
  `Accept-Encoding: gzip` like most clients (the server pays for the compression, and the size received is the
  logged one); `--no-compression` turns it off.

Together with `probe --record` running on the server during the replay, the incident is complete: the
response time of each type of request, and what the machine looked like (memory, swap, accept queue,
processes) at each stage.

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

## Analysing a log: `fobots analyse`

```
fobots analyse                      # the logs of fobots.conf
fobots analyse access.log -t 3      # a given file, highlighting threshold 3
```
Reads the logs once (no nft, no daemon, no RDAP query: only the ranges already in the cache)
and prints:

- the **"what if" table**: for several thresholds, how many ranges would have been banned
  (above the threshold for `sustain` consecutive seconds) and which share of the requests they
  sent, then the busiest ranges. Pick the threshold where the table stops growing;
- the **slow scrapers**: average rate of each range over `--slow-window` (10 min by default).
  A scraper that stays at about one request per second for hours never exceeds a per-second
  threshold, yet may weigh half of the traffic; this table shows how many ranges behave so;
- the busiest **directories**, the share of static files, what your `ignore_path` already
  excludes, and a suggested `ignore_path` (frequent directories that serve almost only static
  files, and fast ones when the log has durations);
- the most frequent user agents, with the number of IPs and ranges they are spread over: one
  agent making a large share of the traffic over many ranges is a distributed scraper.

**Request duration.** It is not in the usual formats. To rank the directories by cost and
avoid excluding something slow, add it as the **last** field: Apache
`LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined`
(microseconds), nginx `$request_time` (seconds). `--time-unit` forces the unit (auto: a decimal
number is seconds, an integer is microseconds). The daemon is not affected by this extra field.

These are **suggestions**: nothing is changed, and a suggestion built from one quiet day
should be checked before use.

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
| `slow_threshold`, `slow_window` | 0, 10m | bans a range whose **average** rate over the window exceeds this (req/s); `0` = disabled |
| `ban_time` | 1h | duration of a ban (`30m`, `1h`, `1d`) |
| `ban_scope` | `allocation` | `allocation`: ban the whole RDAP range; `observed`: only the groups of IPs seen inside it |
| `observed_prefix` | 20 | `observed`: maximum extent of a group of IPs (IPv4 prefix; IPv6: `/48`) |
| `observed_escalate` | 4 | `observed`: partial bans of an allocation, within a ban's duration, before falling back to wide blocks |
| `observed_max_prefix` | 16 | `observed`: width of the blocks banned as a fallback (IPv4 prefix; IPv6: `/32`); `0` = whole allocation |
| `rdap_per_hour`, `delay` | 100, 2 | budget and spacing of RDAP requests |
| `load_signal` | `none` | load-based hardening: `probe`, `psi`, `loadavg` or `none` |
| `load_probe_url`, `load_probe_timeout` | none, 10s | `probe` signal: `[HOST@]URL` page(s) requested; answer time counted as the timeout when slower |
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
fobots analyse [LOG…]             reads logs once and suggests settings (no nft, no root)
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

## Slow scrapers (`slow_threshold`)

A scraper that stays at about one request per second, spread over many IPs of a cloud
allocation, never exceeds a per-second `threshold`. With `slow_threshold = 0.5` and
`slow_window = 10m`, a range is banned when it has sent more than 0.5 × 600 = 300 requests
over the last 10 minutes (counted in 10-second buckets: no cost per request). Disabled by
default. Measure it first with `fobots analyse` (table "Slow scrapers"): it shows which
ranges would be caught and how much of the traffic they send. The rule is the same as the
per-second one for the rest (`welcome` list, `ban_scope`, `ban_time`); with
`ban_scope = observed`, the IPs seen over the whole window are considered, so the ban stays
tight. Caution: a large legitimate network (campus behind a NAT) on a busy site can exceed a
low average rate; check with `analyse` on your own logs, and fix false positives with
`welcome add`. It is not scaled by the load level.

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
