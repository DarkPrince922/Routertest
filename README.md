# Router Pentest Orchestrator

A Telegram-driven orchestrator for **authorized** penetration testing of routers
and IoT devices. The pipeline is: *discovery → fingerprint → vuln-scan → creds →
report*, fully managed from Telegram inline buttons, with a hard scope gate in
front of every tool run.

> ⚠️ **Authorized use only.** Every target is checked against `scope.yaml` (the
> rules of engagement) before any tool is launched. Out-of-scope targets are
> `REJECTED` and nothing runs. Do not point this at systems you are not
> explicitly authorized to test.

## Architecture

```
engine/   ← reusable core, NO Telegram dependency
  models.py    Finding, ScanJob, JobStatus, ScanProfile, Severity, ScopeDecision
  scope.py     ScopeGate — resolves host, checks resolved IP vs allowed CIDRs/hosts, audits
  store.py     SQLite: jobs, findings, audit
  runner.py    Engine: asyncio.Queue + worker pool, per-stage dispatch, progress callbacks
  stages/      nmap_stage, nuclei_stage, routersploit_stage (+ _common._run helper)
bot/      ← aiogram 3.x presentation layer
  main.py      entry point, DI wiring, middleware + router registration
  keyboards.py inline keyboards (the whole button tree)
  callbacks.py typed CallbackData factories
  states.py    FSM (ScanFlow)
  middlewares.py admin-guard (allow-list) + anti-flood
  handlers/    menu, scan, history, scope
config.py   pydantic-settings (reads .env)
scope.yaml  ROE source of truth (committed, reviewed, NOT edited from the bot)
```

The `engine` package has no Telegram imports, so it can later be driven from a
corporate web panel without touching the bot layer.

## Requirements

- Ubuntu 22.04 (the installer targets it; other distros: install deps manually)
- Python 3.10+
- External tools: `nmap`, `masscan`, `nuclei`, `routersploit`, `hydra`, `snmp`
  (the installer handles these). `msfconsole` (Metasploit) is optional and
  installed separately if you want the metasploit stage.

## Install

```bash
git clone <repo> pentest_orchestrator
cd pentest_orchestrator
bash install.sh
```

`install.sh` is **idempotent** (safe to re-run). It:

1. Verifies the OS and `sudo` (also works as root).
2. `apt-get` installs `python3 python3-venv python3-pip nmap git curl unzip ca-certificates build-essential`.
3. Creates `./.venv` and installs `requirements.txt`.
4. Downloads the pinned `nuclei` release (`NUCLEI_VERSION` at the top of the
   script) to `/usr/local/bin` and runs `nuclei -update-templates` (skips if the
   right version is already present).
5. Installs `routersploit` into the venv and verifies it imports.
6. Creates `.env` and `scope.yaml` from the `*.example` templates **only if
   absent** (never overwrites).
7. Warns (without failing) if `BOT_TOKEN` is still a placeholder.
8. Creates the `pentestbot` system user (nologin) and chowns the project.
9. Installs and `enable`s the systemd unit (substituting the real path/user).
   It does **not** start the service while the token is a placeholder.
10. Prints a summary: tool versions, config paths, service commands.

### routersploit git-clone fallback

If `pip install routersploit` fails on your box, vendor a pinned tag instead:

```bash
git clone --depth 1 --branch v3.4.0 https://github.com/threat9/routersploit vendor/routersploit
./.venv/bin/pip install -e vendor/routersploit
```

## Update

To pull the latest code and restart the service:

```bash
cd /opt/pentest_orchestrator   # your install dir
sudo bash update.sh            # optional: sudo bash update.sh <branch> (default main)
```

`update.sh` is idempotent and:

- stashes local edits to tracked files (e.g. your `scope.yaml`) and re-applies
  them after the pull, so your ROE is never overwritten;
- fast-forward pulls `origin/main` (aborts cleanly if it can't, restarting
  nothing);
- reinstalls Python deps only if `requirements.txt` changed, and warns if the
  systemd unit/installer changed (re-run `install.sh` then);
- restores ownership to `pentestbot`, restarts the service and prints status.

`.env`, `scans.db` and `logs/` are untracked, so they are left alone.

## Configure

`.env` (created from `.env.example`):

```
BOT_TOKEN=<token from @BotFather>
ADMIN_IDS=123456789,987654321   # comma-separated Telegram user IDs
MAX_CONCURRENT=6
DB_PATH=./scans.db
LOG_LEVEL=INFO
SCAN_PROXY=                     # optional HTTP-layer proxy, e.g. socks5://127.0.0.1:9050
RSF_DEFAULT_ONLY=true           # true = only factory-default creds (fast, low lockout risk)
```

- **`SCAN_PROXY`** — routes nuclei and the HTTP banner grab through a proxy
  (SOCKS5/HTTP). nmap is **not** proxied; for full tunnelling run the service on
  a VPN/jump host. This is just the initial default — you can also set/change the
  proxy live from the bot under **⚙️ Настройки → 🔌 Прокси** (persisted in the DB,
  takes precedence over `.env`).
- **`RSF_DEFAULT_ONLY`** — `true` runs only routersploit's `*_default` credential
  modules (a handful of factory creds — fast, unlikely to trip a router lockout).
  Set `false` to also run the slower `*_bruteforce` modules. The credential stage
  uses routersploit for **FTP/SSH/Telnet** and a **built-in HTTP Basic-auth
  default-credential check** for the web UI on every open web port (works in
  default-only mode and won't false-positive on form-login pages — those are
  covered by nuclei's `default-login` templates).
- **Vendor-specific exploit checks** — once the fingerprint identifies the vendor
  (MikroTik, D-Link, TP-Link, Netgear, ASUS, Huawei, Zyxel, …), the routersploit
  stage runs that vendor's exploit modules' `check()` (non-destructive) against
  the target and flags the ones it appears vulnerable to (`🎯 Потенциально
  уязвим …`). The detected vendor/model is passed between stages via a shared
  per-scan context (nmap → snmp → routersploit), and SNMP `sysDescr` gives the
  most precise model/firmware string.

`scope.yaml` — the **rules of engagement**, the source of truth for what may be
scanned. Edited on the host and reviewed in version control; it is **never**
editable from the bot.

```yaml
engagement_id: "lab-2026-01"
allow_all: false          # true = disable the gate, accept ANY target (still audited)
allowed_cidrs:
  - 192.168.1.0/24
allowed_hosts:
  - myrouter.local
```

> **`allow_all`** is a reversible kill-switch. With `allow_all: true` the scope
> gate is disabled and every target is accepted (each decision is still written
> to the audit log). Set it back to `false` to re-enforce the
> `allowed_cidrs`/`allowed_hosts` ROE. Use `true` only on networks you are
> authorized to test broadly (e.g. an isolated lab).

A target is allowed if **either** its resolved IP falls inside an
`allowed_cidrs` entry **or** the literal host string is in `allowed_hosts`. The
gate resolves the hostname and checks the **resolved IP**, so a host that
DNS-points outside scope is rejected (no scope leak via DNS).

After editing scope or `.env`:

```bash
sudo systemctl restart pentest-bot
sudo journalctl -u pentest-bot -f
```

## Usage (all inline buttons)

`/start` opens the main menu:

- **🎯 Новый скан** — pick a target (button per scope host **and CIDR**, ✏️ manual
  entry, or 📄 a TXT list) → pick a profile (⚡ Быстрый / 🔍 Стандартный / 💣 Полный)
  → confirm → live progress → summary + buttons `[📄 JSON] [🔁 Повторить] [🏠 Меню]`.
  - **Subnet(s) (CIDR)**: enter or pick a network like `192.168.7.0/24`. You can
    pass **several subnets and hosts at once** (manual entry or TXT file, e.g.
    `192.168.0.0/24, 192.168.4.0/24, 10.0.0.5`). Each subnet is authorized against
    scope, ping-swept (`nmap -sn`), and **each live host is queued the moment it's
    found** — scanning starts immediately, in parallel with the rest of the sweep
    (dead hosts skipped). The message shows discovery progress live
    (`🔎 Поиск живых хостов… найдено: N, просканировано: k`). Discovery allows up
    to a /16; per-input target ceiling is 65536 (effectively unlimited).
  - **Single target**: one message grows into a live, human-readable narrative —
    `⏳ В очереди → 🔍 Сканирую порты и определяю устройство → 🧭 Определено
    устройство: MikroTik RouterOS → 🧪 Проверяю уязвимости → 🔑 …` — then is
    replaced by the final summary. No new messages, no clutter.
  - **TXT batch**: send a `.txt` document with one target (IP or host) per line
    (commas/whitespace also split; `#` lines ignored; deduped; capped at 256).
    Each target is scope-checked and queued. One aggregate message shows live
    progress — `Готово k/N` plus a `▶️ Сейчас:` block listing the targets in
    flight, each with its detected model and current step (and a
    `🚫 не роутер, пропускаю` notice for non-routers) — and ends with a combined
    summary (routers scanned / non-routers / out-of-scope / stopped, notable
    findings). Per-target details and JSON live under **📊 История**.
  - **⏹️ Стоп**: the live progress message (single scan) and the batch message
    carry a stop button. It is **immediate** — the running tool processes
    (nmap/nuclei/discovery sweep) are killed at once, in-flight subnet discovery
    stops queuing new hosts, and every queued/running job in the batch is
    cancelled. Cancelled jobs are **removed from history** (partial results
    dropped); the cancellation is still recorded in the audit log.
  - **Device fingerprint & skip**: the nmap stage runs OS/device detection
    (`-sV -O`) and classifies the target as router / not-router / unknown
    (vendor banners + nmap `osclass`). If the target is **confidently not a
    router**, the deeper stages (nuclei/routersploit) are skipped and the job is
    marked `SKIPPED`. The gate is deliberately conservative so a real router is
    never dropped: a host with **any open web/admin/router-mgmt port** (80/443/
    8080/8291/7547/…) is always fully scanned regardless of the device-type
    guess, and ambiguous nmap labels (`general purpose`, `switch`, `specialized`,
    `remote management` — which embedded routers routinely report) count as
    *unknown*, not *not-router*. Targets whose type can't be determined are, by
    default, still scanned (OS detection often fails through `-Pn`); switch to
    strict mode (**⚙️ Настройки → 🧭 Неизвестные: пропускать**) to skip
    undetermined targets that also expose no scannable ports.
  - **🚨 Vulnerable-router alert**: as soon as a stage produces a `high`/
    `critical` finding, the bot pushes a separate notification message
    (target + device + finding), without waiting for the whole scan to finish.
- **📊 История** — paginated list of past scans; open one to see the severity
  breakdown, paginated findings, and a JSON export.
- **📋 Scope** — read-only view of `engagement_id`, CIDRs and hosts.
- **ℹ️ Статус** — queue depth, active scans, tool versions, interrupted count.
- **⚙️ Настройки** — set/clear the SOCKS5/HTTP proxy, toggle the routersploit
  creds mode (default-only ↔ +bruteforce), toggle skip-unknown (strict ↔ lenient
  device detection), cycle the **port scanner** (auto / masscan / nmap) and the
  **liveness sweep** (auto / masscan / nmap), toggle **Metasploit** and the
  **🐢 economy mode**, and **resume or clear** interrupted scans. All persisted in
  the DB.
  - **🐢 Эконом-режим** — for weak hardware. Serializes heavy tools (effective
    heavy-tool limit = 1), drops nuclei concurrency to `-c 8`, throttles masscan
    rates (port scan ~1000, sweep ~2000 pps), and scans batch **subnets strictly
    one at a time** (each subnet's live hosts finish before the next sweep), so
    the box never juggles a discovery sweep and a full scan queue at once. Much
    lighter CPU, slower overall.

### Scan profiles

| Profile | Stages |
|---|---|
| `QUICK` | nmap (ports + device fingerprint) |
| `STANDARD` | nmap + snmp + nuclei + verify |
| `FULL` | nmap + snmp + nuclei + routersploit + hydra + metasploit* + verify |

\* Metasploit is **off by default** (heavy) — enable in ⚙️ Настройки → 💥.

**Port discovery** uses **masscan** when available (raw-SYN, fast, and gets
through environments that restrict nmap's connect scans), then nmap `-sV` enriches
just the open ports with service/version/OS. If masscan is unavailable or finds
nothing, it falls back to a direct nmap scan. Pick the engine in
**⚙️ Настройки → 🛰 Сканер портов** (`auto` / `masscan` / `nmap`); masscan needs
the `CAP_NET_RAW` the systemd unit already grants.

The **nmap** stage also grabs HTTP `Server`/`<title>` and SSH/Telnet banners to
sharpen the model/firmware fingerprint, and matches the detected firmware against
a curated offline CVE list (`engine/data/router_cves.yaml`) for well-known router
bugs (MikroTik Winbox, RomPager "Misfortune Cookie", Huawei HG532, etc.). The
vendor is also inferred from **characteristic open ports** (e.g. Winbox 8291 →
MikroTik, TR-069 7547 → CPE), so a device is fingerprinted and its known CVEs
flagged even when `-sV` is blocked and there are no service banners. This curated
list is intentionally small — **nuclei provides the bulk of CVE coverage, so keep
its templates updated** (`nuclei -update-templates`); if they're missing, the
nuclei stage now says so in the results. The nuclei stage probes the common
router web ports and runs against the **admin UI wherever it lives** (e.g.
`:8080`), not just 80/443, and uses the **full template set** by default
(set `NUCLEI_TAGS` to restrict it for speed). The
**snmp** stage checks default community strings (`public`/`private`/…) on UDP 161
— a readable community is a high-severity finding and also feeds CVE matching.
Both feed the immediate 🚨 vulnerable-router alert.

The **hydra** stage brute-checks default/weak credentials on SSH/Telnet/FTP and
HTTP-Basic with a small curated combo list (`-f` stops on first hit — fast, low
lockout risk); `+bruteforce` creds mode + `HYDRA_PASS_LIST` allows a wordlist.
The optional **metasploit** stage (enable in ⚙️ Настройки → 💥; needs
`msfconsole` installed separately, e.g. the Rapid7 nightly/omnibus) runs the
detected vendor's Metasploit exploit modules' `check()` for far broader exploit
coverage than routersploit — its hits feed CVE verification as an active method.

The **verify** stage (last in STANDARD/FULL) cross-checks every detected CVE to
cut false positives. CVEs flagged only by passive fingerprint inference (the
curated KB) are **actively re-checked** by running that exact nuclei template
(`-id <CVE>`): a match → `✅ подтверждён`, ran but no match → `⚠️ вероятно ложное`,
no template to check with → `ℹ️ не перепроверено`. CVEs already found by an
active method (nuclei/routersploit) or corroborated by ≥2 methods are marked
`✅ подтверждён`.
| `FIRMWARE` | *reserved* (binwalk/EMBA) — not implemented in v1 |

## Security model

- **Scope gate before every run.** `ScopeGate.check()` runs before any tool;
  rejected targets never reach a subprocess.
- **Resolved-IP check** defends against DNS-based scope leakage.
- **Admin allow-list** enforced by an outer middleware on **every** message and
  callback — not just `/start`. Denials are audited.
- **Audit trail** (SQLite `audit` table) records: scope decisions, job
  queued/started/finished, and access denials — each with actor, target,
  resolved IP, decision and `engagement_id`.
- Credential findings are stored in the DB but not echoed into the general log.

## Reporting / DefectDojo import

Each job exports as JSON (`📄 JSON` button or `Store.export_job`):

```json
{
  "job": { "id": 1, "target": "...", "profile": "FULL", "status": "DONE",
           "engagement_id": "lab-2026-01", "created_at": "...", "finished_at": "...", "error": null },
  "findings": [
    { "stage": "nmap", "severity": "info", "title": "80/tcp open: http (...)", "detail": {...} },
    { "stage": "routersploit", "severity": "high", "title": "default/weak creds admin:admin (port 80)", "detail": {...} }
  ]
}
```

To import into **DefectDojo**, use *Generic Findings Import*. The `findings[]`
array maps cleanly: `title`, `severity` (info/low/medium/high/critical), and the
`detail`/`stage` fields carry the technical context. Create an engagement keyed
on `job.engagement_id` and upload the JSON per job.

## Extending: adding a new stage

1. Create `engine/stages/<name>_stage.py` with
   `async def <name>_stage(target: str) -> list[Finding]:` — use the
   `engine.stages._common.run_cmd` helper for subprocesses (it enforces the
   timeout and kills on overrun).
2. Export it from `engine/stages/__init__.py`.
3. Add it to the relevant profile(s) in `PROFILE_STAGES` in `engine/runner.py`.

A failing stage is isolated: it is recorded as an `info` Finding and the scan
continues. The `FIRMWARE` profile and `engagement_id` plumbing are already in
place for the future binwalk/EMBA branch.

To add a **known-CVE rule**, append an entry to `engine/data/router_cves.yaml`
(`match` is a case-insensitive regex tested against the fingerprint blob). It is
loaded at startup and matched against every target's banners/OS/firmware.

## Operational notes

- Nothing blocks the event loop: all subprocesses are async; routersploit
  (synchronous) runs in `asyncio.to_thread` with a per-module timeout.
- Progress edits are throttled (~once per 2s) and `MessageNotModified` /
  `TelegramRetryAfter` are handled.
- History survives restarts (SQLite on disk; WAL mode). Scans left QUEUED/RUNNING
  by a restart are flagged **`INTERRUPTED`** on startup — nothing runs
  automatically. Resume them on demand from **⚙️ Настройки → ♻️ Возобновить**
  (partial results are dropped and the scans run fresh).
- The systemd unit grants `CAP_NET_RAW`/`CAP_NET_ADMIN` so the unprivileged
  service user can run nmap raw-socket scans.

## Performance / tuning

The bot itself is fast; scan time is dominated by the external tools. Defaults
are tuned for a balance of speed and coverage on routers:

- **Concurrency** — `MAX_CONCURRENT` in `.env` (default **6**) sets how many
  targets scan in parallel. This is the main lever for TXT batch lists. Raise it
  for more throughput (costs CPU/RAM/network); lower it on a small box.
- **Batch/subnet scans run "light"** — the heaviest stage (Metasploit) is skipped
  when scanning a list or subnet (msfconsole per host across a subnet is
  impractical); it still runs for single-host scans. Every stage also has a hard
  backstop timeout, so one stuck tool can never hang a worker — the queue keeps
  moving even at high concurrency.
- **`HEAVY_TOOL_LIMIT`** (default **2**) caps how many heavy tools
  (nuclei/routersploit) run at once, **independently of `MAX_CONCURRENT`**. nuclei
  with the full template set is memory-hungry, so without this a high
  `MAX_CONCURRENT` can OOM-kill the service. Keep it at 1–2 on a small VPS; raise
  it on a big box. (If the service crashes/restarts at higher concurrency, this —
  or more RAM — is the fix; check `journalctl -u pentest-bot` / `dmesg` for OOM.)
- **nmap** — scans ~30 router/CPE-relevant ports (`ROUTER_PORTS` in
  `engine/stages/nmap_stage.py`, incl. MikroTik Winbox 8291, TR-069 7547, common
  mgmt/alt-HTTP ports) instead of nmap's default 1000, with `-T4` and a
  `--host-timeout` so dead IPs in a list return fast. Widen `ROUTER_PORTS` (or
  add a port) if you need a service on an unusual port.
- **Per-host scan speed** — the two time sinks are nmap and nuclei:
  - **`NMAP_FAST`** (default **true**) skips slow OS detection (`-O`) and uses
    light version probes; device type still comes from ports/banners/SNMP. Set
    `false` for full `-sV -O`.
  - **`NUCLEI_TAGS`** is the biggest nuclei lever — empty runs ALL templates
    (thorough, slow); a tag list (e.g. `router,iot,cve,default-login,exposure,
    panel,misconfig`) is much faster. **`NUCLEI_CONCURRENCY`** (`-c`, default 50)
    speeds a single run at the cost of CPU/RAM.
- **Router skip** — non-routers skip nuclei/routersploit automatically, saving
  the bulk of the time on irrelevant hosts.
- **Subnet liveness sweep** — `DISCOVERY_METHOD` (auto/masscan/nmap, also
  switchable in ⚙️ Настройки → 🔎). `masscan` (default when installed) is much
  faster than `nmap -sn` on large ranges **and** finds routers that block ICMP
  ping (it probes common router TCP ports instead). `DISCOVERY_RATE` tunes the
  masscan sweep rate.

## Troubleshooting

- **0 open ports on a host you know is open** — check, in order:
  1. **Reachability.** If the bot runs on a cloud/VPS host, it cannot reach a
     private LAN address like `192.168.1.1` (that's *its* network's gateway, not
     your home router). Verify from the host: `sudo -u pentestbot nmap -Pn -p80,443
     <target>` and `ping <target>`. If those see nothing, run the bot **on the
     same LAN** or tunnel in (VPN). No tool swap fixes this.
  2. **nmap connect-scan restricted / "forbidden ports".** Switch the engine to
     **⚙️ Настройки → 🛰 Сканер портов → masscan** (raw-SYN, bypasses connect
     limits). masscan needs `CAP_NET_RAW` (granted by the systemd unit; if you run
     the bot manually, run it as root or grant the cap).
  3. **Unusual port.** The nmap path auto-retries the top-1000 ports; masscan can
     be pointed at all ports (it widens to `1-65535` when explicitly selected).

- **`systemctl status` shows `200/CHDIR`** — the project lives somewhere the
  service user (`pentestbot`) can't enter, typically under `/root`. Move it to
  `/opt/pentest_orchestrator` (then re-run `install.sh`) or run the unit as
  `root`. Install under `/opt`, not `/root`.
- **nuclei: `failed to create config directory … mkdir /home/pentestbot:
  permission denied`** — the service user has no writable `$HOME`. `install.sh`
  now creates `/home/pentestbot` and updates templates as that user; on an older
  install fix it manually:
  ```bash
  sudo mkdir -p /home/pentestbot
  sudo chown -R pentestbot:pentestbot /home/pentestbot
  sudo -u pentestbot HOME=/home/pentestbot nuclei -update-templates
  sudo systemctl restart pentest-bot
  ```
```
