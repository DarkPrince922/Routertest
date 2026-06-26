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
- External tools: `nmap`, `nuclei`, `routersploit` (the installer handles all three)

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
MAX_CONCURRENT=2
DB_PATH=./scans.db
LOG_LEVEL=INFO
```

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

- **🎯 Новый скан** — pick a target (button per scope host, ✏️ manual entry, or
  📄 a TXT list) → pick a profile (⚡ Быстрый / 🔍 Стандартный / 💣 Полный) →
  confirm → live progress → summary + buttons `[📄 JSON] [🔁 Повторить] [🏠 Меню]`.
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
    carry a stop button. Stopping a running scan cancels the current stage and
    the job is **removed from history** — partial results are dropped (the
    cancellation is still recorded in the audit log). The batch button stops
    every job in that batch.
  - **Device fingerprint & skip**: the nmap stage runs OS/device detection
    (`-sV -O`) and classifies the target as router / not-router / unknown
    (vendor banners + nmap `osclass`). If the target is **confidently not a
    router**, the deeper stages (nuclei/routersploit) are skipped and the job is
    marked `SKIPPED`. Unknown targets are still scanned (OS detection often
    fails through `-Pn`), so a real router isn't dropped on a weak signal.
  - **🚨 Vulnerable-router alert**: as soon as a stage produces a `high`/
    `critical` finding, the bot pushes a separate notification message
    (target + device + finding), without waiting for the whole scan to finish.
- **📊 История** — paginated list of past scans; open one to see the severity
  breakdown, paginated findings, and a JSON export.
- **📋 Scope** — read-only view of `engagement_id`, CIDRs and hosts.
- **ℹ️ Статус** — queue depth, active scans, tool versions.

### Scan profiles

| Profile | Stages |
|---|---|
| `QUICK` | nmap |
| `STANDARD` | nmap + nuclei |
| `FULL` | nmap + nuclei + routersploit |
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

## Operational notes

- Nothing blocks the event loop: all subprocesses are async; routersploit
  (synchronous) runs in `asyncio.to_thread` with a per-module timeout.
- Progress edits are throttled (~once per 2s) and `MessageNotModified` /
  `TelegramRetryAfter` are handled.
- History survives restarts (SQLite on disk; WAL mode).
- The systemd unit grants `CAP_NET_RAW`/`CAP_NET_ADMIN` so the unprivileged
  service user can run nmap raw-socket scans.

## Troubleshooting

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
