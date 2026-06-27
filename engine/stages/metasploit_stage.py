"""metasploit stage — broad vendor exploit coverage via msfconsole (optional).

Metasploit's module DB is far larger than routersploit's. This stage runs a
resource script that loads the detected vendor's exploit modules and runs each
module's non-destructive ``check()``, reporting the ones the target appears
vulnerable to. It is HEAVY (msfconsole startup + RAM) and OFF by default — enable
via ``METASPLOIT_ENABLED`` / the ⚙️ Настройки toggle. Runs only in FULL.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile

from ..cve_db import record_cve
from ..models import Finding, Severity
from ..runtime import get_config, heavy_semaphore
from ._common import run_cmd

MSF_TIMEOUT = 300.0          # msfconsole is slow to start, but bounded
MAX_MSF_MODULES = 15
_RESULT_RE = re.compile(r"MSFCHECK\|([^|]+)\|([^|]*)\|(.+)")

# Ruby resource block: iterate the vendor's exploit modules, run check().
_RUBY = """<ruby>
ip = "%(ip)s"
vendor = "%(vendor)s"
rport = %(port)d
count = 0
framework.exploits.each_key do |name|
  next unless name.downcase.include?(vendor)
  break if count >= %(maxmods)d
  count += 1
  begin
    m = framework.exploits.create(name)
    next if m.nil?
    m.datastore['RHOSTS'] = ip
    m.datastore['RPORT'] = rport if m.datastore.keys.include?('RPORT')
    code = m.check
    cves = (m.references || []).map { |r| r.to_s }.select { |s| s =~ /CVE/ }.join(',')
    if code && code.to_s =~ /Vulnerable|Appears/i
      print_good("MSFCHECK|#{name}|#{cves}|#{code}")
    end
  rescue ::Exception => e
  end
end
print_status("MSFDONE #{count}")
</ruby>
exit -y
"""


async def metasploit_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    cfg = get_config()
    # msfconsole is far too heavy to run per host across a subnet — skip it in
    # batch/subnet (light) scans; it still runs for single-host scans.
    if (ctx or {}).get("light"):
        return [Finding("metasploit", Severity.INFO,
                        "metasploit: пропущен в пакетном/подсетевом скане (тяжёлый)", {})]
    if not cfg.metasploit_enabled:
        return [Finding("metasploit", Severity.INFO,
                        "metasploit: выключен (включите в ⚙️ Настройки)", {})]
    if shutil.which("msfconsole") is None:
        return [Finding("metasploit", Severity.INFO, "metasploit not installed",
                        {"error": "msfconsole not found on PATH"})]

    vendor = (ctx or {}).get("vendor")
    if not vendor:
        return [Finding("metasploit", Severity.INFO,
                        "metasploit: вендор не определён — пропускаю", {})]

    open_ports = (ctx or {}).get("open_ports") or []
    port = next((p for p in (80, 8080, 8000, 8081, 443, 8443) if p in open_ports), 80)
    rc = _RUBY % {"ip": _safe(target), "vendor": _safe(vendor),
                  "port": port, "maxmods": MAX_MSF_MODULES}
    fd, path = tempfile.mkstemp(prefix="msf_", suffix=".rc")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(rc)

    try:
        async with heavy_semaphore():
            _, stdout, _ = await run_cmd(
                ["msfconsole", "-q", "-n", "-r", path], timeout=MSF_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return [Finding("metasploit", Severity.INFO,
                        f"metasploit: ошибка запуска ({exc})", {})]
    finally:
        with _suppress():
            os.unlink(path)

    findings: list[Finding] = []
    for m in _RESULT_RE.finditer(stdout):
        module, cves, code = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        cve_list = [c for c in cves.split(",") if c]
        title = f"🎯 Потенциально уязвим (Metasploit): {module}"
        if cve_list:
            title += f" [{', '.join(cve_list)}]"
        findings.append(Finding("metasploit", Severity.HIGH, title,
                                {"module": module, "cve": cve_list[0] if cve_list else None,
                                 "cves": cve_list, "check": code}))
        for cve in cve_list:
            record_cve(ctx, cve, "metasploit")

    if not findings:
        findings.append(Finding("metasploit", Severity.INFO,
                                f"metasploit: уязвимостей для {vendor} не подтверждено", {}))
    return findings


def _safe(value: str) -> str:
    # Only allow chars valid in an IP/host/vendor token (defensive for the rc).
    return re.sub(r"[^A-Za-z0-9.:_-]", "", value)[:64]


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, Exception)
