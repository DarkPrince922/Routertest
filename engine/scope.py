"""ScopeGate — the authorization gate every target must pass before any tool runs.

Design points (mandatory per ROE):
  * The gate resolves the hostname and checks the *resolved* IP against the
    allowed CIDRs, so a host that DNS-points outside scope is rejected.
  * Every decision is written to the audit table.
  * scope.yaml is the source of truth and is loaded from disk; it is never
    mutated from the bot.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import ScopeDecision
from .store import Store

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ScopeConfig:
    engagement_id: str
    allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    allowed_hosts: set[str]
    # When True the scope gate allows EVERY target (decisions are still audited).
    # Reversible kill-switch: set allow_all: false in scope.yaml to re-enable ROE.
    allow_all: bool = False

    @classmethod
    def load(cls, path: Path) -> "ScopeConfig":
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        engagement_id = str(raw.get("engagement_id") or "unknown")
        cidrs = []
        for entry in raw.get("allowed_cidrs") or []:
            try:
                cidrs.append(ipaddress.ip_network(str(entry), strict=False))
            except ValueError:
                log.warning("scope.yaml: ignoring invalid CIDR %r", entry)
        hosts = {str(h).strip().lower() for h in (raw.get("allowed_hosts") or [])}
        allow_all = bool(raw.get("allow_all", False))
        if allow_all:
            log.warning("scope.yaml: allow_all=true — SCOPE GATE DISABLED, every "
                        "target will be accepted")
        return cls(engagement_id=engagement_id, allowed_cidrs=cidrs,
                   allowed_hosts=hosts, allow_all=allow_all)


def _subnet_of(net, allowed) -> bool:
    """True if ``net`` is contained in ``allowed`` (same IP version only)."""
    if net.version != allowed.version:
        return False
    try:
        return net.subnet_of(allowed)
    except (TypeError, ValueError):
        return False


def _resolve_ip(target: str) -> str | None:
    """Resolve a host/IP to a single IP string, or None on failure.

    If ``target`` is already an IP literal it is returned unchanged.
    """
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        # getaddrinfo handles both IPv4/IPv6; take the first resolved address.
        infos = socket.getaddrinfo(target, None)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        return None
    return None


class ScopeGate:
    """Checks targets against the loaded ROE and audits every decision."""

    def __init__(self, config: ScopeConfig, store: Store) -> None:
        self._config = config
        self._store = store

    @property
    def engagement_id(self) -> str:
        return self._config.engagement_id

    @property
    def config(self) -> ScopeConfig:
        return self._config

    def check(self, target: str, actor_id: int | None = None) -> ScopeDecision:
        """Resolve ``target`` and decide if it is in scope. Always audits."""
        target = target.strip()
        host_key = target.lower()

        # Explicit allowed_hosts entry is an allow (still resolve for the record).
        host_allowed = host_key in self._config.allowed_hosts
        resolved_ip = _resolve_ip(target)

        if self._config.allow_all:
            # Scope gate disabled — accept everything but still audit the decision.
            decision = ScopeDecision(
                target=target,
                resolved_ip=resolved_ip,
                allowed=True,
                reason="allow_all enabled in scope.yaml (scope gate disabled)",
            )
        elif resolved_ip is None and not host_allowed:
            decision = ScopeDecision(
                target=target,
                resolved_ip=None,
                allowed=False,
                reason="DNS resolution failed and host not in allowed_hosts",
            )
        else:
            ip_in_scope = False
            if resolved_ip is not None:
                try:
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    ip_in_scope = any(ip_obj in net for net in self._config.allowed_cidrs)
                except ValueError:
                    ip_in_scope = False

            allowed = host_allowed or ip_in_scope
            if allowed:
                if host_allowed and not ip_in_scope:
                    reason = "host explicitly allowed in scope.yaml"
                else:
                    reason = f"resolved IP {resolved_ip} within allowed_cidrs"
            else:
                reason = (
                    f"resolved IP {resolved_ip} not in allowed_cidrs and host "
                    f"not in allowed_hosts"
                )
            decision = ScopeDecision(
                target=target,
                resolved_ip=resolved_ip,
                allowed=allowed,
                reason=reason,
            )

        self._store.add_audit(
            actor_id=actor_id,
            action="scope_check",
            target=decision.target,
            resolved_ip=decision.resolved_ip,
            decision="ALLOWED" if decision.allowed else "REJECTED",
            engagement_id=self._config.engagement_id,
        )
        log.info(
            "scope_check target=%s ip=%s decision=%s reason=%s",
            decision.target,
            decision.resolved_ip,
            "ALLOWED" if decision.allowed else "REJECTED",
            decision.reason,
        )
        return decision

    def check_network(self, cidr: str, actor_id: int | None = None) -> ScopeDecision:
        """Authorize a whole subnet before sweeping it (audited).

        Allowed when ``allow_all`` is set or the CIDR is a subset of one of the
        ``allowed_cidrs``.
        """
        cidr = cidr.strip()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            decision = ScopeDecision(cidr, None, False, "некорректная подсеть")
        else:
            if self._config.allow_all:
                decision = ScopeDecision(cidr, None, True,
                                         "allow_all enabled (scope gate disabled)")
            else:
                allowed = any(_subnet_of(net, allowed_net)
                              for allowed_net in self._config.allowed_cidrs)
                reason = ("подсеть входит в allowed_cidrs" if allowed
                          else "подсеть вне allowed_cidrs")
                decision = ScopeDecision(cidr, None, allowed, reason)

        self._store.add_audit(
            actor_id=actor_id, action="scope_check_network", target=cidr,
            resolved_ip=None,
            decision="ALLOWED" if decision.allowed else "REJECTED",
            engagement_id=self._config.engagement_id,
        )
        log.info("scope_check_network cidr=%s decision=%s reason=%s", cidr,
                 "ALLOWED" if decision.allowed else "REJECTED", decision.reason)
        return decision
