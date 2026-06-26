"""Parse a batch of scan targets from uploaded text (one or more per line)."""
from __future__ import annotations

import ipaddress
import re

# Hard cap so a huge file can't flood the queue.
MAX_TARGETS = 256

# A permissive hostname label check (RFC-1123-ish): letters/digits/hyphen,
# dot-separated, no leading/trailing hyphen per label.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*)(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)*$"
)


def is_cidr(token: str) -> bool:
    """True if ``token`` is a CIDR subnet (has a prefix length, not a bare IP)."""
    if "/" not in token:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_target(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(token))


def parse_targets(text: str) -> tuple[list[str], int, int]:
    """Extract a de-duplicated, validated target list from ``text``.

    Splits on newlines/commas/whitespace, ignores blank lines and ``#`` comments.
    Returns ``(targets, skipped, truncated)`` where ``skipped`` counts tokens that
    did not look like an IP or hostname, and ``truncated`` counts valid targets
    dropped because the list exceeded :data:`MAX_TARGETS`.
    """
    seen: set[str] = set()
    targets: list[str] = []
    skipped = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for token in re.split(r"[\s,;]+", line):
            token = token.strip()
            if not token:
                continue
            if not _is_valid_target(token):
                skipped += 1
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(token)

    truncated = max(0, len(targets) - MAX_TARGETS)
    return targets[:MAX_TARGETS], skipped, truncated
