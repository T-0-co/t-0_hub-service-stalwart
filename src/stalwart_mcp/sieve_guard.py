"""Static checks on Sieve scripts before they are saved.

@warn A Sieve `redirect` to an outside address is a quiet exfiltration channel: every
      future mail leaves the server, and nobody sees it in a mail client. Since tools
      may be driven by text that arrived by mail (prompt injection), redirects to
      domains outside the account's own are refused unless explicitly allowed.
"""

from __future__ import annotations

import re

_REDIRECT = re.compile(r'\bredirect\b((?:\s+:[a-z-]+(?:\s+"[^"]*")?)*)\s+"((?:[^"\\]|\\.)*)"', re.I)
_NOTIFY_MAILTO = re.compile(r'\bnotify\b[^;]*?"mailto:([^"?]+)', re.I)
_STRING_LIST_REDIRECT = re.compile(r"\bredirect\b[^;]*\[", re.I)
_TEXT_END = re.compile(r"\r?\n\.\r?\n")


def _strip_comments(script: str) -> str:
    """Remove `#` and `/* */` comments, keeping string literals intact (RFC 5228 §2.3)."""
    out: list[str] = []
    i, n = 0, len(script)
    while i < n:
        c = script[i]
        if c == '"':
            j = i + 1
            while j < n and script[j] != '"':
                j += 2 if script[j] == "\\" else 1
            out.append(script[i : j + 1])
            i = j + 1
        elif c == "#":
            j = script.find("\n", i)
            i = n if j < 0 else j
        elif script.startswith("/*", i):
            j = script.find("*/", i + 2)
            out.append(" ")
            i = n if j < 0 else j + 2
        elif script.startswith("text:", i):
            m = _TEXT_END.search(script, i)
            j = n if not m else m.end()
            out.append(script[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def outbound_targets(script: str) -> list[str]:
    """Addresses that a script would send mail to (redirect, notify mailto)."""
    body = _strip_comments(script)
    targets = [m.group(2).strip() for m in _REDIRECT.finditer(body)]
    targets += [m.group(1).strip() for m in _NOTIFY_MAILTO.finditer(body)]
    if _STRING_LIST_REDIRECT.search(body):
        targets.append("<string list>")
    return targets


def external_targets(script: str, own_domains: set[str]) -> list[str]:
    own = {d.lower().lstrip("@") for d in own_domains}
    out = []
    for target in outbound_targets(script):
        if "${" in target or "@" not in target:
            out.append(target)  # variables / unparsable: cannot be verified
            continue
        domain = target.rsplit("@", 1)[1].lower().rstrip(">").strip()
        if domain not in own:
            out.append(target)
    return out
