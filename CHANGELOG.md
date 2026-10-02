# Changelog

Version stamps that must always match: `src/stalwart_mcp/__init__.py` (`__version__`), `pyproject.toml`,
both generated manifests and the first entry below. `tests/test_versions.py` checks it.

## [0.1.0] (unreleased)

First version: an MCP server for Stalwart 0.16 over JMAP, as hub sidecar or standalone.

### Added

* **20 mail tools** (`/mcp`): account info, mailboxes, search with detail levels (`subjects` / `summary` / `headers`),
  read, threads, attachments (PDF/text → text, images → image, attached `.eml` parsed, raw source), change polling
  (`list_changes`), Sieve filters (list/save/delete with validation, backup and a guard against external redirects),
  drafts (new/reply/reply-all/forward) and sending with `confirm_recipients`, move, flags, spam reports, deletion,
  mailbox management, vacation response, List-Unsubscribe one-click with SSRF protection.
* **24 admin tools** (`/admin/mcp`) over the JMAP management API (`urn:stalwart:jmap`): accounts and groups (aliases,
  quota, admin role, disable, password reset), domains with DNS zone text, mailing lists, outbound queue, blocked and
  allowed IPs (with the reload the running server needs), DMARC/TLS report summaries, log search, background tasks,
  reload actions, DMARC/spam diagnosis, and generic read/write access to all management objects.
* Transport rules learned on a production Stalwart: rejected credentials are quarantined and never retried, one
  process-wide pacing budget, `Email/changes` isolated, ban-like 429s pause all traffic.
* Hub manifests generated from the tool lists (`scripts/gen_service_yaml.py`), multi-arch image, CI.
