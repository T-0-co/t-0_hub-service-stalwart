# Changelog

Version stamps that must always match: `src/stalwart_mcp/__init__.py` (`__version__`), `pyproject.toml`,
both generated manifests and the first entry below. `tests/test_versions.py` checks it.

## [0.2.0] (2026-10-02)

Shared mailboxes: one login works in several mailboxes, via Stalwart's mailbox ACLs.

### Added

* **`share_mailbox`** (21st mail tool): list, grant (`read` / `edit`) or revoke other users' access to the login's own folders (JMAP Sharing, RFC 9670). Granting requires `confirm=true`.
* **`account="*"`** for `search_emails` (merged newest first, rows carry their account, paging up to 200 rows per account) and `list_changes` (one state token `*:<account>=<state>,…`; accounts shared later start fresh).
* `account_info` lists shared accounts with `can_send: false` and explains what works in a shared mailbox.

### Changed

* `write_email` in a shared mailbox saves the draft there. The sender defaults to the address the original was sent to if it belongs to the mailbox's domain, otherwise the mailbox address.
* `send_email`, filters and the vacation response refuse shared mailboxes with an explanation. Stalwart 0.16 treats identities, submission, Sieve, vacation and quota as owner-only and answered `forbidden`.
* Unknown account names refetch the cached session once, so a mailbox shared a moment ago is found.

## [0.1.0] (2026-10-02)

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
