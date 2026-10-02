# stalwart-mcp

An [MCP](https://modelcontextprotocol.io) server for [Stalwart](https://stalw.art) mail servers, built on JMAP.
It lets Claude (or any MCP client) search, read, write and organise mail, manage folders, Sieve filters and
out-of-office replies — with safety rules for the parts where an AI assistant can do damage.

It runs in two ways:

- **As a sidecar behind an MCP hub** (the [T-0 MCP hub](https://github.com/T-0-co)): the hub stores each person's Stalwart credential and
  sends it with every tool call. The hub manifests are generated into `service.yaml` (mail) and
  `manifests/stalwart-admin/service.yaml` (admin).
- **Standalone** next to your Stalwart server, added to Claude as a custom connector. *(OAuth sign-in against
  Stalwart's own OAuth server is on the roadmap; see below.)*

## Tools

| Tool | What it does | Kind |
|---|---|---|
| `account_info` | Accounts, sending identities, quota, vacation status, filters, server limits | read |
| `list_mailboxes` | Folder tree with roles and counts | read |
| `search_emails` | Filters (text, from, to, subject, folder, dates, unread, flagged, attachments, size); `detail` = `subjects` / `summary` / `headers`; thread collapsing; match snippets; paging | read |
| `read_email` | Up to 20 emails; body as text (HTML → Markdown, hidden elements removed), attachment list | read |
| `get_thread` | A conversation in order, quoted history stripped | read |
| `load_attachment` | PDF/text → text, images → image, attached `.eml` parsed, or the raw source of the email | read |
| `list_changes` | Created/updated/deleted emails since a state token — for polling from n8n or agents | read |
| `list_filters` | Sieve scripts with content | read |
| `write_email` | Draft only: new, reply, reply-all, forward (original attached); attachments from other mails or inline | write |
| `send_email` | Sends a draft; requires `confirm_recipients` to match the draft exactly | sends mail |
| `move_emails` | Move by folder path, role (`archive`, `inbox`, …) or id | write |
| `set_flags` | Read/unread, flagged, answered | write |
| `report_spam` | Junk / not junk, trains the spam filter | write |
| `delete_emails` | To Trash; permanent deletion only from Trash/Junk | destructive |
| `manage_mailbox` | Create, rename, move folders | write |
| `delete_mailbox` | Empty folders only; system folders protected | destructive |
| `save_filter` | Validate and save a Sieve script, keep the previous version as `<name>.previous` | destructive |
| `delete_filter` | Remove a Sieve script | destructive |
| `set_vacation` | Out-of-office reply with period | write |
| `unsubscribe` | List-Unsubscribe one-click (RFC 8058), mailto via draft, never opens web links | sends request |

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`), so clients like claude.ai
can ask for approval on writes.

## Admin tools (`/admin/mcp`)

A second MCP endpoint on the same server, for administrators, over Stalwart 0.16's JMAP management API
(`urn:stalwart:jmap`; reference with all quirks: [docs/stalwart-management-api.md](docs/stalwart-management-api.md)).
Credential: the administrator's own **API key** (`Bearer API_…`), ideally restricted to the server's IP.

| Tool | What it does |
|---|---|
| `admin_info` | Login, edition, management permissions of the credential |
| `list_accounts`, `get_account` | Accounts/groups with aliases, quota and usage, admin flag, disabled state, groups, credentials (never secrets) |
| `create_account`, `update_account`, `delete_account` | Create (optional generated password, returned once), change aliases/quota/groups/admin/enabled, reset password; deletion needs `confirm_address` |
| `list_domains`, `get_domain_dns`, `create_domain`, `delete_domain` | Domains, DKIM keys, the full DNS record set as BIND zone text; deletion needs `confirm_name` |
| `list_mailing_lists`, `manage_mailing_list` | Distribution lists and their recipients |
| `list_queue`, `queue_action` | Outbound queue with per-recipient errors; retry now, reschedule, cancel, pause/resume |
| `list_ips`, `manage_ip` | Blocked (incl. auto-bans) and allowed IPs; unblock/block/allow/unallow with the reload the server needs |
| `list_reports` | DMARC aggregate / TLS-RPT reports summarised: volume, failing sources |
| `search_logs` | Server log lines, newest first, anchor paging |
| `list_tasks`, `run_task`, `run_action` | Background tasks (DKIM, DNS, ACME, spam training, account maintenance), reloads and cache actions |
| `diagnose` | DMARC evaluation and spam classification of a message |
| `query_objects`, `set_object` | Generic read/write of any management object (expert tools) |

## Safety model

Mail is the one data source where *anyone on the internet* can put text in front of the model. The server assumes
that this text may contain instructions (prompt injection) and limits what such text can achieve:

- **Draft first.** `write_email` never sends. `send_email` refuses unless `confirm_recipients` lists exactly the
  draft's recipients, so the approval dialog shows who will receive the mail. Bcc is passed at send time and never
  written into the stored message.
- **No silent forwarding.** `save_filter` refuses Sieve `redirect`/`notify` targets outside the account's own
  domains unless `allow_external_redirect=true` is passed explicitly.
- **No outbound requests to internal networks.** One-click unsubscribe only calls `https` URLs whose host resolves
  to public addresses, does not follow redirects and ignores the response body.
- **Hidden HTML is dropped** before the model sees a body (`display:none`, zero-size text, tracking pixels).
  This is damage control, not a boundary: every result with mail content is marked as untrusted data.
- **Permanent deletion** only for mails already in Trash or Junk; system folders cannot be renamed or deleted.

## Operating against Stalwart

Rules learned against a production Stalwart (0.16), enforced in `jmap.py`:

- **Rejected credentials are never retried.** Stalwart bans the source IP after failed logins — on some setups
  after a single one — for every account behind that IP. A rejected credential is quarantined for an hour; a new
  credential passes immediately.
- **One pacing budget per process** (default 4 request starts/s, 4 concurrent). Stalwart counts per source IP, and
  behind a hub all users share one IP. Searches are batched into single JMAP requests with result references.
- **Put this server's IP on Stalwart's allowed list** (Settings › Security › Allowed IPs) and then run the action
  *Reload Settings* — allowed-IP entries only take effect after a reload. Allowed IPs bypass rate limits and automatic
  bans, so one person's typo cannot lock everyone out; the quarantine above replaces Stalwart's brute-force protection
  for that IP. Unblocking a banned IP likewise needs *Reload Blocked IPs* (`manage_ip` does both).
- `Email/changes` always runs in its own HTTP request: a stale state token answers HTTP 400 for the whole request.
- `Email/set` is always written as a patch (`mailboxIds/<id>`, `keywords/<kw>`); keywords are lowercase.
- The `header` condition of `Email/query` returns no results on Stalwart instead of an error, so it is not offered.

## Configuration

| Variable | Default | |
|---|---|---|
| `STALWART_URL` | — | Base URL, e.g. `https://mail.example.com` (required) |
| `STALWART_MAX_RPS` | `4` | Request starts per second towards Stalwart, all users together |
| `STALWART_MAX_CONCURRENT` | `4` | Parallel requests (Stalwart's `maxConcurrentRequests`) |
| `STALWART_INTERNAL_DOMAINS` | — | Extra domains Sieve filters may redirect to without confirmation |
| `STALWART_MAX_ATTACHMENT_BYTES` | `26214400` | Largest attachment that is downloaded |
| `MCP_ALLOWED_HOSTS` | — | Host header allow-list (DNS rebinding protection), e.g. `mcp.example.com` |
| `PORT` | `8000` | |

Credentials arrive per request in the `Authorization` header: `Bearer user@domain:app-password` (what a hub sends;
forwarded as HTTP Basic), `Bearer <token>` (Stalwart API key or OAuth token) or `Basic …`.

Endpoints: `POST /mcp` (MCP, Streamable HTTP, stateless), `GET /health`, `GET /auth-check` (one session request
with the given credential — used by the hub's "test connection").

## Running

```bash
docker run -p 8000:8000 -e STALWART_URL=https://mail.example.com ghcr.io/t-0-co/hub-service-stalwart:latest
```

### Hub installation

The hub loads one `service.yaml` per repository, so there are two service repositories per hub:

| Service | Manifest | Deploys | Users store |
|---|---|---|---|
| `stalwart` | `service.yaml` | the sidecar container `stalwart-mcp` | `address@domain:app-password` |
| `stalwart-admin` | `manifests/stalwart-admin/service.yaml` | nothing (uses the same sidecar) | their own admin API key |

Set `STALWART_URL` and `STALWART_MCP_URL=http://stalwart-mcp:8000` for both. Give `stalwart-admin` only to the
admin group. Hub >= 2.28.0 is needed for `mcpProxy.passthrough` (images and error flags reach the client unchanged).

## Development

```bash
uv sync
uv run pytest -q                               # unit tests + tests against an in-process fake Stalwart (mail + admin)
uv run pytest -m live tests/test_live.py       # against a real throwaway mailbox, see the file header
uv run ruff check src scripts tests
uv run python scripts/gen_service_yaml.py      # regenerate both manifests after tool changes (CI checks it)
STALWART_URL=https://mail.example.com uv run stalwart-mcp
```

The hub registers proxied tools from `service.yaml`, not from the sidecar, so the manifest is generated from the
server's own tool list and CI fails when they drift.

## Roadmap

- Standalone OAuth: the server as an OAuth resource server delegating sign-in to Stalwart's built-in OAuth
  (dynamic client registration + PKCE), so it can be added to Claude as a custom connector without app passwords.
