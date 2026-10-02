# Stalwart 0.16 – JMAP management API reference

Reference for building admin tools (MCP server `t-0_hub-service-stalwart`) against Stalwart Mail Server 0.16.

Researched 2026-10-02. Sources:

- Reference docs `https://stalw.art/docs/ref/` (one page per object, `…/ref/object/<kebab-name>/`), `…/ref/permissions/`, `…/ref/events/`, `…/ref/metrics/`, plus the linked guide pages (management/cli, configuration, auth, domains, mta, telemetry, development/api, UPGRADING/v0_16.md).
- Server source, tag `v0.16.24` (latest release, 2026-09-27), github.com/stalwartlabs/stalwart. The server bundles a JSON schema (`resources/schema/schema.json.gz`), which it also serves at `GET /api/schema`.
- CLI source, github.com/stalwartlabs/cli (main).

Legend:

- **[docs]**: stated in the docs.
- **[src]**: confirmed in the v0.16.24 source, the bundled schema, or the CLI source.
- **unverified**: not confirmed. Where docs and source disagree, both are given and the source behaviour is labelled "per source".

---

## 0. Cross-cutting facts (read first)

### 0.1 Endpoint, capability, methods

| Item | Value |
|---|---|
| Capability URN | `urn:stalwart:jmap`. This is the only management capability [docs][src]. |
| Wire type names | `x:<Object>`, e.g. `x:Domain`. Method names follow the pattern `x:Domain/get`. The CLI and the docs drop the `x:` prefix [docs]. |
| Session resource | `GET /jmap/session`. `GET /.well-known/jmap` returns `307` with `Location: /jmap/session` [src]. |
| API endpoint | `POST /jmap/`, which is the session `apiUrl` (`{baseUrl}/jmap/`). `POST /jmap` also works [src]. The CLI fetches `/jmap/session` and posts to the path of `apiUrl` [src cli]. Required header: `Content-Type: application/json`; anything else returns request error `notJSON` [src]. |
| ⚠ Docs curl URL | Every ref page posts to `https://mail.example.com/api`. **This is wrong for v0.16.24.** `/api/*` only serves `auth`, `discover`, `account`, `schema`, `token` and `live`; any other path returns 404 [src: http/src/api/mod.rs]. The bundled OpenAPI spec says: "most of the server's configuration and data is managed via JMAP (see `POST /jmap/`)". UPGRADING/v0_16.md says: "The `/api/...` endpoints from previous releases no longer exist. All management operations happen through **JMAP objects** reachable at `/jmap`." |
| `using` | `["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]`, as in the docs examples and the CLI constant `USING` [src cli]. Per source the server does not reject an `x:` call if `urn:stalwart:jmap` is missing from `using` (`capability != Capability::Stalwart && !using.contains(..)`). Send it anyway. |
| Methods per object | Only `x:<Obj>/get`, `x:<Obj>/set` and `x:<Obj>/query`. Singletons support only `/get` and `/set`. **No `/changes`, `/queryChanges` or `/copy` exists for any `x:` object.** Such names fail to parse and return method error `unknownMethod` [src: jmap-proto/request/method.rs `MethodName::parse` maps only `get`/`set`/`query`, and maps `query` only for non-singletons]. The task brief mentioned `/changes`; it does not exist. |
| Extra method arguments | None. The registry object type declares `GetArguments = ()`, `SetArguments = ()` and `QueryArguments = ()` [src: jmap-proto/object/registry.rs]. Only the standard RFC 8620 arguments apply: `accountId`, `ids`, `properties`, `create`, `update`, `destroy`, `ifInState`, `filter`, `sort`, `position`, `anchor`, `anchorOffset`, `limit`, `calculateTotal`. |
| Result references | The standard RFC 8620 `#ids`/`resultOf` back-references work. `resolve_references` runs for every call, and registry `/set` responses feed `createdIds`, so `"#new1"` creation ids can be used in later calls of the same request [src]. |
| Limits (Jmap singleton defaults) [docs] | `maxMethodCalls` 16, `maxRequestSize` 10000000, `maxConcurrentRequests` 4 per user, `getMaxResults` 500 (= `maxObjectsInGet`), `setMaxObjects` 500 (= `maxObjectsInSet`), `queryMaxResults` 5000. |

Session object shape. This is derived from the source (`jmap-proto/request/capability.rs`, `jmap/api/session.rs`); field values are illustrative:

```json
{
  "capabilities": {
    "urn:ietf:params:jmap:core": {"maxSizeUpload": 50000000, "maxConcurrentUpload": 4, "maxSizeRequest": 10000000,
      "maxConcurrentRequests": 4, "maxCallsInRequest": 16, "maxObjectsInGet": 500, "maxObjectsInSet": 500,
      "collationAlgorithms": ["..."]},
    "urn:ietf:params:jmap:websocket": {"url": "wss://mail.example.com/jmap/ws", "supportsPush": true}
  },
  "accounts": {
    "<ownAccountId>": {"name": "admin@example.com", "isPersonal": true, "isReadOnly": false,
      "accountCapabilities": {"urn:stalwart:jmap": {}}}
  },
  "primaryAccounts": {"urn:stalwart:jmap": "<ownAccountId>"},
  "username": "admin@example.com",
  "apiUrl": "https://mail.example.com/jmap/",
  "downloadUrl": "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
  "uploadUrl": "https://mail.example.com/jmap/upload/{accountId}/",
  "eventSourceUrl": "https://mail.example.com/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
  "state": "…"
}
```

How the management capability appears in the session, per source:

- `urn:stalwart:jmap` is always listed in each account's `accountCapabilities`, with an empty object `{}` as its value.
- It is also listed in `primaryAccounts`, pointing at the caller's own account.
- It is **not** added to the top-level `capabilities` object. There is no session-level management capability data.
- The top-level `capabilities` lists all standard capabilities the server supports (core, mail, submission, calendars, contacts, …) regardless of the caller's permissions.
- `accountCapabilities` and `primaryAccounts` list `urn:stalwart:jmap`, websocket and principals for every principal. The other capabilities appear only when the principal holds the matching JMAP permission (for example `jmapEmailGet` for mail). A management-only API key may therefore show almost nothing besides `urn:stalwart:jmap`.

Not checked against a live server: do not make tool start-up depend on finding `capabilities["urn:stalwart:jmap"]`.

### 0.2 Authentication (admin)

| Scheme | Header | Notes |
|---|---|---|
| Basic | `Authorization: Basic base64(login:secret)` | `login` is the account's email address. In 0.16, account names are full addresses; a bare user name gets the default domain appended (UPGRADING/v0_16.md). The CLI uses `--user`/`--password` or `STALWART_USER`/`STALWART_PASSWORD`. Whether app passwords work as the Basic secret on the management API is unverified. SCIM refuses Basic auth. |
| Bearer with an API key | `Authorization: Bearer API_…` | Create the key with `x:ApiKey/set`. Format: `"API_"` + base64url-no-pad(accountId u32 BE ‖ credentialId u32 BE ‖ 20 random bytes) [src: common/auth/credential.rs]. Valid for the management API only; it does not work for IMAP, POP3, JMAP mail, SMTP submission, CalDAV, CardDAV or WebDAV [docs]. This is the recommended credential for unattended tools; the CLI uses `--api-key`/`STALWART_TOKEN`. |
| Bearer with an OAuth token | `Authorization: Bearer <access_token>` | Token from `POST /auth/token`, via the authorization-code flow (PKCE optional) or the device flow (RFC 8628) [docs]. |
| Live token | `?token=<t>` | Only for the SSE endpoints `/api/live/*`. Obtained from `GET /api/token/{delivery\|tracing\|metrics}`; valid for 60 s [docs]. |

How authentication failures look:

- The server answers HTTP `401` with `WWW-Authenticate: Bearer realm="Stalwart Server", resource_metadata="/.well-known/oauth-protected-resource"` and a body of type `application/problem+json` (RFC 7807) [src][docs]. Some endpoints add a second `WWW-Authenticate: Basic realm="Stalwart Server"` header [src].
- Bearer attempts are also subject to the anonymous HTTP rate limit.
- Authentication failures count towards the auto-ban (`Security.authBanRate`).

Who counts as an admin:

- There is no dedicated admin account type [docs]. Admin power comes from permissions, normally granted through roles.
- `roles: {"@type":"Admin"}` on a User account expands to `Authentication.defaultAdminRoleIds`. If the account creating it is a tenant admin, it expands to `defaultTenantRoleIds` instead [src: common/auth/permissions.rs].
- On a fresh install, the server creates four Role objects, described as "User", "Group", "Tenant Administrator" and "System Administrator". The defaults are: `defaultAdminRoleIds` = [System Administrator, User] and `defaultTenantRoleIds` = [Tenant Administrator, User] [src: common/manager/defaults.rs].
- Emergency access: the environment variable `STALWART_RECOVERY_ADMIN=user:pass` is honoured only in recovery or bootstrap mode [docs].

Introspection: `GET /api/account` (authenticated) returns `{"permissions": [...], "edition": "oss|community|enterprise", "locale": "en-US"}` [docs]. This lets a tool find out what the token may do. The docs example shows kebab-case names (`"jmap-email-get"`); the format actually returned is unverified. JMAP payloads use camelCase.

### 0.3 `accountId`

- `accountId` is optional on every `x:` method. When it is omitted, or is not a parseable id, the server substitutes the caller's own account id [src: jmap/api/request.rs `resolve_account_id`].
- If `accountId` is supplied, the caller must be a member of that account (its own id, or a group it belongs to). Otherwise the call fails [src: `assert_is_member`].
- There is no special "system" account. **Recommendation: never send `accountId`.** The CLI never does.
- Objects scoped to the account behind `accountId`, i.e. effectively the caller [src]:
  - `x:ApiKey`, `x:AppPassword`, `x:AccountPassword` and `x:AccountSettings` always act on that account.
  - `x:PublicKey`, `x:MaskedEmail`, `x:SpamTrainingSample` and `x:ArchivedItem` are filtered by it, unless the caller holds the `impersonate` permission.
- Tenant isolation: for a caller who belongs to a tenant, tenant-filtered objects are both restricted to that tenant and stamped with it [src]. Tenant-filtered objects are Account, AcmeProvider, ArfExternalReport, Directory, DkimSignature, DmarcExternalReport, DnsServer, Domain, MailingList, OAuthClient, Role and TlsExternalReport.

### 0.4 Value encoding [docs: /docs/configuration/object-encoding][src]

| Schema type | JSON on the wire | Example |
|---|---|---|
| `List<T>` | Object keyed by the stringified position `"0"`, `"1"`, … (**not** an array) | `"aliases": {"0": {"name": "info", "domainId": "b"}}` |
| `Set<T>` | Object mapping each member to `true`; empty set is `{}` | `"memberGroupIds": {"c": true}` |
| `Map<K,V>` | Plain JSON object | `"quotas": {"maxDiskQuota": 1073741824}` |
| `Duration` | Integer milliseconds; strings are rejected | `7776000000` (90 days) |
| `Size` | Integer bytes | `104857600` |
| `UTCDateTime` | RFC 3339 UTC | `"2026-01-01T00:00:00Z"` |
| `Id<X>` | JMAP id string (opaque, short base32-like) | `"b"` |
| Multi-variant object | `{"@type": "<Variant>", …}`, with the variant's fields at the same level ("Carries the fields of …") | `{"@type": "Custom", "roleIds": {"r1": true}}` |
| Singleton id | The literal string `"singleton"`; `ids: null` also returns it | |
| `secret` fields | Returned masked as `"****"`. Sending `"****"` back keeps the stored value [src] | |

Rules for update patches (`x:…/set` `update`) [docs: cli/update][src]:

- Top-level keys may be JSON pointers:
  - Nested field: `"aliases/2/name": "x"`.
  - Add or remove a set member: `"memberGroupIds/<id>": true` or `null`.
  - Set or delete a map key: `"quotas/maxDiskQuota": 123` or `null`.
  - Add a list element: `"aliases/3": {...}`; remove it: `"aliases/3": null`.
- Changing a variant (`@type`) requires sending the whole sub-object.
- A wrongly encoded value produces SetError `invalidPatch`, for example `invalidPatch | Invalid value for object property | Properties: retry/intervals` [docs].

Further notes:

- In the docs, "read-only" corresponds to the schema mode `immutable`: the field can be set on create and never updated. "server-set" corresponds to `serverSet`: it is computed by the server and cannot be set [src: schema `update` attribute; the CLI `describe` shows `mutable` / `immutable` / `server-set`].
- Fields the docs mark "required" without a default are always present on reads. Many of them can still be omitted on create: the server then uses the Rust `Default` value (for example `roles` → `User`, `permissions` → `Inherit`) [src]. True create-time requirements are listed per object below.

### 0.5 `/query` semantics (all `x:` objects) [src: jmap/registry/query.rs]

- **Conjunction:** a filter is an object of conditions, implicitly ANDed. `{"operator":"AND","conditions":[…]}` is accepted. **`OR` and `NOT` are rejected** with `unsupportedFilter: Only AND is supported in filters`. The docs claim filters are "combinable with `AnyOf` / `AllOf` / `Not` per RFC 8620"; per source that is false. The CLI docs agree with the source: "JMAP's filter object only supports a single conjunction".
- **Comparisons** use key suffixes: `<prop>IsGreaterThan`, `<prop>IsGreaterThanOrEqual`, `<prop>IsLessThan`, `<prop>IsLessThanOrEqual` (e.g. `"dueIsLessThan": "2026-10-02T00:00:00Z"`) [src][docs cli/query].
- **Unsupported filters** produce `unsupportedFilter: Filter on property X is not supported or invalid`.
- **Generic objects** can be filtered on their indexed properties only:
  - `text`: full-text, matched on tokens.
  - Keyword-indexed properties (e.g. `name` on Account, Domain and MtaRoute): exact match.
  - Id fields: exact match.
  - `IpMask` fields: the value must parse as an IP or CIDR.
- **Sorting:** only the first comparator is used, e.g. `[{"property":"name","isAscending":true}]`. The default is `id` **descending**. Sortable properties are the indexed non-text ones; anything else returns `unsupportedSort`.
- **Paging:** `position`, `anchor`, `limit` (capped at `queryMaxResults`, 5000) and `calculateTotal` work as in RFC 8620. Per-object exceptions are listed below; Log, for example, pages by anchor only.
- **Tenant admins:** a tenant admin's `memberTenantId` filter is replaced by its own tenant.

### 0.6 Errors

Request-level errors return HTTP 4xx with `application/problem+json`, per RFC 8620 §3.6.1. Examples: `urn:ietf:params:jmap:error:notJSON` ("The Content-Type header must be application/json."), `limit` and `notRequest`.

Method-level errors are a standard invocation [src: jmap-proto/error/method.rs]:

```json
["error", {"type": "forbidden", "description": "You are not authorized to create objects of this type"}, "c1"]
```

| Method error `type` | When (for `x:` methods) |
|---|---|
| `forbidden` | Missing `sys*` permission. The messages are "You are not authorized to create, update or destroy objects of this type", "... to create objects of this type", "... to update ...", "... to destroy ..." and, for get/query, "You are not authorized to perform this action". Also returned in bootstrap mode ("The server is in bootstrap mode. Only the 'Bootstrap' object type can be accessed until the bootstrap process is complete."), for an Enterprise-only object on a non-Enterprise server ("This feature is only available in the Enterprise edition. …"), and when `accountId` is not one the caller belongs to. |
| `unknownMethod` | Unknown object or method, `/changes`, or `/query` on a singleton. |
| `invalidArguments` | E.g. "Actions cannot be queried", "No log tracers configured on the server", "Pagination is only possible using anchors for logs". |
| `unsupportedFilter` / `unsupportedSort` | See 0.5. |
| `requestTooLarge` | More `ids` than `maxObjectsInGet`. |
| `anchorNotFound`, `invalidResultReference`, `accountNotFound`, `serverFail`, `serverPartialFail` | Standard RFC 8620 meanings. |

SetError objects appear in `notCreated`, `notUpdated` and `notDestroyed`. Shape per source (jmap-proto/error/set.rs); empty fields are omitted:

```json
{"type": "objectIsLinked", "description": "…", "properties": ["name"], "existingId": "…",
 "objectId": {"object": "Domain", "id": "b"},
 "linkedObjects": [{"object": "DkimSignature", "id": "c"}],
 "validationErrors": [{"type": "Required", "property": "name"}]}
```

| SetError `type` | Meaning |
|---|---|
| `objectIsLinked` | A destroy was blocked because other objects reference this one. `objectId` and `linkedObjects` name them. |
| `invalidForeignKey` | A referenced id does not exist, or belongs to another tenant. `objectId` is the missing target. |
| `primaryKeyViolation` | A unique key is already taken (address, domain name, route name …). `properties` names the field; `objectId` is the existing object. |
| `validationFailed` | `validationErrors[]` with entries `{"type":"Invalid","property","value"}`, `{"type":"Required","property"}`, `{"type":"MaxLength"\|"MinLength"\|"MaxValue"\|"MinValue","property","required"}`. Also returned for failed reloads. |
| `invalidPatch` | Malformed value or JSON pointer. |
| `invalidProperties` | Semantic rejection, with `properties` and `description` (password policy, "Credential type cannot be changed.", …). |
| `forbidden` | Per-object refusal, e.g. "You are not authorized to grant permissions: …", "Telemetry objects cannot be created", "Insufficient permissions to perform action of type X". |
| `singleton` | Attempt to destroy a singleton. |
| `notFound`, `willDestroy`, `overQuota` | Standard RFC 8620 meanings. |

### 0.7 Permissions [docs: /docs/ref/permissions][src]

- Each object `X` has the permissions `sysXGet`, `sysXCreate`, `sysXUpdate`, `sysXDestroy` and `sysXQuery`. Singletons have only `sysXGet` and `sysXUpdate`. All are camelCase strings on the wire (e.g. `"sysAccountGet"`) [src: registry enums `Permission::as_str`].
- `/set` checks the create, update and destroy permissions separately. If the call contains an operation the caller may not perform, the **whole call** fails with method error `forbidden` [src: jmap/api/auth.rs `validate_set`].
- Some objects also need a per-variant permission. For Action this is e.g. `actionReloadSettings`; for Task, e.g. `taskDnsManagement`. If it is missing, the affected object gets SetError `forbidden`.
- A caller can only grant permissions it holds itself, whether through roles, permission lists or API key modes. Otherwise it gets SetError `forbidden` "You are not authorized to grant permissions: a, b and N more" [src].
- ⚠ The page /docs/auth/authorization/permissions/ lists **legacy kebab-case names** (`logs-view`, `message-queue-list`, …). The authoritative 0.16 names are on /docs/ref/permissions (`sysLogQuery`, `sysQueuedMessageQuery`, …).

### 0.8 When changes take effect [docs: /docs/configuration "Applying changes"]

- Directory data (accounts, domains, mailing lists, aliases, group memberships) takes effect immediately.
- Anything compiled into the running core takes effect only after `x:Action` `{"@type":"ReloadSettings"}`. This covers listeners, MTA rules and expressions (routing incl. MtaRoute and MtaOutboundStrategy, queue and TLS strategies, address rewriting, DKIM signing), directory backends and telemetry. Narrower, cheaper reloads exist: `ReloadTlsCertificates`, `ReloadLookupStores` and `ReloadBlockedIps`.
- Per source:
  - `x:BlockedIp/set` does not update the in-memory block list; follow it with `ReloadBlockedIps`.
  - AllowedIp entries, Security and Authentication (password policy, default roles) are parsed into the core and need `ReloadSettings`.
  - Bans the server creates itself apply immediately.

### 0.9 Server modes [docs]

- **Bootstrap mode:** active when no `config.json` exists. Only `x:Bootstrap` is reachable; every other `x:` call returns `forbidden`.
- **Recovery mode:** started with `STALWART_RECOVERY_MODE=1`. Only the management HTTP endpoint (port 8080) is up.

---

## 1. Account – `x:Account`

| Item | Value |
|---|---|
| JMAP type | `x:Account`. Multi-variant: `@type` is `"User"` or `"Group"`. |
| Kind | Collection object (not a singleton); tenant-filtered. |
| Methods | `x:Account/get`, `x:Account/set` (create, update, destroy), `x:Account/query` |
| Permissions | `sysAccountGet`, `sysAccountCreate`, `sysAccountUpdate`, `sysAccountDestroy`, `sysAccountQuery` |
| WebUI | Management › Directory › Accounts; Management › Directory › Groups |

### 1.1 Fields – `@type: "User"` [docs; mutability from schema]

| Field | Type | Required / default | Mutability | Notes |
|---|---|---|---|---|
| `@type` | `"User"` | required on create | type cannot change | Changing it fails with `invalidProperties` "Cannot change the type of an existing account." [src] |
| `name` | `EmailLocalPart` | **required** | mutable | Local part. Login and primary address are `name@<domain>`. |
| `domainId` | `Id<Domain>` | **required** | mutable | |
| `emailAddress` | `EmailAddress` | – | server-set | Computed `name@domain` (returned by get). |
| `credentials` | `List<Credential>` | `{}` | mutable | See 1.3. Secrets come back as `"****"`. |
| `createdAt` | `UTCDateTime` | now | server-set | |
| `memberGroupIds` | `Set<Id<Account>>` (Group accounts) | `{}` | mutable | Group membership ("member of"). Non-existent groups fail with `invalidForeignKey` [src]. |
| `memberTenantId` | `Id<Tenant>?` | `null` | mutable | Enterprise multi-tenancy. |
| `roles` | `UserRoles` | docs: required; default `{"@type":"User"}` [src] | mutable | See 1.3. |
| `permissions` | `Permissions` | docs: required; default `{"@type":"Inherit"}` [src] | mutable | See 1.3. |
| `quotas` | `Map<StorageQuota, UnsignedInt>` | `{}` | mutable | `maxDiskQuota` in bytes, plus object-count limits (enum in 1.4). |
| `usedDiskQuota` | `Size` | – | server-set | Bytes used (computed by get). |
| `aliases` | `List<EmailAlias>` | `{}` | mutable | Additional addresses. |
| `externalId` | `String?` (enterprise) | `null` | mutable | SCIM id. If not null, must be non-empty. |
| `description` | `String?` | `null` | mutable | **Display name.** Shown as "Full Name" in the WebUI; SCIM `displayName` maps here. If not null, must be non-empty; send `null` to clear [src]. |
| `locale` | `Locale` (/docs/ref/enum/locale) | `"en-US"` | mutable | |
| `timeZone` | `TimeZone?` (/docs/ref/enum/time-zone) | `null` | mutable | IANA name. |
| `encryptionAtRest` | `EncryptionAtRest` | docs: required; default `{"@type":"Disabled"}` [src] | mutable | |

### 1.2 Fields – `@type: "Group"`

The Group variant has `name` (required), `domainId` (required), `emailAddress` (server-set), `description`, `createdAt` (server-set), `memberTenantId`, `roles`, `quotas`, `usedDiskQuota` (server-set), `permissions`, `aliases`, `locale`, `timeZone` and `externalId`.

Differences from User:

- `roles` uses the type `Roles`, whose default is `{"@type":"Default"}`.
- There is **no `credentials` field**: groups cannot log in.
- There is **no `memberGroupIds` field**.
- Membership is stored on the members, not on the group. To list a group's members, run `x:Account/query` with filter `{"memberGroupIds": "<groupId>"}`.

### 1.3 Nested types

**Credential** (variant field `@type`):

| Variant | Fields |
|---|---|
| `Password` (PasswordCredential) | `secret` (String, required, secret): plaintext, or an existing hash recognised by prefix (`$argon2`, `$pbkdf2`, `$scrypt`, `$2`, `$6$`, `$5$`, `$sha1`, `$1`, `_`, `{SHA}`, `{SSHA}`, `{CRYPT}`, `{PLAIN}`, …). `otpAuth` (Uri?, secret): TOTP `otpauth://` URI. `expiresAt` (UTCDateTime?). `allowedIps` (Set<IpMask>). Schema-only field: `credentialId` (server-set). |
| `AppPassword` and `ApiKey` (SecondaryCredential) | `description` (String, required). `secret` (read-only, server-set, secret). `createdAt` (read-only, server-set). `expiresAt` (UTCDateTime?). `permissions` (CredentialPermissions, required). `allowedIps` (Set<IpMask>). Schema-only field: `credentialId` (server-set). |

Rules for credentials on `x:Account` [src: jmap/registry/mapping/principal.rs]:

- Only one `Password` credential is allowed. A second one fails with `invalidProperties` "Only one password credential is allowed."
- Before hashing, a plaintext `secret` is checked against the password policy (§2.2). A secret that is already a recognised hash, starting with `$` or `{`, is stored as-is and bypasses the policy.
- `AppPassword` and `ApiKey` entries **cannot be created through `x:Account`**. Attempts fail with `invalidProperties` "Secondary credentials cannot be set directly." Their secret cannot be changed either ("Cannot change app password or API credentials through this method."). Removing an entry, e.g. `"credentials/<k>": null`, revokes it.
- Accounts whose domain uses an external directory cannot get or change credentials. The error is `forbidden` "Cannot set credentials for accounts in an external directory."
- If `Authentication.passwordDefaultExpiry` is set, a new password gets `expiresAt = now + expiry`.

**CredentialPermissions:**

- `{"@type":"Inherit"}`: same permissions as the account.
- `{"@type":"Disable","permissions":{…}}`: the account's permissions minus the listed ones.
- `{"@type":"Replace","permissions":{…}}`: exactly the listed ones.

`permissions` is a `Set<Permission>`, e.g. `{"authenticate":true,"sysAccountGet":true}`.

**UserRoles:**

- `{"@type":"User"}`: expands to `Authentication.defaultUserRoleIds`.
- `{"@type":"Admin"}`: expands to `defaultAdminRoleIds`, or to `defaultTenantRoleIds` when the creator is a tenant admin [src].
- `{"@type":"Custom","roleIds":{"<roleId>":true}}`: the listed roles.

**Roles** (groups and tenants): `{"@type":"Default"}` or `{"@type":"Custom","roleIds":{…}}`.

**Permissions:** `{"@type":"Inherit"}`, `{"@type":"Merge","enabledPermissions":{…},"disabledPermissions":{…}}` or `{"@type":"Replace","enabledPermissions":{…},"disabledPermissions":{…}}`. Disabled permissions always win.

**EmailAlias:**

| Field | Type | Default |
|---|---|---|
| `enabled` | Boolean | `true` |
| `name` | EmailLocalPart | required |
| `domainId` | Id<Domain> | required |
| `description` | String? | – |

Alias addresses are globally unique: a clash with an account, list or alias address fails with `primaryKeyViolation` [src: unique composite index].

**EncryptionAtRest:**

- `{"@type":"Disabled"}`.
- `Aes128`, `Aes256`, `Aes256Gcm` (S/MIME only) or `ChaCha20Poly1305` (S/MIME only), each with EncryptionSettings: `publicKey` (Id<PublicKey>, required), `encryptOnAppend` (false), `allowSpamTraining` (false).

### 1.4 Enum `StorageQuota` (keys of `quotas`)

| Group | Values |
|---|---|
| Storage | `maxDiskQuota` (bytes) |
| Mail | `maxEmails`, `maxMailboxes`, `maxEmailSubmissions`, `maxEmailIdentities` |
| Identities and Sieve | `maxParticipantIdentities`, `maxSieveScripts`, `maxPushSubscriptions` |
| Calendar and contacts | `maxCalendars`, `maxCalendarEvents`, `maxCalendarEventNotifications`, `maxAddressBooks`, `maxContactCards` |
| Files and masked addresses | `maxFiles`, `maxFolders`, `maxMaskedAddresses` |
| Credentials and keys | `maxAppPasswords`, `maxApiKeys`, `maxPublicKeys` |

### 1.5 `x:Account/query`

| Condition | Kind [docs] | Per source |
|---|---|---|
| `text` | text | Full-text over `name`, `description` and alias local parts. |
| `name` | text | Keyword index: **exact** local-part match. |
| `domainId` | id of Domain | Exact. |
| `memberTenantId` | id of Tenant | Exact; overridden for tenant admins. |
| `memberGroupIds` | id of Account/Group | Members of that group. |
| `@type` | – (used by the WebUI as a static filter) | `"User"` or `"Group"` [src]. |
| `externalId` | – | Exact (keyword) [src]. |

- Sort: `id` (default, descending) or the indexed non-text properties (`name`, `domainId`, `externalId`, `memberTenantId`, `memberGroupIds`) [src].
- To find an account by address, filter on `{"name": "alice", "domainId": "<domainId>"}`.

### 1.6 Behaviour notes [src]

- **Destroy** revokes every ACL share the account granted to others and schedules a `DestroyAccount` Task, which purges the data asynchronously. On Enterprise, deletion waits for the `deletedAccountsRetention` period; destroying that pending task restores the account. A destroy can fail with `objectIsLinked`.
- **Enterprise licence:** creating an account fails with `forbidden` "Enterprise licensed account limit reached …" once the licensed number of accounts is reached.
- **Disabled state:** there is no `enabled` field. Disabling means taking away the `authenticate` permission, which is what SCIM `active:false` does (docs: auth/scim/mapping; src: scim/users/mod.rs `set_active`). A deactivated account keeps its mailbox and still receives mail.
- **Password set and reset by an admin** happen in the `credentials` Password entry (§1.7). `x:AccountPassword` is the self-service variant (§2).

### 1.7 Recipes (derived from source and docs; not docs examples)

```jsonc
// Create a user with password, display name, alias, quota and group membership
["x:Account/set", {"create": {"u1": {
  "@type": "User", "name": "alice", "domainId": "<domainId>",
  "description": "Alice Example",
  "credentials": {"0": {"@type": "Password", "secret": "Long-unguessable-passphrase-42"}},
  "aliases": {"0": {"name": "a.example", "domainId": "<domainId>"}},
  "quotas": {"maxDiskQuota": 5368709120},
  "memberGroupIds": {"<groupId>": true},
  "roles": {"@type": "User"}, "permissions": {"@type": "Inherit"},
  "encryptionAtRest": {"@type": "Disabled"}}}}, "c1"]
// → "created": {"u1": {"id": "<newId>"}}

// Create a group
["x:Account/set", {"create": {"g1": {"@type": "Group", "name": "sales", "domainId": "<domainId>"}}}, "c1"]

// Grant admin rights / custom roles
["x:Account/set", {"update": {"<id>": {"roles": {"@type": "Admin"}}}}, "c1"]
["x:Account/set", {"update": {"<id>": {"roles": {"@type": "Custom", "roleIds": {"<roleId>": true}}}}}, "c1"]

// Reset password
// 1) Find the key k of the Password entry.
["x:Account/get", {"ids": ["<id>"], "properties": ["credentials"]}, "c1"]
// response: "credentials": {"0": {"@type":"Password","credentialId":"…","secret":"****","expiresAt":null,"allowedIps":{}}, …}
// 2) Patch only that entry's secret. This keeps app passwords and API keys.
["x:Account/set", {"update": {"<id>": {"credentials/0/secret": "New-long-passphrase-43"}}}, "c1"]
// No Password entry yet: add one under a new key.
["x:Account/set", {"update": {"<id>": {"credentials/<nextKey>": {"@type": "Password", "secret": "…"}}}}, "c1"]
// Remove TOTP 2FA (unverified that null is accepted here; the field is a mutable Uri?):
// {"credentials/0/otpAuth": null}
// ⚠ Replacing the whole "credentials" object with a fresh {"0": {"@type":"Password",…}} drops all app passwords and API keys.

// Disable login when permissions are currently Inherit (mirrors SCIM active=false).
["x:Account/set", {"update": {"<id>": {"permissions": {"@type": "Merge", "enabledPermissions": {}, "disabledPermissions": {"authenticate": true}}}}}, "c1"]
// Re-enable: remove "authenticate" from disabledPermissions; if both sets end up empty, go back to Inherit.
["x:Account/set", {"update": {"<id>": {"permissions": {"@type": "Inherit"}}}}, "c1"]
// When permissions are already Merge or Replace, patch by pointer instead:
// {"permissions/disabledPermissions/authenticate": true}   (pointer into a variant sub-object; unverified)

// Add or remove an alias, group membership or quota (JSON pointers)
{"aliases/3": {"name": "info", "domainId": "<domainId>"}}   {"aliases/3": null}
{"memberGroupIds/<groupId>": true}                          {"memberGroupIds/<groupId>": null}
{"quotas/maxDiskQuota": 10737418240}                        {"quotas/maxDiskQuota": null}
```

### 1.8 Verbatim docs examples

The full curl command exactly as shown in the docs. **Note the URL problem in 0.1: replace `/api` with `/jmap/`.**

```
curl -X POST https://mail.example.com/api \
  -H 'Authorization: Bearer $TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
      "methodCalls": [
        [
          "x:Account/set",
          {
            "create": {
              "new1": {
                "@type": "User",
                "aliases": {},
                "credentials": {},
                "domainId": "<Domain id>",
                "encryptionAtRest": {
                  "@type": "Disabled"
                },
                "memberGroupIds": {},
                "name": "alice",
                "permissions": {
                  "@type": "Inherit"
                },
                "quotas": {},
                "roles": {
                  "@type": "User"
                }
              }
            }
          },
          "c1"
        ]
      ],
      "using": [
        "urn:ietf:params:jmap:core",
        "urn:stalwart:jmap"
      ]
    }'
```

Other docs request bodies, verbatim with whitespace compacted. The `using` array is identical in all of them and is abbreviated `…` here:

```json
{"methodCalls":[["x:Account/get",{"ids":["id1"]},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Account/set",{"update":{"id1":{"externalId":"updated value"}}},"c1"]],"using":[…]}
{"methodCalls":[["x:Account/set",{"destroy":["id1"]},"c1"]],"using":[…]}
{"methodCalls":[["x:Account/query",{"filter":{}},"c1"]],"using":[…]}
```

The docs CLI example for creating a user with a password (shows the list encoding):

```
stalwart-cli create account/user \
  --field name=alice \
  --field domainId=b \
  --field 'credentials={"0":{"@type":"Password","secret":"hunter2"}}'
```

---

## 2. AccountPassword – `x:AccountPassword` (singleton, self-service), and the password policy

| Item | Value |
|---|---|
| JMAP type | `x:AccountPassword`. **Singleton** (id `"singleton"`). |
| Methods | `x:AccountPassword/get` (`ids: ["singleton"]` or `null`) and `x:AccountPassword/set` (`update` of `singleton` only; `create` and `destroy` are rejected) |
| Permissions | `sysAccountPasswordGet`, `sysAccountPasswordUpdate` |
| WebUI | Account › Credentials › Password |
| Scope | Always the **caller's own** account [src: mapping/account.rs]. This is not the tool for an admin resetting another user's password; use §1.7 for that. |

Fields:

| Field | Type | Notes |
|---|---|---|
| `secret` | `String?` (secret) | The new password. get returns `"****"`. |
| `currentSecret` | `String?` (secret) | The current password, required to change `secret` or the OTP. |
| `otpAuth` | `OtpAuth` (required) | Sub-fields: `otpCode` (`String?`, secret): current OTP code, required for changes when 2FA is enabled. `otpUrl` (`Uri?`, secret): TOTP provisioning URI; get returns `"****"` when one is set. |

Behaviour [src]. Every refusal below is a SetError `forbidden`, except the policy check:

| Situation | Result |
|---|---|
| `currentSecret` missing | "Current secret must be provided to change the password or OTP auth." |
| Current secret wrong | "Current secret is incorrect.". The failure counts towards the auth ban. |
| 2FA enabled but no `otpCode` sent | "Current OTP code is required …" |
| Domain uses an external directory | "Operation not allowed." |
| Account has no password | "Cannot set a password or OTP auth on an account that doesn't have one." |
| New `secret` fails the policy | SetError `invalidProperties`, property `secret`. |

Verbatim docs bodies:

```json
{"methodCalls":[["x:AccountPassword/get",{"ids":["singleton"]},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:AccountPassword/set",{"update":{"singleton":{"secret":"updated value"}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

The docs example omits `currentSecret`, which per source is always required.

### 2.1 Related singleton `x:AccountSettings` (self-service)

Fields: `encryptionAtRest`, `locale`, `description`, `timeZone`. Per source an update may touch only these four fields, and only on the caller's own account. Permissions: `sysAccountSettingsGet`, `sysAccountSettingsUpdate`.

### 2.2 Password policy – `x:Authentication` singleton

Methods: `x:Authentication/get` and `x:Authentication/set` (update `singleton`). Permissions: `sysAuthenticationGet`, `sysAuthenticationUpdate`. WebUI: Settings › Authentication › General.

| Field | Type / default | Meaning |
|---|---|---|
| `directoryId` | `Id<Directory>?` | External directory used for authentication. `null` means the internal directory. |
| `defaultUserRoleIds` / `defaultGroupRoleIds` / `defaultTenantRoleIds` (enterprise) / `defaultAdminRoleIds` | `Set<Id<Role>>` | Roles behind the `User`, Group `Default`, Tenant `Default` and `Admin` role modes. |
| `passwordHashAlgorithm` | `argon2id` (default), `bcrypt`, `scrypt`, `pbkdf2` | |
| `passwordMinLength` | UnsignedInt, default `8` (1–100) | |
| `passwordMaxLength` | UnsignedInt, default `128` (1–1000) | |
| `passwordMinStrength` | `zero`, `one`, `two`, `three` (default), `four` (zxcvbn scores) | |
| `passwordDefaultExpiry` | `Duration?` | New passwords get `expiresAt = now + expiry`. |
| `maxAppPasswords` / `maxApiKeys` | `UnsignedInt?`, default `5` (min 1) | Per-account caps. Exceeding a cap gives SetError `overQuota`. |

How the policy interacts [docs: auth/authentication/password][src]:

- **Where it runs:** on every new or reset internal password. That covers `x:Account` Password `secret` on create and update, and `x:AccountPassword`. It does not apply retroactively.
- **Exemptions:** external directories (they enforce their own policy) and pre-hashed secrets.
- **Error messages** (`description`): "Password must be at least N characters long.", "Password must be at most N characters long.", "Password is too weak. <zxcvbn feedback>".
- **Applying changes:** policy changes are compiled into the core, so apply them with `ReloadSettings` (§0.8).

Verbatim docs bodies:

```json
{"methodCalls":[["x:Authentication/get",{"ids":["singleton"]},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Authentication/set",{"update":{"singleton":{"directoryId":"<Directory id>"}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 3. Domain – `x:Domain`

| Item | Value |
|---|---|
| JMAP type | `x:Domain`. Collection object; tenant-filtered. |
| Methods | `x:Domain/get`, `x:Domain/set` (create, update, destroy), `x:Domain/query` |
| Permissions | `sysDomainGet`, `sysDomainCreate`, `sysDomainUpdate`, `sysDomainDestroy`, `sysDomainQuery` |
| WebUI | Management › Domains › Domains |

### 3.1 Fields

| Field | Type | Required / default | Mutability | Notes |
|---|---|---|---|---|
| `name` | `DomainName` | **required** | mutable | Unique, and must not collide with another domain's aliases. Clashes give `primaryKeyViolation`. |
| `aliases` | `Set<DomainName>` | `{}` | mutable | Extra domain names treated as local; unique. |
| `isEnabled` | Boolean | `true` | mutable | Disable without deleting: the domain is kept but no longer accepted as local [docs]. |
| `createdAt` | UTCDateTime | – | server-set | |
| `description` | `String?` | – | mutable | |
| `logo` | `String?` (enterprise) | – | mutable | |
| `certificateManagement` | `CertificateManagement` | docs: required; default `Manual` [src] | mutable | |
| `dkimManagement` | `DkimManagement` | docs: required; **default `Automatic` with default properties** [src] | mutable | ⚠ Omitting it on create turns on automatic DKIM key generation. |
| `dnsManagement` | `DnsManagement` | docs: required; default `Manual` [src] | mutable | |
| `dnsZoneFile` | `Text` | – | server-set | **The DNS records the domain needs**; see 3.3. |
| `memberTenantId` | `Id<Tenant>?` (enterprise) | – | mutable | |
| `directoryId` | `Id<Directory>?` (enterprise) | – | mutable | `null` means the internal directory. |
| `catchAllAddress` | `EmailAddress?` | – | mutable | `null` rejects unknown recipients at SMTP time. |
| `subAddressing` | `SubAddressing` | docs: required; default `Enabled` [src] | mutable | |
| `allowRelaying` | Boolean | `false` | mutable | |
| `reportAddressUri` | `String?` | `"mailto:postmaster"` | mutable | Recipient of DMARC, TLS-RPT and CAA reports; `null` means no reports. |
| `allowScimProvisioning` | Boolean (enterprise) | `false` | mutable | |

### 3.2 Nested types

**CertificateManagement:**

- `{"@type":"Manual"}`.
- `{"@type":"Automatic","acmeProviderId":"<id>","subjectAlternativeNames":{"mta-sts":true,"autoconfig":true}}`. `acmeProviderId` is required. SANs are host labels only; the domain is appended automatically. To include the apex, give it in full. Leave the set empty to request a wildcard or the default SANs.

**DkimManagement:**

- `{"@type":"Manual"}`.
- `{"@type":"Automatic", …}` with these fields:

| Field | Default | Meaning |
|---|---|---|
| `algorithms` | `{"Dkim1Ed25519Sha256":true,"Dkim1RsaSha256":true}` | Algorithms used for new keys. |
| `selectorTemplate` | `"v{version}-{algorithm}-{date-%Y%m%d}"` | Variables: `{algorithm}` (`rsa`, `ed25519`), `{hash}` (`sha256`), `{version}` (`1`), `{date-<strftime>}`, `{epoch}`, `{random}` (8 characters). |
| `rotateAfter` | `7776000000` (90 d) | How often to rotate. Needs automatic DNS. |
| `retireAfter` | `604800000` (7 d) | How long the old key's DNS record stays after rotation. Needs automatic DNS. |
| `deleteAfter` | `2592000000` (30 d) | How long retired key material is kept. Needs automatic DNS. |

**DnsManagement:**

- `{"@type":"Manual"}`.
- `{"@type":"Automatic","dnsServerId":"<DnsServer id>","origin":null,"publishRecords":{…}}`. `dnsServerId` is required. `origin` names the zone apex if it differs from the domain. `publishRecords` defaults to `autoConfig`, `autoConfigLegacy`, `autoDiscover`, `caa`, `dkim`, `dmarc`, `mtaSts`, `mx`, `spf`, `srv` and `tlsRpt`, each `true`; at least one is required.

**SubAddressing:**

- `{"@type":"Enabled"}`, `{"@type":"Disabled"}`, or `{"@type":"Custom","customRule":<Expression>}`.
- An Expression has the form `{"match":{"0":{"if":"…","then":"…"}},"else":"…"}`. Available variables: MtaRcptVariable.

Enums:

- `DkimSignatureType`: `Dkim1Ed25519Sha256`, `Dkim1RsaSha256`, `Dkim2Ed25519Sha256`, `Dkim2RsaSha256`.
- `DnsRecordType`: `dkim`, `tlsa`, `spf`, `mx`, `dmarc`, `srv`, `mtaSts`, `tlsRpt`, `caa`, `autoConfig`, `autoConfigLegacy`, `autoDiscover`.

### 3.3 Getting the DNS records (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, autoconfig …)

- **Use the field `dnsZoneFile`.** There is no separate method or Action for this.
- `dnsZoneFile` is read-only BIND zone text. It is computed on every `x:Domain/get` that asks for it, or when `properties` is omitted [src: jmap/registry/get.rs → `build_bind_dns_records`].
- It contains the record types `Dkim`, `Tlsa`, `Spf`, `Mx`, `Dmarc`, `Srv`, `MtaSts`, `TlsRpt`, `Caa`, `AutoConfig`, `AutoConfigLegacy` and `AutoDiscover` [src].
- DKIM TXT values come from the domain's DkimSignature objects [docs].
- The WebUI's "View Zone File" is the view `x:Domain/DomainZone`, which shows exactly this field.

```json
["x:Domain/get", {"ids": ["<domainId>"], "properties": ["name", "dnsZoneFile"]}, "c1"]
```

Publishing automatically [docs: domains/dns-records]:

- Set `dnsManagement` to `Automatic` with a `DnsServer` (the provider object).
- The first save schedules a `DnsManagement` Task. The save itself is not blocked; the task's `failureReason` holds any error.
- To refresh later, create a Task `{"@type":"DnsManagement","domainId":…,"updateRecords":{…},"onSuccessRenewCertificate":false}` (§16).

Side effects of create and update [src: mapping/domain.rs]:

- When `dkimManagement` becomes `Automatic`, a `DkimManagement` task is scheduled immediately, which generates the keys.
- When `dnsManagement` becomes `Automatic`, a `DnsManagement` task is scheduled for `publishRecords`. DKIM is left out if a DKIM task was also scheduled. On create, `onSuccessRenewCertificate` is set when certificates are automatic.
- When `certificateManagement` becomes `Automatic` without DNS automation, an `AcmeRenewal` task is scheduled.
- A DNS-01 ACME provider without automatic DNS fails with `invalidProperties` "ACME provider requires automatic DNS management".
- An invalid `selectorTemplate` fails with `invalidProperties` on property `selectorTemplate`.
- The tenant quota `maxDomains` is enforced.

Destroy fails with `objectIsLinked` while Accounts, MailingLists, DkimSignatures or `SystemSettings.defaultDomainId` reference the domain.

### 3.4 `x:Domain/query`

- Conditions [docs]: `text` (text), `name` (text), `memberTenantId` (id of Tenant).
- Per source: `name` is an **exact** keyword match, `text` is full-text over `name`, `aliases` and `description`, and `aliases` is also filterable (exact).
- Sort: `name`, `aliases`, `memberTenantId` or `id`.

### 3.5 Verbatim docs bodies

```json
{"methodCalls":[["x:Domain/set",{"create":{"new1":{"aliases":{},"certificateManagement":{"@type":"Manual"},"dkimManagement":{"@type":"Automatic"},"dnsManagement":{"@type":"Manual"},"name":"example.com","subAddressing":{"@type":"Enabled"}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Domain/get",{"ids":["id1"]},"c1"]],"using":[…]}
{"methodCalls":[["x:Domain/set",{"update":{"id1":{"description":"updated value"}}},"c1"]],"using":[…]}
{"methodCalls":[["x:Domain/set",{"destroy":["id1"]},"c1"]],"using":[…]}
{"methodCalls":[["x:Domain/query",{"filter":{"text":"example"}},"c1"]],"using":[…]}
```

---

## 4. DkimSignature – `x:DkimSignature`

| Item | Value |
|---|---|
| JMAP type | `x:DkimSignature`. Multi-variant: `@type` is `Dkim1Ed25519Sha256`, `Dkim1RsaSha256`, `Dkim2Ed25519Sha256` or `Dkim2RsaSha256`. Tenant-filtered. |
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysDkimSignatureGet`, `sysDkimSignatureCreate`, `sysDkimSignatureUpdate`, `sysDkimSignatureDestroy`, `sysDkimSignatureQuery` |
| WebUI | Management › Domains › DKIM Signatures |

### 4.1 Fields

Variants `Dkim1Ed25519Sha256` and `Dkim1RsaSha256`:

| Field | Type | Required / default | Mutability |
|---|---|---|---|
| `auid` | `String?` | – | mutable |
| `canonicalization` | `relaxed/relaxed`, `simple/simple`, `relaxed/simple`, `simple/relaxed` | `"relaxed/relaxed"` | mutable |
| `expire` | `Duration?` | – | mutable |
| `headers` | `Set<String>` | `{"Date":true,"From":true,"Message-ID":true,"Subject":true,"To":true}` | mutable |
| `privateKey` | `SecretText` | **required** | mutable |
| `publicKey` | `Text` | – | server-set: PEM, derived on get [src] |
| `report` | Boolean | `true` | mutable |
| `thirdParty` | `String?` | – | mutable |
| `thirdPartyHash` | `sha256` or `sha1` (nullable) | – | mutable |
| `domainId` | `Id<Domain>` | **required** | mutable |
| `memberTenantId` | `Id<Tenant>?` (enterprise) | – | mutable |
| `selector` | String | **required** | mutable |
| `createdAt` | UTCDateTime | – | server-set |
| `nextTransitionAt` | `UTCDateTime?` | – | mutable |
| `stage` | `active`, `pending`, `retiring`, `retired` | `"active"` | mutable |

Variants `Dkim2Ed25519Sha256` and `Dkim2RsaSha256` have `flags` (`Set<Dkim2Flag>`: `donotmodify`, `donotexplode`, `feedback`), `privateKey`, `publicKey`, `domainId`, `memberTenantId`, `selector`, `createdAt`, `nextTransitionAt` and `stage`.

**SecretText:**

- `{"@type":"Text","secret":"-----BEGIN PRIVATE KEY-----\n…"}`
- `{"@type":"EnvironmentVariable","variableName":"…"}`
- `{"@type":"File","filePath":"…"}`

On get the secret comes back as `"****"` [src].

### 4.2 Key generation, algorithms, selector, rotation

- **`x:DkimSignature/set` does not generate keys.** `privateKey` must contain a valid PEM key. The server validates it by building a signer; failure gives `invalidProperties` "Failed to validate DKIM signature: …" [src: mapping/dkim.rs]. The docs suggest `openssl genrsa 2048` or `openssl genpkey -algorithm ed25519`. The tenant quota `maxDkimKeys` is enforced.
- **Server-side generation** is done by the `DkimManagement` Task for a domain with `dkimManagement: Automatic`. Creating such a domain schedules the task automatically [src: services/task_manager/dkim.rs]:
  - It creates one key per algorithm in `algorithms`: RSA keys are 2048-bit, Ed25519 keys are standard. The selector comes from `selectorTemplate`.
  - If the domain has automatic DNS with `dkim` in `publishRecords`, the key is published and becomes `active` once propagation is confirmed. `nextTransitionAt` is then set to `now + rotateAfter`. If publishing fails, the key stays `pending` and is retried after 1 minute.
  - Otherwise (manual DNS), the key is created `active` immediately and has no rotation schedule. Copy it into DNS from `dnsZoneFile`.
  - The task fails permanently with "Domain is not set to automatic DKIM management" or "No DKIM algorithms configured for domain".
- **Lifecycle** [docs: domains/dkim-rotation]: `pending` → `active` (signs; at most one active key per algorithm) → `retiring` (still published, no longer signs) → `retired` (DNS record removed; deleted after `deleteAfter`).
- **Forced rotation** [docs]: set `nextTransitionAt` on the active key to now, then create the Task `{"@type":"DkimManagement","domainId":"<id>"}`.
- **Which keys sign** [docs: mta/authentication/dkim/sign]: the `SenderAuth.dkimSignDomain` expression picks the domain, and every DkimSignature of that domain signs. Changing the signing setup needs `ReloadSettings`.

### 4.3 `x:DkimSignature/query`

- Conditions: `domainId` (id of Domain), `memberTenantId` (id of Tenant).
- Sort: `domainId`, `memberTenantId` or `id`.

### 4.4 Verbatim docs bodies

```json
{"methodCalls":[["x:DkimSignature/set",{"create":{"new1":{"@type":"Dkim1Ed25519Sha256","domainId":"<Domain id>","privateKey":{"@type":"Text","secret":"Example"},"selector":"Example"}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:DkimSignature/query",{"filter":{"domainId":"id1"}},"c1"]],"using":[…]}
{"methodCalls":[["x:DkimSignature/set",{"update":{"id1":{"auid":"updated value"}}},"c1"]],"using":[…]}
```

The docs example's `"secret":"Example"` would be rejected per source, because it is not a valid key.

---

## 5. MailingList – `x:MailingList`

| Item | Value |
|---|---|
| JMAP type | `x:MailingList`. Collection object; tenant-filtered. |
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysMailingListGet`, `sysMailingListCreate`, `sysMailingListUpdate`, `sysMailingListDestroy`, `sysMailingListQuery` |
| WebUI | Management › Directory › Mailing Lists. Docs guide: email/management/mailing-lists. |

| Field | Type | Required / default | Mutability | Notes |
|---|---|---|---|---|
| `name` | EmailLocalPart | **required** | mutable | |
| `domainId` | Id<Domain> | **required** | mutable | |
| `emailAddress` | EmailAddress | – | server-set | `name@domain` |
| `description` | `String?` | – | mutable | Must be non-empty if not null. |
| `aliases` | `List<EmailAlias>` | `{}` | mutable | EmailAlias as in §1.3. |
| `memberTenantId` | `Id<Tenant>?` | – | mutable | |
| `recipients` | `Set<EmailAddress>` | `{}` | mutable | Member addresses, internal or external, e.g. `{"bob@example.com":true}`. |

- Addresses are globally unique and clash with accounts and aliases (`primaryKeyViolation`). The tenant quota `maxMailingLists` is enforced on create [src].
- Query: `text` (full-text over `name`, `description`, alias local parts and `recipients` [src]) and `memberTenantId`. Sort: `memberTenantId` or `id`.
- Add or remove a member by patch: `{"recipients/bob@example.com": true}` or `null`. Escape `/` as `~1` and `~` as `~0` per JSON pointer rules.

Verbatim docs bodies:

```json
{"methodCalls":[["x:MailingList/set",{"create":{"new1":{"aliases":{},"domainId":"<Domain id>","name":"alice","recipients":{}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:MailingList/query",{"filter":{"text":"example"}},"c1"]],"using":[…]}
```

---

## 6. Role – `x:Role`

| Item | Value |
|---|---|
| JMAP type | `x:Role`. Collection object; tenant-filtered. |
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysRoleGet`, `sysRoleCreate`, `sysRoleUpdate`, `sysRoleDestroy`, `sysRoleQuery` |
| WebUI | Management › Directory › Roles |

| Field | Type | Required | Notes |
|---|---|---|---|
| `description` | String | **required** | Doubles as the label; there is no `name` field [docs]. |
| `memberTenantId` | `Id<Tenant>?` | – | |
| `roleIds` | `Set<Id<Role>>` | – | Roles this role extends (inherits from). |
| `enabledPermissions` | `Set<Permission>` | – | |
| `disabledPermissions` | `Set<Permission>` | – | Takes precedence over enabled permissions. |

Built-in roles:

- The docs (auth/authorization/roles) describe three built-ins, **user**, **admin** and **tenant-admin**, reached through `UserRoles` `User` and `Admin` plus a tenant role set.
- In 0.16.24 source, the first start creates four ordinary Role objects: "User", "Group", "Tenant Administrator" and "System Administrator". The Authentication defaults point at them: user → [User], group → [Group], tenant → [Tenant Administrator, User], admin → [System Administrator, User] [src].
- They are ordinary, editable objects. Look up their ids with `x:Role/query {"filter":{"description":"Administrator"}}` (full-text match).

Making a user an admin: `{"roles":{"@type":"Admin"}}` on the Account (docs CLI: `--field 'roles={"@type":"Admin"}'`), or `{"@type":"Custom","roleIds":{…}}`. Membership is stored on the Account or Tenant, never on the Role [docs].

Query and sort:

- Conditions: `description` (text, full-text) and `memberTenantId`.
- Sort: `memberTenantId` or `id`. Per source, `description` is text-indexed and therefore not sortable.

Verbatim docs bodies:

```json
{"methodCalls":[["x:Role/set",{"create":{"new1":{"description":"Example","disabledPermissions":{},"enabledPermissions":{},"roleIds":{}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Role/query",{"filter":{"description":"example"}},"c1"]],"using":[…]}
```

---

## 7. Tenant – `x:Tenant` (Enterprise)

| Item | Value |
|---|---|
| JMAP type | `x:Tenant`. Requires an Enterprise licence [docs]. |
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysTenantGet`, `sysTenantCreate`, `sysTenantUpdate`, `sysTenantDestroy`, `sysTenantQuery` |
| WebUI | Management › Directory › Tenants |

Fields:

| Field | Type / default | Notes |
|---|---|---|
| `name` | String, required | |
| `createdAt` | server-set | |
| `logo` | `String?` | |
| `roles` | `Roles` | `Default` or `Custom{roleIds}` |
| `permissions` | `Permissions` | The ceiling on what the tenant's principals can be granted. |
| `quotas` | `Map<TenantStorageQuota, UnsignedInt>` | Keys below. |
| `usedDiskQuota` | server-set | |

`TenantStorageQuota` keys: `maxAccounts`, `maxGroups`, `maxDomains`, `maxMailingLists`, `maxRoles`, `maxOauthClients`, `maxDkimKeys`, `maxDnsServers`, `maxDirectories`, `maxAcmeProviders`, `maxDiskQuota`.

- Query: `text` (full-text over `name`). Sort: `id`.
- Objects reference a tenant through `memberTenantId`. Objects of a tenant may only reference objects in the same tenant; violations give `invalidForeignKey` [docs: cli/apply].

Verbatim docs body:

```json
{"methodCalls":[["x:Tenant/set",{"create":{"new1":{"name":"Example","permissions":{"@type":"Inherit"},"quotas":{},"roles":{"@type":"Default"}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 8. ApiKey and AppPassword – `x:ApiKey`, `x:AppPassword`

The two pages are identical apart from the names [docs].

| Item | ApiKey | AppPassword |
|---|---|---|
| Methods | get, set (create, update, destroy), query | same |
| Permissions | `sysApiKeyGet`, `sysApiKeyCreate`, `sysApiKeyUpdate`, `sysApiKeyDestroy`, `sysApiKeyQuery` | `sysAppPassword…` (same five) |
| WebUI | Account › Credentials › API Keys | Account › Credentials › App Passwords |
| Used for | Management API only (Bearer) | Mail protocols (IMAP, SMTP …) for clients without 2FA support |
| Secret format [src] | `API_<base64url>` | `app_<base32>` |

### 8.1 Fields

| Field | Type | Required / default | Mutability |
|---|---|---|---|
| `description` | String | **required** | mutable |
| `secret` | String (secret) | – | read-only, server-set |
| `createdAt` | UTCDateTime | – | read-only, server-set |
| `expiresAt` | `UTCDateTime?` | `null` (never expires) | mutable |
| `permissions` | `CredentialPermissions` | docs: required; default `Inherit` [src] | mutable |
| `allowedIps` | `Set<IpMask>` | `{}` (any IP) | mutable |

### 8.2 `CredentialPermissions` – exact JSON shapes

```json
{"@type": "Inherit"}
{"@type": "Disable", "permissions": {"sysAccountDestroy": true, "sysDomainDestroy": true}}
{"@type": "Replace", "permissions": {"authenticate": true, "sysAccountGet": true, "sysAccountQuery": true}}
```

- `Inherit`: same permissions as the owning account.
- `Disable`: the account's permissions minus the listed ones.
- `Replace`: only the listed ones, regardless of the account's own permissions [docs].
- Include `authenticate` in a `Replace` list; the SCIM guide's key includes it.
- The caller can grant only permissions it holds itself [src].

### 8.3 `IpMask` format [src: registry/types/ipmask.rs]

- A single IPv4 or IPv6 address, e.g. `"203.0.113.7"`, or CIDR notation `"addr/len"`, e.g. `"203.0.113.0/24"`.
- The prefix length must be 8–32 for IPv4 and 8–128 for IPv6. Anything else is rejected with "Invalid IP address …".
- On the wire it is a Set: `"allowedIps": {"203.0.113.0/24": true}`.

### 8.4 Semantics [src: mapping/account.rs]

- **Ownership:** the credential is attached to the account behind `accountId`, i.e. the authenticated caller. There is no owner field; per the docs, "a separate `accountId` is neither supplied nor accepted".
- **Consequence for admins:** API keys and app passwords cannot be created for other users through this object. The docs say admins can view and revoke them but "cannot create new ones on a user's behalf". Revoke another user's key via `x:Account` by setting `"credentials/<k>": null`. The only route to creating one for another user would be impersonation (`impersonate` permission, login `target%admin`); this is unverified for the management API.
- **The secret is returned exactly once,** in the create response: `"created": {"new1": {"id": "<credentialId>", "secret": "API_…"}}`. It is stored hashed and cannot be recovered; get afterwards returns `"****"` [docs][src].
- **Caps:** `Authentication.maxApiKeys` / `maxAppPasswords` (default 5) and the per-account quotas `maxApiKeys` / `maxAppPasswords`. Exceeding them gives SetError `overQuota` "You have exceeded your quota of N API keys." [src].
- **Updates:** `description`, `expiresAt`, `permissions` and `allowedIps` can be updated. Changing `secret` gives `forbidden`.
- **Destroy** removes the credential. Ids are the credential ids inside the account.
- **Query:**
  - Only `expiresAt` (date; supports the `Is…` operators). Credentials without `expiresAt` never match an `expiresAt` filter.
  - Sort: `expiresAt` or `id`.
  - The docs example filters with an exact `expiresAt`.

### 8.5 Verbatim docs bodies

```json
{"methodCalls":[["x:ApiKey/set",{"create":{"new1":{"allowedIps":{},"description":"Example","permissions":{"@type":"Inherit"}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:ApiKey/query",{"filter":{"expiresAt":"2026-01-01T00:00:00Z"}},"c1"]],"using":[…]}
{"methodCalls":[["x:AppPassword/set",{"create":{"new1":{"allowedIps":{},"description":"Example","permissions":{"@type":"Inherit"}}}},"c1"]],"using":[…]}
```

The docs SCIM key example (auth/scim/configuration), verbatim:

```json
{
  "description": "SCIM provisioning (corporate IdP)",
  "permissions": {
    "@type": "Replace",
    "permissions": {
      "authenticate": true,
      "scimAccess": true,
      "sysAccountGet": true,
      "sysAccountCreate": true,
      "sysAccountUpdate": true,
      "sysAccountDestroy": true
    }
  },
  "allowedIps": {
    "203.0.113.0/24": true
  }
}
```

---

## 9. AllowedIp, BlockedIp and Security

### 9.1 `x:AllowedIp` and `x:BlockedIp`

| Item | AllowedIp | BlockedIp |
|---|---|---|
| Methods | get, set (create, update, destroy), query | same |
| Permissions | `sysAllowedIpGet`, `sysAllowedIpCreate`, `sysAllowedIpUpdate`, `sysAllowedIpDestroy`, `sysAllowedIpQuery` | `sysBlockedIp…` (same five) |
| WebUI | Settings › Security › Allowed IPs | Settings › Security › Blocked IPs |

| Field | AllowedIp | BlockedIp |
|---|---|---|
| `address` | `IpMask`, read-only (immutable; set it on create, it is unique). Required in practice: the default `0.0.0.0` is invalid [src]. | same |
| `reason` | `String?` (non-empty if set) | `BlockReason`, default `"manual"`: one of `rcptToFailure`, `authFailure`, `loitering`, `portScanning`, `manual`, `other` |
| `createdAt` | UTCDateTime, read-only (defaults to now) | UTCDateTime, server-set |
| `expiresAt` | `UTCDateTime?` (`null` = permanent) | `UTCDateTime?` (`null` = permanent) |

Query:

- Condition `address`. Per source it is a unique IpMask index, so the value must parse as an IP or CIDR (exact key); the docs example `"address":"example"` would be rejected.
- Sort: `address` or `id`.

Reloading:

- Create and destroy go to the database. Per source, the running block list is rebuilt only by `x:Action` `ReloadBlockedIps`, and the allow list only by `ReloadSettings` (§0.8).
- Expired entries are deleted when lists are reloaded.
- Bans created by the server itself apply instantly and are written as BlockedIp records with `reason` set to e.g. `authFailure` and `expiresAt` derived from the ban period [docs: server/auto-ban].

**Do allowed IPs bypass bans and rate limits?** Yes, per source (common/network/security.rs, common/auth/rate_limit.rs, spam-filter/analysis/ip.rs). An allowed IP:

1. is never considered blocked, even if a BlockedIp entry matches it;
2. is never auto-banned: the auth, rcpt/abuse, loiter and scan trackers and the `scanBanPaths` checks are skipped;
3. is exempt from the HTTP authenticated and anonymous rate limits;
4. is excluded from spam-filter IP checks on `Received` headers.

Further notes:

- Loopback addresses and `SystemSettings.proxyTrustedNetworks` are always implicitly allowed.
- The per-user concurrency limit (`maxConcurrentRequests`) still applies. The `unlimitedRequests` permission is the per-principal bypass.
- Whether SMTP throttles (MtaInboundThrottle) are skipped is unverified.
- The docs themselves say nothing about these semantics.

Verbatim docs bodies:

```json
{"methodCalls":[["x:AllowedIp/set",{"create":{"new1":{}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:AllowedIp/query",{"filter":{"address":"example"}},"c1"]],"using":[…]}
{"methodCalls":[["x:BlockedIp/set",{"update":{"id1":{"reason":"manual"}}},"c1"]],"using":[…]}
```

The docs create example `{}` lacks `address`. A useful body is `{"address":"203.0.113.0/24","reason":"office","expiresAt":null}`.

### 9.2 `x:Security` (singleton) – auto-ban rules

| Item | Value |
|---|---|
| Methods | `x:Security/get` (`singleton`), `x:Security/set` (update `singleton` only) |
| Permissions | `sysSecurityGet`, `sysSecurityUpdate` |
| WebUI | Settings › Security › Settings |

| Field | Type / default | Meaning |
|---|---|---|
| `abuseBanRate` | `Rate?`, `{"count":35,"period":86400000}` | Relay or failed RCPT TO attempts before a ban. |
| `abuseBanPeriod` | `Duration?` | Ban length. `null` means the ban stays until removed manually [docs]. |
| `authBanRate` | `Rate?`, `{"count":100,"period":86400000}` | Failed logins across all services. Keyed on IP **and** login name. |
| `authBanPeriod` | `Duration?` | |
| `loiterBanRate` | `Rate?`, `{"count":150,"period":86400000}` | Idle or loitering disconnects. |
| `loiterBanPeriod` | `Duration?` | |
| `scanBanPaths` | `Set<String>` (glob patterns), default `{"*../*","*.asp*","*.cgi*","*.php*","*/..*","*/cgi-bin*","*/php*","*/wp-*","*drupal*","*joomla*","*wordpress*","*xmlrpc*"}` | HTTP paths that ban on first hit. |
| `scanBanRate` | `Rate?`, `{"count":30,"period":86400000}` | Port or URL scanning. |
| `scanBanPeriod` | `Duration?` | |

`Rate` is `{"count": UnsignedInt 1..1000000, "period": Duration ms ≥1}`. Per source, a `null` rate disables that ban category. Changes need `ReloadSettings`.

Verbatim docs body:

```json
{"methodCalls":[["x:Security/set",{"update":{"singleton":{"abuseBanRate":{"count":35,"period":86400000}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 10. QueuedMessage – `x:QueuedMessage`

| Item | Value |
|---|---|
| Methods | get, set (update and destroy; **create is always refused**), query |
| Permissions | `sysQueuedMessageGet`, `sysQueuedMessageCreate`, `sysQueuedMessageUpdate`, `sysQueuedMessageDestroy`, `sysQueuedMessageQuery` |
| WebUI | Management › Emails › Queued |

### 10.1 Fields [docs]

| Field | Type | Mutability | Notes |
|---|---|---|---|
| `createdAt` | UTCDateTime | server-set | When the message was received and queued. |
| `nextRetry` | `UTCDateTime?` | **mutable** | Next delivery attempt. Writing it reschedules all recipients that have not permanently failed [src]. |
| `nextNotify` | `UTCDateTime?` | server-set | Next DSN notification. |
| `blobId` | BlobId | server-set | Raw message. Download via `GET /jmap/download/{accountId}/{blobId}/{name}`; per source this needs the `fetchAnyBlob` permission. |
| `returnPath` | String | server-set | MAIL FROM; `"<>"` for null senders. |
| `recipients` | `Map<EmailAddress, QueuedRecipient>` | mutable | Keyed by recipient address. |
| `receivedFromIp` | IpAddr | server-set | |
| `receivedViaPort` | UnsignedInt | server-set | |
| `flags` | `Set<MessageFlag>` | server-set | Values: `authenticated`, `unauthenticated`, `unauthenticatedDmarc`, `dsn`, `report`, `autogenerated`. |
| `envId` | `String?` | mutable | SMTP ENVID. |
| `priority` | Integer, default 0 (−100..100) | mutable | Lower value means higher priority. |
| `size` | UnsignedInt | server-set | Bytes. |

**QueuedRecipient** (the per-recipient status):

| Field | Type | Mutability |
|---|---|---|
| `retryCount` | UnsignedInt | mutable |
| `retryDue` | UTCDateTime | mutable |
| `notifyCount` | UnsignedInt | mutable |
| `notifyDue` | UTCDateTime | mutable |
| `expires` | `{"@type":"Ttl","expiresAt":…}` or `{"@type":"Attempts","expiresAttempts":N}` | mutable |
| `queueName` | String ≤ 8 characters | server-set |
| `status` | `RecipientStatus` | mutable |
| `flags` | `Set<RecipientFlag>`: `dsnSent`, `spamPayload` | server-set |
| `orcpt` | `String?` | mutable |

**RecipientStatus:**

- `{"@type":"Scheduled"}`.
- `{"@type":"Completed", …ServerResponse}`, where ServerResponse has `responseHostname`, `responseCode`, `responseEnhanced` and `responseMessage`.
- `{"@type":"TemporaryFailure", …DeliveryError}` or `{"@type":"PermanentFailure", …DeliveryError}`.
- DeliveryError has `errorType` (required), `errorMessage`, `errorCommand`, `responseHostname`, `responseCode`, `responseEnhanced` and `responseMessage`.
- `errorType` is one of `dnsError`, `unexpectedResponse`, `connectionError`, `tlsError`, `daneError`, `mtaStsError`, `rateLimited`, `concurrencyLimited`, `io`.

### 10.2 `x:QueuedMessage/query` [docs; semantics per source]

| Condition | Kind | Per source |
|---|---|---|
| `text` | text | Substring of the return path **or** any recipient address. |
| `to` | text | Substring of any recipient address. |
| `returnPath` | text | Substring of the return path. |
| `queueName` | text | Exact virtual-queue name. |
| `due` | date | Next delivery event. Supports `dueIsGreaterThan`, `dueIsGreaterThanOrEqual`, `dueIsLessThan` and `dueIsLessThanOrEqual`. |

- **Sort:** only by `due`; any other property returns `unsupportedSort` "Only sorting by 'due' is supported for queued messages". The default is **descending**; use `[{"property":"due","isAscending":true}]` to get the next due message first.
- **Paging:** `anchor`, `position` and `limit` work.
- **get without ids** returns up to `maxObjectsInGet` queued messages.
- **Tenant admins** only see messages whose return-path domain belongs to their tenant.

### 10.3 Retry now, reschedule, cancel, delete [src: mapping/queued_message.rs + WebUI list actions in schema]

| Goal | Request |
|---|---|
| **Retry now** (the WebUI "Retry Now" and "Retry All") | `["x:QueuedMessage/set", {"update": {"<id>": {"nextRetry": "2000-01-01T00:00:00Z"}}}, "c1"]`. Sets `retryDue` for every recipient that has not permanently failed, and wakes the queue. |
| Reschedule (whole message) | `{"update": {"<id>": {"nextRetry": "2026-10-03T08:00:00Z"}}}` |
| Reschedule one recipient | `{"update": {"<id>": {"recipients/bob@example.org/retryDue": "2026-10-03T08:00:00Z"}}}` |
| Re-queue a permanently failed recipient | `{"update": {"<id>": {"recipients/bob@example.org/status": {"@type": "Scheduled"}}}}` |
| Cancel one recipient | `{"update": {"<id>": {"recipients/bob@example.org": null}}}`. The recipient gets PermanentFailure "Delivery canceled.". The message is removed once no recipient is pending. |
| **Cancel or delete the whole message** (WebUI "Cancel Delivery" and "Cancel All") | `["x:QueuedMessage/set", {"destroy": ["<id>"]}, "c1"]` |
| Change priority or ENVID | `{"update": {"<id>": {"priority": -10}}}` |
| Pause or resume the whole queue | `x:Action` `PauseMtaQueue` / `ResumeMtaQueue` (§15) |
| Delivery history of a message (Enterprise) | `x:Trace/query` with `{"event":"delivery.attempt-start","queueId":"<queuedMessageId>"}`. This is the WebUI item action "Delivery History" (view `x:Trace/OutboundDelivery`). |

Errors:

- Create always fails with `forbidden` "Queued messages cannot be created".
- An unknown recipient key gives `invalidProperties` "Recipient '<addr>' does not exist".
- A failed write gives `forbidden` "Queue update operation failed" or "Queue delete operation failed".

Verbatim docs bodies:

```json
{"methodCalls":[["x:QueuedMessage/query",{"filter":{"text":"example"}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:QueuedMessage/set",{"update":{"id1":{"envId":"updated value"}}},"c1"]],"using":[…]}
{"methodCalls":[["x:QueuedMessage/set",{"destroy":["id1"]},"c1"]],"using":[…]}
```

The docs create example (`{"recipients":{}}`) is refused by the server.

Related: the docs MTA guide (mta/management) only says that administrators "can list, inspect, requeue, and cancel queued messages through this object"; it has no request examples. Live delivery troubleshooting is **not** a JMAP Action; it is the SSE endpoint `GET /api/live/delivery/{domain-or-address}?timeout=30` (permission `liveDeliveryTest`). Frames have the form `event: event\ndata: [{"type":"mxLookupStart","domain":"…"}]`. Stage types include `mxLookupStart/Success/Error`, `mtaStsFetch*`, `tlsRptLookup*`, `deliveryAttemptStart`, `tlsaLookup*`, `ipLookup*`, `connectionStart/Success/Error`, `readGreeting*`, `ehlo*`, `startTls*`, `daneVerify*`, `mailFrom*`, `rcptTo*`, `quit*`, and the final `completed` [docs: development/api][src: http/api/diagnose.rs].

---

## 11. MtaRoute – `x:MtaRoute` (smarthost / relay)

| Item | Value |
|---|---|
| JMAP type | `x:MtaRoute`. Multi-variant: `@type` is `Mx`, `Relay` or `Local`. |
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysMtaRouteGet`, `sysMtaRouteCreate`, `sysMtaRouteUpdate`, `sysMtaRouteDestroy`, `sysMtaRouteQuery` |
| WebUI | Settings › MTA › Outbound › Routes |

Fields by variant:

- **All variants:** `name` (String, read-only/immutable, unique; the identifier that expressions refer to) and `description` (`String?`).
- **`Mx`:** `ipLookupStrategy` (`v4ThenV6` default, `v6ThenV4`, `v4Only`, `v6Only`), `maxMultihomed` (2, min 1), `maxMxHosts` (5, min 1).
- **`Relay`:**

| Field | Type / default | Notes |
|---|---|---|
| `address` | String, required | Hostname or IP. |
| `port` | 25 | 1–65535 |
| `protocol` | `smtp` (default) or `lmtp` | |
| `implicitTls` | false | |
| `allowInvalidCerts` | false | |
| `authUsername` | `String?` | |
| `authSecret` | `SecretKeyOptional`, required | `{"@type":"None"}`, `{"@type":"Value","secret":"…"}`, `{"@type":"EnvironmentVariable","variableName":"…"}` or `{"@type":"File","filePath":"…"}` |

- **`Local`:** no additional fields.

Selecting a route:

- Defining a route does nothing on its own. It is selected per recipient by the `route` expression on the singleton `x:MtaOutboundStrategy`, whose default is `{"else":"'mx'"}`. Example: `{"route":{"match":{"0":{"if":"is_local_domain(rcpt_domain)","then":"'local'"}},"else":"'relay'"}}` [docs: mta/outbound/routing, strategy].
- Afterwards run `ReloadSettings`.

Query and sort:

- Condition `name` (exact, unique). Per the docs, filtering on `@type` is **rejected** for MtaRoute (cli/apply).
- Sort: `name` or `id`.

Verbatim docs bodies:

```json
{"methodCalls":[["x:MtaRoute/set",{"create":{"new1":{"@type":"Mx"}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:MtaRoute/query",{"filter":{"name":"example"}},"c1"]],"using":[…]}
```

Docs smarthost example (routing page):

```json
{"@type": "Relay", "name": "relay", "address": "relay.example.org", "port": 25, "protocol": "smtp",
 "implicitTls": false, "allowInvalidCerts": false, "authSecret": {"@type": "None"}}
```

---

## 12. DmarcExternalReport and TlsExternalReport

| Item | DmarcExternalReport | TlsExternalReport |
|---|---|---|
| JMAP type | `x:DmarcExternalReport` (tenant-filtered) | `x:TlsExternalReport` (tenant-filtered) |
| Methods | get, query; `set` **destroy only**. Create returns `forbidden` "Reports cannot be created"; update returns `forbidden` "External reports cannot be updated" [src]. | same |
| Permissions | `sysDmarcExternalReport…` (Get/Create/Update/Destroy/Query) | `sysTlsExternalReport…` |
| WebUI | Management › Reports › Inbox › DMARC | Management › Reports › Inbox › TLS |

Common top-level fields (all immutable in practice):

| Field | Type |
|---|---|
| `report` | `DmarcReport` or `TlsReport` (required) |
| `from` | EmailAddress |
| `subject` | String |
| `to` | `Set<EmailAddress>` |
| `receivedAt` | UTCDateTime |
| `expiresAt` | UTCDateTime. Per source this is `receivedAt` + the configured retention, so it tracks the received date. |
| `memberTenantId` | `Id<Tenant>?` (enterprise) |

**DmarcReport fields:**

| Group | Fields |
|---|---|
| Report metadata | `version` (1.0), `orgName`, `email`, `extraContactInfo`, `reportId`, `dateRangeBegin`, `dateRangeEnd`, `errors` (Set), `generator` |
| Policy | `policyDomain`, `policyVersion`, `policyAdkim` / `policyAspf` (`relaxed`, `strict`, `unspecified`), `policyDisposition` / `policySubdomainDisposition` / `policyNp` (`none`, `quarantine`, `reject`, `unspecified`), `policyTestingMode`, `policyFailureReportingOptions` (Set of `all`, `any`, `dkimFailure`, `spfFailure`), `policyDiscoveryMethod` (`psl`, `treewalk`, `unspecified`) |
| Content | `records` (List<DmarcReportRecord>), `extensions` |

**DmarcReportRecord fields:**

| Field | Type / values |
|---|---|
| `sourceIp` | IpAddr |
| `count` | UnsignedInt |
| `evaluatedDisposition` | `none`, `pass`, `quarantine`, `reject`, `unspecified` |
| `evaluatedDkim` / `evaluatedSpf` | `pass`, `fail`, `unspecified` |
| `policyOverrideReasons` | List of `{overrideType: Forwarded \| SampledOut \| TrustedForwarder \| MailingList \| LocalPolicy \| Other \| PolicyTestMode, comment}` |
| `envelopeTo`, `envelopeFrom`, `headerFrom` | String |
| `dkimResults` | List of `{domain, selector, result: none \| pass \| fail \| policy \| neutral \| tempError \| permError, humanResult}` |
| `spfResults` | List of `{domain, scope: helo \| mailFrom \| unspecified, result: none \| neutral \| pass \| fail \| softFail \| tempError \| permError, humanResult}` |
| `extensions` | List |

**TlsReport fields:** `organizationName`, `contactInfo`, `reportId`, `dateRangeStart`, `dateRangeEnd` and `policies` (List of TlsReportPolicy).

| TlsReportPolicy field | Type / values |
|---|---|
| `policyType` | `tlsa`, `sts`, `noPolicyFound`, `other` |
| `policyStrings` | Set |
| `policyDomain` | DomainName |
| `mxHosts` | Set |
| `totalSuccessfulSessions`, `totalFailedSessions` | UnsignedInt |
| `failureDetails` | List of `{resultType, sendingMtaIp, receivingMxHostname, receivingMxHelo, receivingIp, failedSessionCount, additionalInformation, failureReasonCode}` |

`resultType` is one of `startTlsNotSupported`, `certificateHostMismatch`, `certificateExpired`, `certificateNotTrusted`, `validationFailure`, `tlsaInvalid`, `dnssecInvalid`, `daneRequired`, `stsPolicyFetchError`, `stsPolicyInvalid`, `stsWebpkiInvalid`, `other`.

Query filters, by date and domain:

| Condition | Docs (DMARC) | Docs (TLS) | Per source (both external types) |
|---|---|---|---|
| `domain` | text | – | **Not accepted for external reports** (it is only used for internal reports) → `unsupportedFilter`. Unverified at runtime, but the code path is unambiguous. |
| `text` | – | – | Accepted. Full-text over the policy domain, reporter email, envelope and header domains, DKIM and SPF domains, and the sender. **Use this for domain filtering.** |
| `totalFailedSessions`, `totalSuccessfulSessions` | integer | – | Accepted, with `Is…` operators. For DMARC: counts of records with and without a `pass` disposition. |
| `expiresAt` | date | – | Accepted, with `Is…` operators. The only date filter; it works as a proxy for the received date. |
| `memberTenantId` | id | – | Accepted (system admins only). |

- Sort: `id` (default, descending) or `expiresAt`.
- There is no filter on `dateRangeBegin` or `dateRangeEnd`. Filter those client-side after get.
- With no filter, all reports are returned (via `expiresAt > 0`).

Verbatim docs bodies:

```json
{"methodCalls":[["x:DmarcExternalReport/query",{"filter":{"domain":"example"}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:TlsExternalReport/query",{"filter":{}},"c1"]],"using":[…]}
{"methodCalls":[["x:DmarcExternalReport/get",{"ids":["id1"]},"c1"]],"using":[…]}
{"methodCalls":[["x:DmarcExternalReport/set",{"destroy":["id1"]},"c1"]],"using":[…]}
```

Related objects:

- `x:DmarcInternalReport` and `x:TlsInternalReport` hold outbound reports waiting to be sent. Their only updatable field is `deliverAt`, which must be in the future. They support the `domain` filter and sorting by `domain`.
- `x:ArfExternalReport` holds received abuse (ARF) feedback reports.

---

## 13. Log (`x:Log`) and Trace (`x:Trace`, Enterprise)

### 13.1 `x:Log` – server log file entries

| Item | Value |
|---|---|
| Methods | `x:Log/get` and `x:Log/query`. **`x:Log/set` always returns `forbidden`** ("Telemetry objects cannot be created / modified / deleted"), although the docs list create, update and destroy examples [src]. |
| Permissions | `sysLogGet`, `sysLogQuery` (the docs also list Create, Update and Destroy). |
| WebUI | Management › Observability › Logs |
| Prerequisite | A `Tracer` of `@type: "Log"` (file output: `path`, `prefix`, `rotate`, `level` …). Without one, the server answers `invalidArguments` "No log tracers configured on the server" [src]. Entries are read from those files. |

Fields:

| Field | Type |
|---|---|
| `timestamp` | UTCDateTime |
| `level` | `error`, `warn`, `info`, `debug`, `trace` |
| `event` | Event id, e.g. `auth.failed` (/docs/ref/events) |
| `details` | Text |

How to query, per source (mapping/log.rs):

- **Filter:** only `text`, a **case-sensitive substring match on the raw log line**. That line holds the timestamp, the level as written in the file (likely upper-case, e.g. `ERROR`; unverified), the event description, `(<event-id>)` and the details. If the tracer writes ANSI colour codes (`ansi: true` is the default), matches can fail where codes sit inside the text; use `ansi: false` for reliable filtering.
- **No server-side filter by time, level or event.**
  - The docs CLI page shows `stalwart-cli query log --where level=error`; per source this would return `unsupportedFilter`.
  - Emulate level or event filters with `text`, e.g. `"(auth.failed)"` or `" ERROR "`; this is unverified.
  - For time windows, page until the timestamps fall outside the window.
- **Order:** newest first, since files are read in reverse. Only `sort` by `id` is allowed; anything else gives `unsupportedSort` "Only sorting by 'id' is supported for logs".
- **Pagination by anchor only:**
  - `position` must be 0, otherwise `invalidArguments` "Pagination is only possible using anchors for logs".
  - To page, pass the last id you received as `anchor`. Results start **after** that id; `anchorOffset` is ignored.
  - `limit` is capped at `queryMaxResults`. No `total` is returned.
  - Ids are opaque. They encode file number and byte offset, so they are not stable across log rotation.
- **get:** `x:Log/get {"ids": [...]}` with ids from the query. `ids: null` returns the newest `maxObjectsInGet` entries.

```json
[["x:Log/query", {"filter": {"text": "(auth.failed)"}, "limit": 100}, "q"],
 ["x:Log/get", {"#ids": {"resultOf": "q", "name": "x:Log/query", "path": "/ids"}}, "g"]]
```

Verbatim docs bodies:

```json
{"methodCalls":[["x:Log/query",{"filter":{"text":"example"}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Log/get",{"ids":["id1"]},"c1"]],"using":[…]}
```

### 13.2 `x:Trace` (Enterprise) – stored delivery traces

| Item | Value |
|---|---|
| Methods | get, query. **set is forbidden** (telemetry) [src]. |
| Permissions | `sysTraceGet`, `sysTraceQuery` |
| WebUI | Management › Emails › History › Inbound Delivery / Outbound Delivery |
| Edition | Enterprise only. Otherwise `forbidden` "This feature is only available in the Enterprise edition …" [src]. |

Fields:

| Field | Type |
|---|---|
| `events` | `List<TraceEvent>`, each `{event, timestamp, keyValues: List<{key, value: TraceValue}>}` |
| `timestamp`, `from`, `to`, `size` | server-set |

`TraceValue` is one of `String`, `UnsignedInt`, `Integer`, `Boolean`, `Float`, `UTCDateTime`, `Duration`, `IpAddr`, `List`, `Event` or `Null`, each carrying a `value` field.

Query:

| Condition | Docs | Per source |
|---|---|---|
| `text` | text | Keyword search; whitespace-separated terms, quoted phrases supported. |
| `timestamp` | date | Supports `Is…` operators. |
| `queueId` | text | A queued message id. |
| `event` | – | Event id. The WebUI views use `"delivery.attempt-start"` (outbound) and `"smtp.connection-start"` (inbound). |

- Without a `text`, `queueId` or `timestamp` filter, results are limited to the **last 24 h**.
- Sort: `id` or `timestamp`.
- Live tracing is the SSE endpoint `/api/live/tracing` (Enterprise, `liveTracing`).

Verbatim docs body:

```json
{"methodCalls":[["x:Trace/query",{"filter":{}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 14. Metric – `x:Metric`

| Item | Value |
|---|---|
| Kind | Stored metric data points. The docs index does not mark it Enterprise; per source, `assert_enterprise_object` rejects Metric on non-Enterprise servers (same as Trace, MaskedEmail and ArchivedItem). |
| Methods | get, query. **set is forbidden** [src]. |
| Permissions | `sysMetricGet`, `sysMetricQuery` |
| Variants | `Counter` {`count`, `metric`, `timestamp`}, `Gauge` {`count`, `metric`, `timestamp`}, `Histogram` {`count`, `sum`, `metric`, `timestamp`} |

- `metric` is a MetricType id of the form `<subsystem>.<name>`, e.g. `acme.order-completed` (/docs/ref/metrics).
- The docs list no filters. Per source the filters are `timestamp` (with `Is…` operators) and `metric`, whose **value must be a JSON array** of metric ids, e.g. `{"metric":["delivery.total-time"]}` (illustrative id).
- Paging works by anchor.
- Collection and export are configured on the singleton `x:Metrics` (OpenTelemetry, Prometheus). Live metrics are the SSE endpoint `/api/live/metrics` (Enterprise).

Verbatim docs body:

```json
{"methodCalls":[["x:Metric/query",{"filter":{}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 15. Action – `x:Action` (on-demand operations)

| Item | Value |
|---|---|
| JMAP type | `x:Action`. Multi-variant. |
| How to invoke | `x:Action/set` with `create` and the variant in `@type`. The action **runs synchronously within the call** and its result is returned in `created.<creationId>` [src: mapping/action.rs]. |
| Permissions | `sysActionCreate`, plus a per-variant permission (below). A missing per-variant permission gives SetError `forbidden` "Insufficient permissions to perform action of type X". |
| get / query / update / destroy | Per source: `x:Action/get` always returns `notFound` (actions are **not stored**); `x:Action/query` returns `invalidArguments` "Actions cannot be queried"; update and destroy give `forbidden`. The docs claim results "can be retrieved afterwards with `x:Action/get`"; per source they cannot, so capture the result from the create response. |
| WebUI | Management › Actions |

| `@type` | Input fields (required unless noted) | Per-variant permission | Result in `created.<cid>` |
|---|---|---|---|
| `ReloadSettings` | – | `actionReloadSettings` | `{"id": "<opaque>"}`. On configuration errors: `notCreated` with `validationFailed` (`description` and `objectId` of the bad object). |
| `ReloadTlsCertificates` | – | `actionReloadTlsCertificates` | same |
| `ReloadLookupStores` | – | `actionReloadLookupStores` | same |
| `ReloadBlockedIps` | – | `actionReloadBlockedIps` | same |
| `UpdateApps` | – | `actionUpdateApps` | same (updates the hosted web apps, e.g. the WebUI) |
| `InvalidateCaches` | – | `actionInvalidateCaches` | `{"id": …}` (cluster-wide) |
| `InvalidateNegativeCaches` | – | `actionInvalidateNegativeCaches` | `{"id": …}` |
| `PauseMtaQueue` | – | `actionPauseMtaQueue` | `{"id": …}` (stops outbound delivery attempts) |
| `ResumeMtaQueue` | – | `actionResumeMtaQueue` | `{"id": …}` |
| `TroubleshootDmarc` | `remoteIp` (IpAddr), `ehloDomain`, `mailFrom` (EmailAddress), `spfEhloDomain`, `spfMailFromDomain`; optional `to` (Set<EmailAddress>, for DKIM2), `message` (Text?, raw message, needed for DKIM and ARC) | `actionTroubleshootDmarc` | Object **without `id`**, containing `spfEhloDomain`, `spfEhloResult`, `spfMailFromDomain`, `spfMailFromResult`, `ipRevResult`, `ipRevPtr` (Set), `dkimResults` (List), `dkimPass`, `dkim2Result`, `dkim2Pass`, `arcResult`, `dmarcResult`, `dmarcPass`, `dmarcPolicy` (`none`, `quarantine`, `reject`, `unspecified`), `elapsed` (ms). If the message cannot be parsed: `invalidProperties` "Failed to parse the message for DMARC troubleshooting". |
| `ClassifySpam` | `message` (Text, raw RFC 5322), `remoteIp`, `ehloDomain`, `envFrom`; optional `authenticatedAs` (String?), `isTls` (default true), `envFromParameters` (SpamClassifyParameters?), `envRcptTo` (Set<EmailAddress>) | `actionClassifySpam` | Object **without `id`**: `{"score": Float, "tags": {"<TAG>": {"score": Float, "disposition": "score\|reject\|discard"}}, "result": "spam\|ham\|reject\|discard"}`. If the message cannot be parsed: `invalidProperties` "Failed to parse the message for spam classification". |

Value types used above:

- `DmarcTroubleshootAuthResult` is `{"@type":"Pass"}`, `{"@type":"None"}`, or `{"@type":"Fail"|"SoftFail"|"TempError"|"PermError"|"Neutral","details":"…"}`.
- `SpamClassifyParameters` is one of `bit7`, `bit8Mime`, `binaryMime`, `smtpUtf8`. The docs label cell for `bit8Mime` is garbled.

There is no "troubleshoot delivery" Action; use the SSE endpoint `/api/live/delivery/{target}` (§10). There is no "spam training" Action either; use Task `SpamFilterMaintenance` (§16).

Verbatim docs body:

```json
{"methodCalls":[["x:Action/set",{"create":{"new1":{"@type":"ReloadSettings"}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

Derived example:

```json
["x:Action/set", {"create": {"t1": {"@type": "TroubleshootDmarc", "remoteIp": "203.0.113.5",
  "ehloDomain": "mx.sender.example", "mailFrom": "news@sender.example",
  "spfEhloDomain": "mx.sender.example", "spfMailFromDomain": "sender.example",
  "message": "From: …\r\n…"}}}, "c1"]
```

---

## 16. Task (`x:Task`) and TaskManager (`x:TaskManager`)

### 16.1 `x:Task` – background jobs

| Item | Value |
|---|---|
| Methods | get, set (create, update, destroy), query |
| Permissions | `sysTaskGet`, `sysTaskCreate`, `sysTaskUpdate`, `sysTaskDestroy`, `sysTaskQuery`, plus a per-type permission `task<Type>` (e.g. `taskSpamFilterMaintenance`, `taskDnsManagement`). A missing per-type permission gives SetError `forbidden` "Insufficient permissions to create task of type X". |
| WebUI | Management › Tasks › Scheduled; Management › Tasks › Failed (view `x:Task/TaskFailed` with static filter `{"status":"Failed"}`) |

Every variant has `status` (TaskStatus, required) and `due` (`UTCDateTime?`, server-set).

**TaskStatus:**

| Variant | Fields |
|---|---|
| `{"@type":"Pending", …}` | `createdAt` (server-set), `due` (required) |
| `{"@type":"Retry", …}` | `createdAt`, `due`, `attemptNumber`, `failureReason` |
| `{"@type":"Failed", …}` | `createdAt`, `failedAt`, `failedAttemptNumber`, `failureReason` |

The default status is Pending with `due` = now, so `status` may be omitted on create [src].

Variants that clients may create, with their extra fields (all "read-only", i.e. immutable after create):

| `@type` | Fields |
|---|---|
| `AccountMaintenance` | `accountId`, `maintenanceType`: `purge`, `reindex`, `recalculateImapUid`, `recalculateQuota` |
| `TenantMaintenance` | `tenantId`, `maintenanceType`: `recalculateQuota` |
| `StoreMaintenance` | `maintenanceType` (see below), `shardIndex?` |
| `SpamFilterMaintenance` | `maintenanceType`: `train`, `retrain`, `abort`, `reset`, `updateRules` |
| `AcmeRenewal` | `domainId` |
| `DkimManagement` | `domainId` (key generation, rotation, retirement, deletion) |
| `DnsManagement` | `domainId`; `updateRecords` (`Set<DnsRecordType>`); `onSuccessRenewCertificate` (Boolean, default false) |
| `IndexDocument` / `UnindexDocument` | `accountId`, `documentId`, `documentType`: `email`, `calendar`, `contacts`, `file` |
| `IndexTrace` | `traceId` |

`StoreMaintenance` `maintenanceType` values:

| Category | Values |
|---|---|
| Reindex | `reindexAccounts`, `reindexTelemetry` |
| Purge | `purgeAccounts`, `purgeData`, `purgeBlob` |
| Reset | `resetRateLimiters`, `resetUserQuotas`, `resetTenantQuotas`, `resetBlobQuotas` |
| Remove | `removeAuthTokens`, `removeLockQueueMessage`, `removeLockTask`, `removeLockDav`, `removeSieveId`, `removeGreylist` |

Internal variants **cannot be created by clients**: `CalendarAlarmEmail`, `CalendarAlarmNotification`, `CalendarItipMessage`, `MergeThreads`, `DmarcReport`, `TlsReport`, `DestroyAccount`, `RestoreArchivedItem`. Attempts give `forbidden` "<Type> is an internal task type that cannot be created by clients" [src].

Semantics [src: mapping/task.rs]:

- **Create** returns `{"id": "<taskId>"}` and wakes the task queue. Foreign keys are checked (`invalidForeignKey`).
- **Update** changes `status` to reschedule. To retry a failed task, set `{"status":{"@type":"Pending","due":"<now>"}}`; this is inferred from the code and unverified as the official retry path.
- A task that is currently running cannot be updated: `forbidden` "Task is currently being processed and cannot be updated".
- **Destroy** removes the task. On Enterprise, destroying a pending `DestroyAccount` task **restores** the deleted account.
- Completed tasks disappear from the queue; only pending, retrying and failed tasks are listed (inferred).

Query:

| Condition | Kind | Notes |
|---|---|---|
| `@type` | enum TaskType | E.g. `"DnsManagement"`. |
| `status` | enum TaskStatusType | `Pending`, `Retry`, `Failed`. Per source, `Failed` is matched separately and the other values do not narrow the result. |
| `due` | date | Supports `Is…` operators. |

Sort: only `due`; other properties give `unsupportedSort` "Only sorting by 'due' is supported for tasks".

Derived examples:

```json
["x:Task/set", {"create": {"t1": {"@type": "SpamFilterMaintenance", "maintenanceType": "train"}}}, "c1"]
["x:Task/set", {"create": {"t2": {"@type": "DnsManagement", "domainId": "<domainId>", "updateRecords": {"dkim": true}, "onSuccessRenewCertificate": false}}}, "c1"]
["x:Task/set", {"create": {"t3": {"@type": "AccountMaintenance", "accountId": "<accountId>", "maintenanceType": "recalculateQuota"}}}, "c1"]
["x:Task/query", {"filter": {"status": "Failed"}, "sort": [{"property": "due", "isAscending": true}]}, "c1"]
```

The trigger the brief calls `trainSpamClassifier` does not exist. Use `SpamFilterMaintenance` with `maintenanceType: "train"` (or `retrain`).

Verbatim docs bodies:

```json
{"methodCalls":[["x:Task/set",{"create":{"new1":{"@type":"IndexDocument","status":{"@type":"Pending","due":"2026-01-01T00:00:00Z"}}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
{"methodCalls":[["x:Task/set",{"update":{"id1":{"status":{"@type":"Pending","due":"2026-01-01T00:00:00Z"}}}},"c1"]],"using":[…]}
{"methodCalls":[["x:Task/query",{"filter":{"@type":"value"}},"c1"]],"using":[…]}
```

### 16.2 `x:TaskManager` (singleton) – retry policy

| Item | Value |
|---|---|
| Methods | `x:TaskManager/get` and `x:TaskManager/set` (update `singleton`) |
| Permissions | `sysTaskManagerGet`, `sysTaskManagerUpdate` |
| WebUI | Settings › Task Manager |

Fields:

| Field | Type / default |
|---|---|
| `maxAttempts` | UnsignedInt, default 3, min 1 |
| `strategy` | `TaskRetryStrategy`, required (variants below) |
| `totalDeadline` | Duration, default 21600000 (6 h) |

`strategy` variants:

- `{"@type":"ExponentialBackoff","factor":2.0,"initialDelay":60000,"maxDelay":1800000,"jitter":true}`.
- `{"@type":"FixedDelay","delay":300000}`.

Verbatim docs body:

```json
{"methodCalls":[["x:TaskManager/set",{"update":{"singleton":{"maxAttempts":3}}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 17. SpamClassifier (`x:SpamClassifier`) and SpamTrainingSample (`x:SpamTrainingSample`)

### 17.1 `x:SpamClassifier` (singleton)

| Item | Value |
|---|---|
| Methods | `x:SpamClassifier/get` and `x:SpamClassifier/set` (update `singleton`) |
| Permissions | `sysSpamClassifierGet`, `sysSpamClassifierUpdate` |
| WebUI | Settings › Spam Filter › Classifier |

| Field | Type / default |
|---|---|
| `model` | `SpamClassifierModel`, required (variants below) |
| `learnHamFromCard` | Boolean, `true` |
| `learnSpamFromRblHits` | UnsignedInt, `2` (max 100) |
| `learnSpamFromTraps` | Boolean, `true` |
| `holdSamplesFor` | Duration, `15552000000` (180 d) |
| `minHamSamples` / `minSpamSamples` | UnsignedInt, `100` each (1–10000) |
| `reservoirCapacity` | UnsignedInt, `1024` (100–100000) |
| `trainFrequency` | `Duration?`, `43200000` (12 h) |
| `learnHamFromReply` | Boolean, `true` |

`model` variants:

| Variant | Fields |
|---|---|
| `{"@type":"FtrlFh"}` | `parameters` (FtrlParameters, default `{"numFeatures":"20"}`), `featureL2Normalize` (`true`), `featureLogScale` (`true`) |
| `{"@type":"FtrlCcfh"}` | as FtrlFh, plus `indicatorParameters` (default `{"numFeatures":"18"}`) |
| `{"@type":"Disabled"}` | – |

`FtrlParameters` fields: `alpha` 2, `beta` 1, `numFeatures` (ModelSize `"16"`…`"28"`, i.e. 2^n; default `"20"`), `l1Ratio` 0.001, `l2Ratio` 0.0001.

Training is triggered by Task `SpamFilterMaintenance` (`train`, `retrain`, `abort`, `reset`, `updateRules`) or runs every `trainFrequency`. To test the classifier, use Action `ClassifySpam`.

### 17.2 `x:SpamTrainingSample`

| Item | Value |
|---|---|
| Methods | get, query, set (create and destroy). **Update is refused**: `forbidden` "Spam training samples cannot be modified." [src]. |
| Permissions | `sysSpamTrainingSampleGet`, `sysSpamTrainingSampleCreate`, `sysSpamTrainingSampleUpdate`, `sysSpamTrainingSampleDestroy`, `sysSpamTrainingSampleQuery` |
| WebUI | Account › Spam Samples |

| Field | Type | Notes |
|---|---|---|
| `blobId` | BlobId, read-only | **Required on create** [src]: an uploaded RFC 5322 message (`POST /jmap/upload/{accountId}/`). It must parse and have a Subject or From header. |
| `isSpam` | Boolean, read-only, default `false` | |
| `deleteAfterUse` | Boolean, read-only, default `false` | |
| `accountId` | `Id<Account>?`, read-only | Settable only with the `impersonate` permission; otherwise forced to the caller's account [src]. |
| `from`, `subject`, `expiresAt` | server-set | `expiresAt` = now + `holdSamplesFor`. |

- If the classifier is not configured, create fails with `forbidden` "Spam classifier is not configured on the server".
- Query: condition `accountId`; the list is account-filtered unless the caller has `impersonate`.

Verbatim docs body:

```json
{"methodCalls":[["x:SpamTrainingSample/query",{"filter":{"accountId":"id1"}},"c1"]],"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"]}
```

---

## 18. Schema and describe (generic introspection)

- **The schema is not available as a JMAP method or capability object.** It is served over HTTP [docs: development/api, management/cli][src]:
  - `GET /api/schema` (authenticated) returns `302` to `/api/schema/{sha256}`.
  - `GET /api/schema/{hash}` returns `application/json` with `Content-Encoding: gzip` and an immutable cache policy. A wrong hash redirects to the current one.
- The CLI downloads this schema, caches it per server and keys the cache by hash. `stalwart-cli describe [Object|Enum]` renders it offline.
- Top-level keys of the document (v0.16.24 bundle, about 940 KB unzipped) [src]:

| Key | Content |
|---|---|
| `objects` | `x:Name` → `{"type":"object"\|"singleton"\|"view","description","permissionPrefix"}`. Views look like `x:Account/User` and point to their base object via `objectName`. |
| `schemas` | `{"type":"multiple","variants":[{"name","label","schemaName"}]}` or `{"type":"single","schemaName"}` |
| `fields` | `schemaName` → `{"properties": {prop: {"description", "type": {"type": "string"\|"number"\|"boolean"\|"utcDateTime"\|"object"\|"objectList"\|"set"\|"map"\|"objectId"\|"enum"\|"blobId", "format"?, "objectName"?, "enumName"?, "nullable"?, "class"?, "keyClass"?, "valueClass"?}, "update": "mutable"\|"immutable"\|"serverSet", "enterprise"?}}, "defaults": {…}}` |
| `lists` | Per object or view: `columns`, `filters` (`{"type":"text"\|"integer"\|"date"\|"enum"\|"objectId","field",…}`), `filtersStatic`, `labelProperty`, `itemActions` and `massActions` (e.g. QueuedMessage "Retry Now" = setProperty `nextRetry: "2000-01-01T00:00:00Z"`). |
| `enums` | Each enum's values with `name` and `label`. |
| `forms`, `dashboards`, `layouts` | WebUI rendering data. |

- The schema has **no sort information**; sortability follows the index rules in §0.5.
- The filter lists in the schema mirror the docs tables and are not always what the server accepts (e.g. DmarcExternalReport `domain`, Log, AllowedIp). Generate MCP tool schemas from it, but check against the §0.5 behaviour.

---

## Appendix A – Docs vs. source discrepancies (implementation gotchas)

1. Docs curl examples post to `/api`. The JMAP endpoint is `POST /jmap/` (session `apiUrl`).
2. "Combinable with AnyOf / AllOf / Not": only AND is supported; OR and NOT give `unsupportedFilter`.
3. No `/changes` or `/queryChanges` exists for any `x:` object.
4. `x:Action` results are returned only in the `/set` create response. `get` always returns notFound and `query` returns `invalidArguments`.
5. `x:Log`, `x:Trace` and `x:Metric` `/set` are always forbidden, despite the docs examples. `x:QueuedMessage` and `x:*ExternalReport` create are forbidden.
6. `x:Log/query` accepts only `text`. The CLI doc's `--where level=error` fails. Paging is by anchor only.
7. `x:DmarcExternalReport` `domain` filter (docs and schema): per source it is accepted only for internal reports. Use `text`.
8. `x:AllowedIp` / `x:BlockedIp` `address` filter: the value must be a valid IP or CIDR (docs example `"example"` fails).
9. `x:Metric` requires Enterprise per source; the docs index does not mark it.
10. The urn:stalwart:jmap capability is absent from the top-level session `capabilities`; it appears in `accountCapabilities` and `primaryAccounts`.
11. Docs mark many fields "required" that have server defaults (`roles`, `permissions`, `encryptionAtRest`, Domain `*Management`, `subAddressing`). ⚠ Domain `dkimManagement` defaults to **Automatic**.
12. API keys and app passwords are always created for the calling account. Admins can only revoke other users' keys (via `x:Account` `credentials`).
13. Legacy kebab-case permission names on /docs/auth/authorization/permissions are obsolete. Use the camelCase names from /docs/ref/permissions.
14. `x:BlockedIp` and `x:AllowedIp` writes need `ReloadBlockedIps` and `ReloadSettings` respectively before they take effect in the running server.

## Appendix B – Pages consulted

`/docs/ref/` (index), `/docs/ref/permissions/`, `/docs/ref/events/`, `/docs/ref/metrics/`, and these object pages under `/docs/ref/object/`:

- `account`, `account-password`, `authentication`, `domain`, `dkim-signature`, `mailing-list`, `role`, `tenant`
- `api-key`, `app-password`, `allowed-ip`, `blocked-ip`, `security`
- `queued-message`, `mta-route`, `mta-outbound-strategy`, `dmarc-external-report`, `tls-external-report`
- `log`, `trace`, `metric`, `action`, `task`, `task-manager`, `spam-classifier`, `spam-training-sample`, `system-settings`, `tracer`

Guide pages:

- `/docs/development/api/`, `/docs/configuration/` and `/docs/configuration/object-encoding/`
- `/docs/management/cli/` and its sub-pages `describe`, `get`, `query`, `create`, `update`, `delete`, `apply`, `snapshot`
- `/docs/management/tasks-actions/` (incl. `actions`, `tasks`), `/docs/management/troubleshoot/`
- `/docs/domains/` (incl. `dns-records`, `dkim-rotation`)
- `/docs/auth/authentication/` (`password`, `api-key`, `app-password`), `/docs/auth/authorization/` (`administrator`, `roles`, `permissions`, `tenants`), `/docs/auth/principals/`, `/docs/auth/scim/configuration/` and `/docs/auth/scim/mapping/`
- `/docs/mta/outbound/routing/` and `/docs/mta/outbound/strategy/`, `/docs/mta/authentication/dkim/sign/`
- `/docs/server/auto-ban/`, `/docs/telemetry/tracing/log/`, `/docs/spamfilter/classifier/training/`
- `/docs/http/jmap/`, `/docs/install/security/`

Source files (stalwart v0.16.24):

- `crates/jmap-proto/src/request/{capability,method}.rs`, `crates/jmap-proto/src/object/registry.rs`, `crates/jmap-proto/src/error/{set,method}.rs`
- `crates/jmap/src/api/{request,session,auth}.rs`, `crates/jmap/src/registry/{get,set,query}.rs`
- `crates/jmap/src/registry/mapping/{account,principal,domain,dkim,action,task,log,telemetry,report,queued_message,spam_sample}.rs`
- `crates/http/src/{request.rs,api/mod.rs,api/diagnose.rs,auth/authenticate.rs}`
- `crates/common/src/{network/security.rs,auth/rate_limit.rs,auth/credential.rs,auth/permissions.rs,manager/defaults.rs,cache/reload.rs}`
- `crates/services/src/task_manager/dkim.rs`, `crates/scim/src/users/mod.rs`, `crates/registry/src/types/{ipmask,list,error}.rs`
- `resources/schema/schema.json.gz`, `api/v1/openapi.yml`, `UPGRADING/v0_16.md`

stalwart-cli: `src/jmap/{session,protocol}.rs`.
