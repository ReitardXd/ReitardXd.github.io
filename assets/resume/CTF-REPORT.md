# Superhuman (formerly Grammarly + Coda + Superhuman Mail) — $100K CTF — EXHAUSTIVE TECHNICAL REPORT

**Challenge**: Retrieve the `$FLAG` stored in `document_id: 1198436185`, owned by `user_id: 1411519194` (email `h1_ctf@grammarly.com`). First to report the flag wins $100K.
**Program scope (HackerOne)**: `*.coda.io`, `*.grammarly.com`, `*.grammarly.io`, `*.grammarlyaws.com`, `*.superhuman.com` (wildcards) + `app.grammarly.com`, `coda.grammarly.com`, `coda.io`, `codacontent.io`, `codahosted.io`, `docs.superhuman.com`, `gateway.superhuman.com`, `id.superhuman.com`, `mail.superhuman.com`, `settings.superhuman.com`, `superhuman.com` + apps/extensions. Out of scope: `status.coda.io`, third-party services.
**Engagement date**: 2026-08-06 (single continuous session, ~6 hours of active testing, 4 parallel sub-agents + manual deep-dive).
**Status**: FLAG NOT YET RETRIEVED. All primary surfaces mapped and exhausted; 1 strong intended-path candidate (gated migration IDOR) + several secondary leads remain (see §12).

---

## TABLE OF CONTENTS
1. Executive summary
2. Identity & session architecture
3. System-by-system deep dive
   - 3.1 dox.grammarly.com (legacy Grammarly Docs) — PRIMARY SUSPECT
   - 3.2 coda.grammarly.com (Coda AI Editor / Grammarly tenant)
   - 3.3 docs.superhuman.com / coda.io (Superhuman Docs tenant)
   - 3.4 app.grammarly.com (Denali editor SPA)
   - 3.5 capi.grammarly.com (writing assistant)
   - 3.6 gateway/goldengate.grammarly.com (experiments, settings registry)
   - 3.7 auth.grammarly.com / id.superhuman.com / tokens.grammarly.com
   - 3.8 codacontent.io / codahosted.io / cdn.coda.io (content CDN)
4. Complete endpoint inventory with exact behaviors (target vs control vs random)
5. Exhaustive list of everything tried (fuzz matrices, payloads, headers)
6. Realtime/websocket protocol reverse engineering (exact frames)
7. Client-side JS reverse engineering findings (exact code, file locations)
8. Experiments / feature flags discovered
9. Demo-doc & seed-content system
10. Migration system (the intended-path candidate)
11. Evidence for "where the flag lives"
12. Working hypotheses (ranked)
13. Recommended next steps (priority order, with exact commands)
14. Artifact & file location index
15. Protocol cheatsheets for instant replay
16. Open questions / unknowns

---

## 1. EXECUTIVE SUMMARY

- The challenge's `document_id: 1198436185` / `user_id: 1411519194` match the **numeric ID scheme of the legacy Grammarly Docs backend (`dox.grammarly.com`)** exactly. Coda-family backends use base62 doc IDs (e.g. `nt6_6EOfDO`) and their own numeric user IDs; the target document is verifiably absent from every Coda tenant (three independent oracle checks).
- **Every legacy-docs endpoint is strictly user-scoped**: the authenticated session's user ID is always used as the ownership key; every client-supplied identity vector (headers, query params, body fields, WS params) was ignored. The target doc is indistinguishable from a nonexistent doc on EVERY tested surface (no existence oracle exists).
- The **legacy→Coda document migration endpoint** (`POST /importdoc/migrate/`) is the only cross-user primitive found in the entire product: the client sends `{"grammarlyUserId": <num>, "grammarlyDocumentId": <num>}` — both IDs client-supplied by design. It is currently blocked by a **403 gate that runs BEFORE document lookup** (identical response for own docs, target, and random IDs). The gate correlates with the server-side experiment `ai_editor_migration_internal` being OFF for test accounts. If the gate can be satisfied, this endpoint almost certainly migrates (copies) the target user's document into the caller's Coda account → flag.
- The h1 account's flag doc is likely provisioned as its **auto-created demo document** — evidenced by the experiment name `ai_editor_demo_doc_h1_2026` (+ gate `ai_editor_demo_doc_h1_2026_prefilter`), "H1 2026" = HackerOne 2026. The demo-doc seed system was fully reversed; only one client-side seed exists (`proofreaderDemo`), and the seed content is NOT the flag. The provisioning path for the h1 demo doc remains unknown.
- No share-link, publish, embed, or realtime channel exposes the document. No user enumeration exists. Settings registry is ACL-enforced.

---

## 2. IDENTITY & SESSION ARCHITECTURE

### 2.1 Identity providers
- **id.superhuman.com** — Superhuman identity (OAuth2, PKCE S256, `client_id=superhumanDocs`, `oauth_client_type=MEDIATED_WEB`, scopes `grammarly.capi.all`; flows: Google/Microsoft/Apple/email+password; email verification = 6-digit code, 15 min expiry; workspace-name onboarding step).
- **auth.grammarly.com** — Grammarly identity layer (`/auth/v3/*`, `/tokens/v4/*`). Federates with Superhuman.

### 2.2 Session artifacts observed
- `gr-wc-tkn` (docs.superhuman.com) — JWT access token; claims: `aud: [capi.grammarly.com, coda.io, id.superhuman.com, gateway.superhuman.com, docs.superhuman.com]`, `scp: grammarly.capi.all`, `sub: <grammarlyUserId>`, `acr: urn:grammarly:auth:2fa`, `cid: superhumanDocs`.
- `grauth` (.grammarly.com) — legacy auth cookie (opaque token).
- `csrf_token` / `csrf-token` (.grammarly.com) — dual CSRF cookies; note: after re-login the `csrf-token` cookie rotates while the legacy `csrf_token` cookie may NOT (observed stale value causing dox `csrf token mismatch`).
- `prod_origin_session`, `session_data` (base64 `{"id":"as-..."}`), `auth_flag` (base64 of Coda userId) — coda.grammarly.com session.
- `sticky` (capi.grammarly.com), `tdi`, `AWSALB`/`AWSALBCORS`, `window_visit_id`, `lastActivePage`.
- OAuth token exchange: `tokens.grammarly.com/oauth2/exchange` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:grammarly:params:oauth:token-type:grauth` → access_token; clientId fingerprint `webeditor_chrome` etc.; WAF-blocked for direct curl (403), browser-only (proxy path `"oauth"`); tokens cached in `localStorage["grammarly.<clientId>.tokens"]`. **This JWT is usable as `?accessToken=` on the dox websocket — NOT YET TESTED against the target doc.**

### 2.3 Two account origins observed
- **Superhuman-origin** accounts (signed up via id.superhuman.com): user profile `origin: "superhuman"`, groups contain `super-human`.
- **Grammarly-origin** accounts (signed up directly at www.grammarly.com/signup): origin `"grammarly"`.
- Both produce working sessions on dox/coda/app. The migration gate (403) was identical for both origins → gate is not origin-based.
- New Grammarly-origin signup lands on a team-join interstitial when the email domain belongs to an org (`/request-to-join`) — skippable.

### 2.4 User ID model
- Grammarly user ID: 10-digit numeric (e.g. `31xxxxx` range for 2026 signups; `14xxxxx` range for older accounts — target `1411519194` fits an older account).
- Coda user ID: separate numeric (e.g. `61xxxxx`), exposed via `auth_flag` cookie and collab socket `userId`.
- No endpoint found that maps between them for other users; the collab socket accepts arbitrary client-supplied userId but the subscription resolves the session user.

---

## 3. SYSTEM-BY-SYSTEM DEEP DIVE

### 3.1 dox.grammarly.com — LEGACY GRAMMARLY DOCS (PRIMARY SUSPECT)

**Stack fingerprint**: `server: nginx-clojure`, `x-powered-by: Jetty`, Spring-style error bodies (`{"type":"about:blank","status":405,"detail":"Method 'GET' is not supported.","instance":"/documents/2988746564"}`), static-resource fallthrough (`"No static resource documents/<id>/xxx."`).

**Auth**: `.grammarly.com` cookies (grauth). Custom headers REQUIRED (else `403 {"status":"error","info":"missing required headers"}`):
```
X-Csrf-Token: <csrf-token cookie value>
X-Api-Version: 2
X-Container-Id: <containerId>           (observed: famjaviic75m0ao1)
X-Client-Type: denali_editor
X-Client-Version: 1.5.43-6806+master
Accept: application/json
Referer: https://app.grammarly.com/
User-Agent: <Chrome Linux UA mandatory>
```

**Core behaviors (ALL user-scoped; error text reveals the scoping key)**:
- `GET /documents?search=&limit=100&firstCall=false&filterDocs=not_deleted,not_migration_completed` → 200 `[{"id":<num>,"user_id":<num>,"title","size","first_content","errors","created_at","updated_at","demo":0|1,"is_deleted":0,"extra_params":{...}}]`. **`first_content` leak for own docs** (first ~100 chars of the doc).
- `POST /documents` (JSON) → 201 creates doc; server assigns `id`; any `user_id` in body is OVERRIDDEN by session.
- `GET /documents/{id}/metadata` → 200 own: `{"id","user_id","title","size","first_content","errors","created_at","updated_at","is_deleted"}`; others → 404 `{"status":"error","info":"Cannot find document for userId = <session>, docId = <target>"}`.
- `GET /documents/{id}/download` (needs `Accept: text/plain` or `application/octet-stream`) → 200 own: **full document plaintext**; others → 404 `document not found`. With `Accept: application/json` → 406 (content-negotiation before 404 — identical for random, NOT an oracle).
- `GET /documents/{id}/preview` → 200 own (PNG render); others 404.
- `GET /documents/{id}/revisions` → 200 own JSON incl. first_content; others 404.
- `POST /documents/{id}/restore` → 200 own; others 404 `Cannot find document for userId = ..., docId = X`.
- `DELETE /documents/{id}` → 204 own; others 404. `OPTIONS` → `Allow: DELETE,OPTIONS`.
- `POST /documents/{id}/report` → report flow.
- `GET /documents/deleted` → own deleted docs; `GET /documents/downloadAll` → bulk; `POST /docproc/extract` → extraction.
- `DELETE /documents/demo` → batch-delete demo docs (`Allow: DELETE,OPTIONS`).
- `DELETE /documents/migrate`, `DELETE /documents/migration` → batch-delete migrated docs (`Allow: DELETE,OPTIONS`). **NOTE: these paths EXIST — the platform tracks migration state per doc.**
- `GET /health` → 200; `GET /admin` → 403.
- **WS**: `wss://dox.grammarly.com/documents/{docId}/ws` — see §6.1.

**Doc-list filter values**: only `not_deleted`, `not_migration_completed`, `deleted`, `demo` accepted; `all`, `shared`, `shared_with_me`, `public`, `migration_completed` → 400 or 403 "missing required headers" (validation quirk).

**Demo doc**: every new user automatically receives `{"title":"Demo document","size":1076,"demo":1,"first_content":"The basics\nMispellings and grammatical errors can effect your credibility. ..."}` (content == `bulkAcceptDemoText` in the app bundle). Server-side auto-provisioning at first login; identical content for both test accounts → the standard demo doc is not user-specific. The h1 user's doc 1198436185 (created in an older ID range ~1.19B vs current ~2.98B) is consistent with an old demo/provisioned doc.

### 3.2 coda.grammarly.com — CODA / AI EDITOR (Grammarly tenant)

**Stack**: Same Coda backend as docs.superhuman.com (same Coda userId across tenants). Doc URL formats: `/d/<slug>_<docId>` (e.g. `/d/Untitled-doc_dnt6_6EOfDO`) and `/d/_d<docId>` (e.g. `/d/_dnt6_6EOfDO`). **Collab-socket `documentId` = doc id WITHOUT the leading `d`** (i.e. `nt6_6EOfDO`).

**Auth**: grammarly.com cookies + coda session (`prod_origin_session`, `session_data`, `auth_flag`); headers `X-CSRF-Token`, `X-Auth-User-Id: <codaUserId>`; Chrome Linux UA mandatory (Windows UA → redirects/403). POST/PUT without CSRF → 400 SPA "Error" page; wrong origin → 400 `Invalid Origin or Referer header` / `InvalidCsrfToken`.

**Endpoints** (all session-scoped; target ≡ random everywhere):
- `GET /api/initLoad?docId=X` → 200 for own docs (initContext + signed snapshot URLs); target/random → 404 `You need permission to access this doc.` (identical).
- `GET /internalAppApi/doclist/recent?pageToken=0&limit=100&sortOrder=modified&viewType=<T>` → 200; **valid viewTypes (schema error leak)**: `FOLDER, SHARED, STARRED, VIEWED, OWNED_NON_DELETED, OWNED_DELETED, ALL_DOCS, TRENDING`. `SHARED` → `{"items":[]}` (nothing shared with attacker).
- `GET /internalAppApi/documents/{id}` → own 200; target 403.
- `GET /internalAppApi/documents/{id}/users` → own 200 (roster); target 404 (SPA).
- `GET /internalAppApi/documents/{id}/sharing?queryFullMetadata=true` → own 200 (fields: `canShare, canManage, canShareWithOrg, canShareWithWorkspace, docCopyState, editorShareState, documentUrl, documentType, effectivePermissions, permissionGroups, permissionUsers...`); target → 404 `{"statusCode":404,...,"message":"Doc does not exist or is inaccessible."}` (identical to random).
- `POST /internalAppApi/documents/{id}/sharing` — update collaborators (schema: `{"changes":[{"type":"Create","accessType":"View|Edit|...","email":...|"anyone":true}],"message","suppressEmail","sharingBehavior","sharingMentionEmailOptions"}`); control-doc schema learned; target untested-effect (rejected at doc layer).
- `POST /internalAppApi/documents/{id}/export` `{"format":"pdf|docx|...","filename","includeComments","separateTitlePages","layoutOptions"}` → workflow → `GET /internalAppApi/workflows/{wfId}/isComplete` → `POST /internalAppApi/documents/{id}/export/{wfId}/url` → `{signedUrl}`; target 403.
- `GET /internalAppApi/documents/{id}/star`, `/activity`, `/linkMetadata`, `/publish`, `/publish/categories/{cat}`, `/publish/react/{id}`, `/templates/{id}`, `/blobs/{id}`, `/objects/{id}`, `/externalConnections/{id}`, `/automations/{id}`, `/packs/{id}`, `/syncPagePermissions/...`, `/crossdoc/table/...`, `/brain/table/...` — full surface, same access pattern.
- `GET/POST /internalAppApi/account/*` (tokens, settings, providers, picture, delete flows), `/workspaces/*` (users, groups, pinnedDocs, folders, billing, assistant/quota, claimDocOwnership, requestDocOwner*), `/folders/*` (sharing, pinnedDocs), `/organizations/*` (users, groups, packs, SAML, apiTokens, legalHolds, webhooks, importers, MCP allowlist), `/mentions*`, `/assistant/*` (brainSearch, customBrain, quota, records), `/agents*`, `/workflows/*`, `/billingAccounts/*` — all session-scoped.
- `POST /newdoc/Untitled%20document?openDocument=false` → 200 `{"documentId":"<base62>","initContext":{...}}` — creates blank Coda doc.
- `GET /newdoc?agentId=<a>&seedContentId=<s>` — SPA page; creates doc then applies seed content CLIENT-SIDE (see §9).
- `POST /importdoc/prepare/v2` `{"fileName","payloadHash","contentType"}` → **200** `{"blobId":"bl-...","blobUploadUrlInfo":{"uploadUrl":"https://coda-us-west-2-prod-blobs-upload.s3-accelerate.amazonaws.com/migrations/blobs/<codaUserId>/<blobId>","authorizedHeaders":{content-disposition, x-amz-content-sha256, x-amz-meta-filename, policy, x-amz-signature...}}}` — **import pipeline works; S3 path uses the SESSION Coda userId.**
- `POST /importdoc/complete/v2` `{"blobId",...}` → 400 (needs real uploaded blob).
- `POST /importdoc/migrate/` (trailing slash) → **403 Forbidden** for EVERYTHING (see §10). `POST /importdoc/migrate` (no slash) → 404. `POST /importdoc` → 403. `GET /importdoc/migrate/` → 403.
- `GET /d/_d{id}` SSR → editor page for own docs; generic `Grammarly | Request access - Coda` page (404) for target AND random — identical bytes.
- `GET /d/{numeric}` → 302 or 403 (inconsistent routing); `GET /p/{id}`, `/embed/...` → SPA fallthrough.
- `GET /apis/v1/*`, `/apis/v1beta1/*` → 403 Forbidden (docs.superhuman.com API tokens rejected; session also rejected).
- `wss://coda.grammarly.com/collab/?params=<b64>&EIO=4&transport=websocket` — see §6.2.
- `wss://coda.grammarly.com/logging/socket/?params=<b64>&EIO=4&transport=websocket` — logger (namespace `/logger_server`).

### 3.3 docs.superhuman.com / coda.io — SUPERHUMAN DOCS TENANT

**Auth**: `gr-wc-tkn` JWT cookie + `csrf_token` cookie + `prod_origin_session`; headers `X-CSRF-Token`, `X-Auth-User-Id: <codaUserId>`; API tokens minted via `POST /internalAppApi/account/tokens {"description":...}` → `{token:{...,"secret":"<uuid>"}}` (works only on this tenant; `coda.io/apis/v1/docs/{id}` with Bearer token works).

**Endpoints**:
- `GET /api/document/{id}` → 200 for own docs: `{"initContext":{"docId","blockingShards":[{"url":"https://codacontent.io/docs/<docId>/snapshots/<schemaVer>/<opVer>/fui-critical?Expires=...&Key-Pair-Id=...&Signature=...","shardId":"fui-critical"}],...},"docUser":{permissions},"runtimeConfig":{...}}`; target/random → 404 SPA (identical).
- `GET /apis/v1/resolveBrowserLink?url=<url-encoded>` → **the existence oracle**: own docs → `{"type":"apiLink","href":...,"browserLink":...,"resource":{"type":"doc","id":"<base62>",...}}`; target & random → `{"statusCode":404,...,"message":"Doc does not exist or is inaccessible."}` → **target NOT on this tenant** (also for `coda.io/d/_d1198436185` and `docs.superhuman.com/d/_d1198436185` forms).
- `GET /apis/v1/docs/{id}` → 200 own (full doc metadata incl. `owner` (email), `ownerName`, `workspaceId`, `folderId`, `sourceDoc`, `docSize`); target 404.
- `GET /internalAppApi/documents/{id}/sharing`, `/export/{fmt}`, `/star`, `/activity`, `/linkMetadata`, `/publish`, `/publish/categories/{id}`, `/templates/{id}`, `/blobs/{id}`, `/objects/{id}`, `/users` — same Coda codebase; own docs OK; target 404/403.
- `GET /internalAppApi/doclist/recent|search|search2|trashed|mentioned|templates|trending` — session lists; `search2` POST `{"query":...,"docSearchPermissionContextType":"User"}` returns empty for test accounts.
- `POST /docaccess/{id}` → "request access" notification (200 with valid session; requires X-Csrf-Token; **target-vs-random NOT conclusively tested with a valid fresh session**).
- `GET /v1/mediator/initiate`, `GET /v1/mediator/token`, `GET /v1/mediator/callback` — OAuth mediation.
- `GET /api/initLoad`, `/api/oembedResolve?docId=&url=&isMobile=`, `/api/icons`, `/api/thumbnail`, `/api/formulaMetadata`, `/api/gallery`, `/api/agents/search`, `/api/featuredPacks`, `/api/packs/prefetchSet`, `/api/import/v2`, `/api/mobileStarterDocs`, `/api/marketplace/{id}` — content/marketing APIs.
- `POST /logging/event`, `/csp-violation` — telemetry.
- `wss://docs.superhuman.com/...` — same collab stack.

**Observation**: `docs.superhuman.com/importdoc/migrate/` and `/importdoc/prepare/v2` respond `400 Invalid Origin or Referer header` / `401 Unauthorized` when called with stale/wrong-origin sessions — the importdoc namespace EXISTS on this tenant too (untested with fresh correct-origin session).

### 3.4 app.grammarly.com — DENALI EDITOR SPA

- Routes: `/` (docs list), `/ddocs/<id>` (classic editor; `/docs/<id>` 301→`/ddocs/<id>`), `/documentVersionHistory`, `/trash`, `/account`, `/apps`.
- `/ddocs/1198436185` → `Can't find this document` (identical for random; control docs open). The editor resolves classic docs through the dox WS; no REST content fetch.
- Doc list merges: `GET dox.grammarly.com/documents?...` (classic) + `GET coda.grammarly.com/internalAppApi/doclist/recent?...` (AI editor) + `GET auth.grammarly.com/auth/v3/user/bridge/check-eligibility/coda` (bridge check).
- "New doc" → `coda.grammarly.com/newdoc`; "AI New doc" → `coda.grammarly.com/newdoc?agentId=proofreader&seedContentId=proofreaderDemo`.
- Per-doc "More actions" menu: Download / Delete (classic), plus Migrate (AI-editor docs) — Migrate appears only with `?exp=denaliMigration` URL override; clicking it fires `POST coda.grammarly.com/importdoc/migrate` (no trailing slash → 404; the client path is effectively dead).
- Editor session: dox WS (content) + capi WS (suggestions) + coda collab WS (for AI-editor docs).
- Webpack bundles at `denali-static.grammarly.com/js/<hash>/<name>.js?env=prod`; entry `1893fda00e29cfc4dc83/index.js` requires modules 48732/8299/2329; chunk naming: `default-*.js`, `vendor-*.js`, `dyn/*.js`.

### 3.5 capi.grammarly.com — WRITING ASSISTANT

- `wss://capi.grammarly.com/freews` — client → `{"id":0,"action":"start","client":"denali_editor","docid":"<docId>",...}`; server returns session/features/suggestions only. **Never fetches or returns document content server-side → no leak surface.**
- `GET /api/configuration/cheetah/v1/settings` → 200 (session).
- No doc REST surface: `/api/document|documents|doc|docs|edits|v1/document|getDocument/<id>` all → 404 `{"error":"HTTP 404"}`.

### 3.6 gateway.grammarly.com / goldengate.grammarly.com

- `POST /experimentation/treatment/get` — 200; requires `x-csrf-token`, `x-client-type: ai_editor`, `x-client-version: 0.0.1`, `x-page-path`, `referer`, `x-container-id`; body = JSON array of experiment names (the app sends ~200 names). Returns per-user treatments/gates (Statsig — `x-statsig-sdk-version: serversdk:3.1.3`).
- `POST /experimentation/gates/get`, `GET /experimentation/properties`, `GET /passport/api/v1/passport?features=...`, `GET /vito/*`, `GET /subscription.grammarly.com/api/v1/*` — session-scoped.
- **Settings registry** (`goldengate.grammarly.com/settings-registry/v1`): `GET /settings/{key}/resource/{USER|GLOBAL|INSTITUTION}/{id}`, `POST /settings/merged`, `POST /settings/batch-get`, `PUT/PATCH/DELETE /settings/{key}/resource/...`, `POST /settings/batch/{type}`. **ACL enforced**: requesting another user's setting → `401 {"error":"unauthorized"}` (tested `promoDocument` etc. from the authenticated origin with full headers). No IDOR.
- CORS allow-list includes: `Authorization, X-API-Version, X-Client-Type, X-Client-Version, X-Container-Id, X-Features, X-CSRF-Token, X-Consent-*, X-Authorization-SuperUser-ResourceId, X-Authorization-SuperUser-ResourceType, X-Authorization-Passport, Grammarly-Auth-Policy, X-Page-Path` — superuser/passport headers are first-class citizens; all were tested and ignored on dox/coda/migrate (§5.6).

### 3.7 auth.grammarly.com / id.superhuman.com / tokens.grammarly.com

- `GET /auth/v3/user?app=webeditor_chrome&field=...` — own profile (401 without app context).
- `GET /auth/v3/user/bridge/check-eligibility/coda` → `{"isEligible":true}` — Coda bridge eligibility. No doc-migration bridge endpoints exist (404s on `/bridge/*` guesses).
- `GET /auth/v3/user/{id}` and `?userId=`/`?email=` → 404 or own user (params ignored). No enumeration.
- `id.superhuman.com`: `/auth/v3/user/location/data-regulation`, `/auth/v5/api/userinfo`, `/tokens/v4/api/sessions` (403), `/login/api/v1/flow/bootstrap|continue`, `/ui/flow/generic?transactionId=`, `/signup/track`.
- `tokens.grammarly.com`: `/oauth2/token` (refresh/authorization_code), `/oauth2/exchange` (grauth token-exchange). curl → nginx 403; browser-only (app proxy `"oauth"`). **Highest-value unlock (§12.1).**

### 3.8 codacontent.io / codahosted.io / cdn.coda.io

- `codacontent.io/docs/{docId}/snapshots/{schemaVer}/{opVer}/fui-critical?Expires=&Key-Pair-Id=APKA...&Signature=` — CloudFront-signed snapshot shards; issued ONLY by `/api/initLoad`/`/api/document` AFTER ACL; not guessable/forgeable (RSA signature).
- `codahosted.io` — blob CDN (raw/attachments).
- `cdn.coda.io/assets/*` — SPA bundles (public).
- Direct probe of target snapshot paths → AccessDenied/404.

---

## 4. COMPLETE ENDPOINT INVENTORY — TARGET vs CONTROL vs RANDOM BEHAVIOR MATRIX

Legend: T = target doc 1198436185, C = control (own doc), R = random 9999999999 (or zzzzzzzzzz). "≡" = responses byte-identical.

### 4.1 dox.grammarly.com
| Endpoint | C | T | R | Oracle? |
|---|---|---|---|---|
| GET /documents?filterDocs=... | 200 list | (not in list) | (not in list) | no |
| POST /documents | 201 | — | — | no |
| GET /documents/{id}/metadata | 200 | 404 | 404 | **no (T≡R)** |
| GET /documents/{id}/download (text/plain) | 200 full text | 404 | 404 | no (T≡R) |
| GET /documents/{id}/download (json) | 406 | 406 | 406 | no |
| GET /documents/{id}/preview | 200 | 404 | 404 | no (T≡R) |
| GET /documents/{id}/revisions | 200 | 404 | 404 | no (T≡R) |
| POST /documents/{id}/restore | 200 | 404 | 404 | no (T≡R) |
| DELETE /documents/{id} | 204 | 404 | 404 | no (T≡R) |
| OPTIONS /documents/{id} | Allow: DELETE,OPTIONS | same | same | no |
| WS /documents/{id}/ws | init+content | 4004 | 4004 | no (T≡R) |
| WS /documents/{id}/ws (no auth) | 4001 | 4001 | 4001 | no |
| POST /documents/{id}/report | 200 | 404 | 404 | no (T≡R) |
| 60+ suffixes on /documents/{id}/... | — | 404 static | 404 static | no |
| 40+ query params on list | own only | — | — | no |
| /documents/demo, /migrate, /migration | DELETE-only | — | — | n/a |

### 4.2 coda.grammarly.com
| Endpoint | C | T | R | Oracle? |
|---|---|---|---|---|
| GET /api/initLoad?docId= | 200 | 404 | 404 | no (T≡R) |
| GET /internalAppApi/documents/{id} | 200 | 403 | 403 | no |
| GET /internalAppApi/documents/{id}/users | 200 | 404 | 404 | no |
| GET .../sharing?queryFullMetadata=true | 200 | 404 | 404 | no (T≡R) |
| POST .../sharing | 200-ish | rejected | rejected | no |
| GET/POST .../export | 200 | 403 | 403 | no |
| GET /d/_d{id} SSR | editor | "Request access" | "Request access" | no (T≡R) |
| GET /d/{numeric} | — | 302/403 | 302/403 | no |
| POST /importdoc/migrate/ | 403 | 403 | 403 | **no (all ≡)** |
| POST /importdoc/prepare/v2 | 200 | — | — | n/a |
| POST /importdoc/complete/v2 | 400 | 400 | 400 | no |
| WS /collab/ (subscribe) | subscribed | error 404 | error 404 | no (T≡R) |
| WS /collab/ (handshake only) | sid granted | sid granted | sid granted | no |
| WS /collab/ (userId=owner 1411519194) | — | error 404 | — | no |
| GET /apis/v1/* | 403 | 403 | 403 | no |

### 4.3 docs.superhuman.com
| Endpoint | C | T | R | Oracle? |
|---|---|---|---|---|
| GET /api/document/{id} | 200 | 404 | 404 | no (T≡R) |
| GET /apis/v1/resolveBrowserLink | resource | not exist | not exist | **no (T≡R)** |
| GET /apis/v1/docs/{id} | 200 | 404 | 404 | no (T≡R) |
| GET /d/_d{id} SSR | editor | "Request access" | "Request access" | no (T≡R) |
| POST /docaccess/{id} | 200 | 200 (stale sess) | untested | **PENDING fresh-session test** |

### 4.4 app.grammarly.com
| Endpoint | C | T | R | Oracle? |
|---|---|---|---|---|
| GET /ddocs/{id} | editor loads | "Can't find this document" | "Can't find this document" | no (T≡R) |

**CONSOLIDATED VERDICT**: Not a single endpoint distinguishes the target document from a nonexistent one. The document exists only in the dox database under user 1411519194 and is strictly private.

---

## 5. EXHAUSTIVE LIST OF EVERYTHING TRIED

### 5.1 Recon & enumeration
- crt.sh-style subdomain review via program scope; confirmed hosts: docs.superhuman.com, coda.grammarly.com, codacontent.io, codahosted.io, gateway.superhuman.com, id.superhuman.com, app.grammarly.com, dox.grammarly.com, capi.grammarly.com, auth.grammarly.com, tokens.grammarly.com, goldengate.grammarly.com, gateway.grammarly.com, subscription.grammarly.com, denali-static.grammarly.com, cdn.coda.io.
- HackerOne GraphQL team/scope enumeration (all assets, eligibility flags).
- mail.tm disposable inboxes (2) — used for signup verification codes; monitored for share invitations (none received).
- Browser automation: 14 tabs across all tenants, network interception, WebSocket frame capture via `addInitScript` hooking (captured both directions incl. `send()`).

### 5.2 Auth & identity
- Signup via id.superhuman.com (email+password+6-digit code; workspace name step).
- Signup via www.grammarly.com/signup (email+password+6-digit code; team-join interstitial skip).
- Federated sign-in Grammarly↔Superhuman; sign-out flows.
- Token mints: Coda API token (docs.superhuman.com `/internalAppApi/account/tokens`); attempted grauth→access_token exchange on tokens.grammarly.com (WAF 403 both curl and cross-origin; clientIds blocked).
- Auth header probes on dox WS: `?accessToken=`, cookie-only, origin checks (rejects non-app.grammarly.com origins).
- Auth/v3/user endpoint fuzz: `/auth/v3/user/{id}`, `?userId=`, `?email=` (all scoped).

### 5.3 dox.grammarly.com full fuzz
- **Methods**: GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD on `/documents/{id}` and aliases `/document/`, `/docs/`, `/d/`, `/document-server/`.
- **Suffixes (60+)**: content, text, html, body, edits, meta, info, share, shares, shared, invite, invitations, collaborators, collaboration, access, export, download, versions, version, history, activity, comments, permissions, acl, thumbnail, preview, view, open, session, edit, update, delete, trash, restore, copy, duplicate, rename, title, settings, proofread, proofit, proofit/*, versions, migrate, migration, migrations, migration/start, demo, publish, embed, print, pdf, docx, html, markdown, image, icon, cover, favorite, star, pin, lock, archive, move, transfer, owner, takeover, claim, exportAll, import, template.
- **List params (40+)**: search, q, query, ids, id, doc_id, document_id, user_id, userId, owner_id, ownerId, shared, shared_with, shared_by, from_user, fromUser, demo, is_demo, deleted, is_deleted, migration, migration_status, sort, order, page, offset, cursor, limit, firstCall, filterDocs (all variants), onlyCnt, view, scope, folder, includeDeleted.
- **Header identity overrides**: X-User-Id, X-Denali-User-Id, X-Grammarly-User-Id, X-Impersonate, X-On-Behalf-Of, X-Forwarded-User, X-Forwarded-Email, X-Authorization-SuperUser-ResourceId (+ResourceType USER/DOC), X-Authorization-Passport, driverId, X-Container-Id (tenant swaps: superhuman/coda/other ids), X-Client-Type variations (denali_editor, ai_editor, webeditor_chrome), X-Api-Version (1,2,3).
- **Path tricks**: `;` matrix params, `%2f`, `%2e%2e`, double slashes, trailing slashes, case variations, `..;/`, unicode.
- **Body overrides**: POST /documents with `user_id`, `owner_id`, `demo:true`, arbitrary title/content (server overrides identity).
- **WS variants**: `/documents/{id}/ws?userId=`, `?uid=`, `?owner=`, `?share=1`, `?demo=true`, `?sinceVersion=`, `/users/{id}/documents/{id}/ws`, `/documents/ws` (new doc), accessToken JWT (not yet minted), Sec-WebSocket-Protocol.
- All failed: identity always from session; T≡R on every path.

### 5.4 coda.grammarly.com full fuzz
- All internalAppApi doc paths (see §3.2) with correct CSRF + X-Auth-User-Id: target 403/404 ≡ random.
- SSR HTML diffing: `/d/_d1198436185` vs `/d/_d9999999999` — byte-identical "Request access" pages (31,227 bytes on docs.superhuman.com; 25,741 bytes on coda.grammarly.com — compared full HTML, no metadata leak).
- doclist viewType enumeration via schema error (all 8 valid values; SHARED empty).
- search2 with `docSearchPermissionContextType: "User"` (empty corpus) and `"FullCorpus"` (blocked on prod).
- Collab socket: full handshake with (control,myUid), (target,myUid), (target,ownerUid 1411519194), (random,myUid) — handshake sid granted for ALL; subscription: control OK, target/random 404, target+ownerUid 404.
- subscribe-to-objects with `{"objectStubDocIds":["<id>"]}` — 404 for wrong stub format; learned correct flow.
- Origin/CSRF matrix on /importdoc/*: coda origin + coda CSRF → migrate 403; app origin → 400 InvalidCsrfToken (origin-scoped CSRF); missing CSRF → 400 SPA Error; no Origin (curl) → 400 InvalidOriginOrReferer.
- Superuser/passport headers on migrate (see §5.6).

### 5.5 docs.superhuman.com full fuzz
- resolveBrowserLink oracle for: `https://docs.superhuman.com/d/_d1198436185`, `https://coda.io/d/_d1198436185`, `https://docs.superhuman.com/d/1198436185` (400 invalid URL), `https://coda.io/d/1198436185` (400) — all → not exist (or 400 for wrong formats).
- /api/document for: 1198436185, _d1198436185, zzzzzzzzzz, 9999999999 — all 404 ≡.
- v1 API docs/{id} with Bearer token for 1198436185, _d1198436185, dnt6_6EOfDO — target/random 404; own 200.
- oembedResolve, thumbnail, embed, publish paths — 404/400.
- docaccess POST with stale session — 302 to mediator (session expired mid-engagement; fresh-session target-vs-random test still pending).
- importdoc namespace with stale session — 400/401 (fresh-session test pending).

### 5.6 Impersonation/superuser attempts (all rejected)
On dox REST+WS, coda internalAppApi, migrate, settings-registry:
`X-Authorization-SuperUser-ResourceId: 1411519194`, `X-Authorization-SuperUser-ResourceType: USER`, `X-Authorization-Passport: 1411519194`, `X-Forwarded-User/Email`, `X-User-Id`, `X-Denali-User-Id`, `X-Impersonate`, `X-On-Behalf-Of`, `driverId`, body `userId` fields → all ignored/403/401.

### 5.7 Settings registry
- getSetting for own user: 200 `{"promoDocuments":{"seen":[],"created":[],"dismissed":[]}}` (needs x-container-id + x-client-type headers).
- getSetting for target/random users: 401 `{"error":"unauthorized"}`. No IDOR.
- Other keys probed: promoDocument, ProofreaderDemo, demoDoc, onboarding — ACL applies equally.
- GLOBAL scope probes: 401 (or empty) — config keys not enumerable anonymously.

### 5.8 Demo-doc / seed enumeration
- Created ~15 Coda docs via /newdoc with agentId/seedContentId combos: (proofreader, proofreaderDemo) → content-filled "Proofreader Demo"; (h1, h1_2026), (h1_ctf, ...), (canvas, ...), (multipage, ...), (demo, ...), (flag, ...), (ctf, ...), (2026, ...), (testagent, testseed) → all blank.
- Confirmed seed application is CLIENT-SIDE with hardcoded allowlist `["proofreaderDemo"]` (chunk 284 `SeedContentManager`); registry maps `proofreaderDemo` → server config `ProofreaderDemo` (title/icon/htmlContent) fetched via settings/config bootstrap.
- Determined dox demo doc ("Demo document", size 1076, demo:1) is auto-provisioned server-side at first login with fixed content (bulkAcceptDemoText) — identical for both test accounts.
- DELETE /documents/demo (batch) exists — demo docs are a tracked class.

### 5.9 CAPI / realtime
- capi WS protocol captured (start/submit_ot/suggestions) — no content channel.
- capi REST fuzz — no doc endpoints.
- dox WS protocol captured incl. incremental `sinceVersion`, `?accessToken` auth requirement, origin check, Quill ops format.

### 5.10 Misc
- Publish/embed/oEmbed/thumbnail/share-link formats on all tenants — no cross-user access.
- CloudFront signed URLs — not forgeable; only issued post-ACL.
- Inbox monitoring for share invites — none.
- Coda team/workspace invite flows — session-scoped.
- Google Groups access check ("Check group access" on Request-access page) — requires Google identity, not applicable.

---

## 6. REALTIME / WEBSOCKET PROTOCOL REVERSE ENGINEERING (exact frames)

### 6.1 dox.grammarly.com content channel
```
URL: wss://dox.grammarly.com/documents/<docId>/ws        (Origin: https://app.grammarly.com, cookies: grauth)
     wss://dox.grammarly.com/documents/<docId>/ws?accessToken=<JWT>
     wss://dox.grammarly.com/documents/ws                (new empty doc)
     ?sinceVersion=<n>                                   (incremental)
Server (no client message needed) → full doc on connect:
{"doc":{"ops":[{insert:"...",attributes:{...}},...]}, "doc_len":<n>, "title":"...", "vsn":<n>,
 "demo":0|1, "errors":<n>, "created_at":"...", "extra_params":{...}, "clientId":"...", "op":"init"}
Errors:
4001 {"error":"grauth or access token should be provided","code":4001}     (no auth)
4004 {"error":"Cannot find document for userId = <sessionUid>, docId = <id>","code":4004}   (close 4004)
```
Client submit (capi suggestion session) uses `{"id":0,"action":"start","client":"denali_editor","docid":"<id>",...}`.

### 6.2 coda.grammarly.com collab channel (socket.io v4, engine.io)
```
params = base64url(JSON({"documentId":"<docId WITHOUT leading d>","userId":<codaUid>,
                         "csrfToken":"<csrf>","docSocketProtocolVersion":70}))
URL: wss://coda.grammarly.com:443/collab/?params=<b64>&EIO=4&transport=websocket[&sid=<s>]
Flow (fresh connection):
  < 0{"sid":"...","upgrades":[],"pingInterval":25000,"pingTimeout":60000,"maxPayload":1000000}
  > 40
  < 40{"sid":"..."}
  > 40/document_server,
  < 40/document_server,{"sid":"..."}
  (then, for accessible docs, server pushes on its own):
  < 42/document_server,["subscribed",{"anonymize":false,"availabilityState":"ONLINE","connectionId":"...",
      "schemaVersion":177,"latestOpVersion":12,"latestOpId":"op-...","serverAppVersion":{...},
      "permissions":{"canEdit":true,"canComment":true,"canManage":true,"canShare":true,"canCopy":true,
      "canSuperAdmin":false,"canHide":false},"featureSetId":"..."}]
  (for inaccessible/unknown docs):
  < 42/document_server,["error",{"name":"HttpError","statusCode":404,"statusMessage":"Not Found","isDelayedError":true}]
  < 41  / 41/document_server,   (disconnect)
Client events: 42/document_server,["move-cursor",{cursor}], ["bulk-commit",{ops,schemaVersion,basisVersion,basisOpId,immediateSnapshot,sourceObjectId}],
               ["subscribe-to-objects",{"objectStubDocIds":[...]}], ["request-blob-auth-token",{docId?}]
Server events (enum names): subscribed, cursor, applyOps, objectSubscribed, objectSubscribeError, latestOpVersion,
               applySnapshotDelta, workspaceUserPermissionsUpdated, mentionsUpdated, packSubscribed, blobAuthTokenRefreshed...
```
Key: **handshake accepts ANY documentId+userId** (no validation at connect); the subscription resolves the doc against the SESSION user. Target rejected even with owner's userId.

### 6.3 logging socket
Same scheme, namespace `/logger_server`; events `["event",{...}]` → `["processingComplete",id]`.

---

## 7. CLIENT-SIDE JS REVERSE ENGINEERING (exact findings & file locations)

### 7.1 Denali (app.grammarly.com) bundles — `/tmp/opencode/agent-b/js/`
- **`dyn/70a9f628c6cca42a57a8_default-ae.js` (module 29630, `AiEditorClientImpl`)** — the AI-editor API client:
  - `createDocument()` → `POST {url}/newdoc/Untitled%20document?openDocument=false` (confirmed 200; returns documentId+initContext)
  - `migrateDocument(e)` → `POST {url}/importdoc/migrate` body `{"grammarlyUserId":Number(sessionUid),"grammarlyDocumentId":Number(e.id)}`
  - `_prepareImportDocument` → `POST {url}/importdoc/prepare/v2`; `_completeImportDocument` → `POST {url}/importdoc/complete/v2`; `_uploadFileToS3` → PUT to returned uploadUrl with authorizedHeaders
  - `listOwnedDocuments/listAllDocuments` → `GET {url}/internalAppApi/doclist/recent?...viewType=OWNED_NON_DELETED|ALL_DOCS`
  - `downloadInFormat` → export workflow (export → workflows/{id}/isComplete → export/{wfId}/url)
  - `_url` = `aiEditor.documentURL` = **`https://coda.grammarly.com`** (config in `72baf6b45ccb636a41d5_vendor-*.js`)
  - URL builder `tM.post(base, ...segments)` joins with `/` and normalizes (module 72936 in same vendor chunk).
- **`9883edde5beaebfb726e_default-i~nd~e~ae~cb~as~a.js`** — experiments module 16843: `AiEditorMigrationInternal = new iD("ai_editor_migration_internal","enabled")`, `AiEditorPromoDocPreFilter = new iD("ai_editor_demo_doc_h1_2026_prefilter","enabled")`, `CodaNamedExport`, `AiEditorPdfImportInternal`, etc.
- **`277669f7567c4497e8cc_default-i~cb.js`** — docs-list UI: `denaliMigrationEnabled = isQuery("denaliMigration") || isManakin(AiEditorMigrationInternal)`; promo tile config module 13620: `{id:"proofreaderDemo", agentId:"proofreader", seedContentId:"proofreaderDemo"}`; Migrate button → `documentsPage.actions.migrateDocument(doc)` then navigate to editor.
- **`adb90b8ed1a7d0f4b813_default-i.js`** — promo-doc model: enabled iff `aiEditorVersion != Off && isGateEnabled(AiEditorPromoDocPreFilter) && getTreatment(AiEditorPromoDoc) === "test"` (AiEditorPromoDoc = `ai_editor_demodoc_h1_2026`); settings key `"promoDocument"` via settings registry; `isPristineDemoDocument = isDemo && title=="Demo document" && size==1076`.
- **`dyn/f5c2fe4ce0b3e8bc2ae6_demotxt.js` (module 44011)** — classic demo texts: `bulkAcceptDemoText` (matches dox demo doc content), `fullSentenceDemoText`, `mutedAlertsDemoText`, `listTransformDemoText`, `premiumDemoDocument`, `annotatorEmptyDocument`.
- **`ae38b67dbe0e4799b78a_vendor-i~nd~e~a.js`** — settings-registry client: `getSetting` = `GET {url}/settings/{key}/resource/{type}/{id}`; default URL `https://gateway{t}/settings-registry/v1`; resource types USER/INSTITUTION/USER_GROUP; also `getBatchSettings`, `getMergedSettings`, `saveBatchSettings` (`PUT /settings/batch/{type}`).
- **`72baf6b45ccb636a41d5_vendor-i~nd~e~ae~nf~dt~ci~cb~as~a.js`** — config: `aiEditor:{documentURL:"https://coda.grammarly.com",codaCdn:"https://cdn.coda.io"}`, settings registry base, tokens URL `https://tokens.grammarly.com`, proofit URL `/documents/{id}/proofread`.
- **`d2d09fa36d9d3912d18c_vendor-i~nd~e~ae~dt~cb~as~a.js`** — OAuth: `POST {tokensUrl}/oauth2/token` (refresh_token/authorization_code) and `/oauth2/exchange` (token-exchange grant, subject_token_type `urn:grammarly:params:oauth:token-type:grauth`); tokens cached `localStorage["grammarly.<clientId>.tokens"]`.
- **`7b0f3e4f6375fbb7b1d1_vendor-i~e~a~mga~ea~nda~aa.js`** — dox WS metadata parser: init payload fields (`demo`, `created_at`, `orig_filename`, `extra_params`, `proofit`, `title`, `errors`, `settings`).

### 7.2 Coda bundle — `/tmp/opencode/agents/agent-c/coda_browser.js` (12 MB)
- CSRF header constant: `"X-Csrf-Token"`; user header `"X-Auth-User-Id"`; container chain `"X-Container-Docs-Chain"`.
- Namespaces: `/collab` URL path ↔ socket.io namespace `/document_server`; `/logging/socket` ↔ `/logger_server`.
- Client events enum: `bulk-commit`, `move-cursor`, `request-blob-auth-token`, `subscribe-to-objects`.
- Seed manager (chunk 284, `SeedContentManager`): allowlist `["proofreaderDemo"]`; registry `{proofreaderDemo: config.ProofreaderDemo}`; inserts content via metadata POSTs + collab bulk-commit ops.
- `/importdoc/*` — NOT present in the Coda bundle (server-side-only routes; only the Denali client calls them).
- Importer surface: `/importers/imports/{id}`, `/importers/runningImports`, `/importers/imports/{id}/documents`, `/importers/notion/uploads/prepare` (different feature from importdoc).
- `importdoc` S3 host: `coda-us-west-2-prod-blobs-upload.s3-accelerate.amazonaws.com/migrations/blobs/{codaUserId}/<blobId>` — "migrations" bucket namespace.

### 7.3 docs.superhuman.com bundles — `/tmp/opencode/docsjs/`
- `browser.35bf0f458662c301.entry.js` (12 MB) + `website...` + `postload...` — same Coda codebase; API route list extracted (90 static routes + ~200 template routes) — see §3.3; `swapDocIdInUrl`/`DocId` formula helpers; CSRF header `X-Csrf-Token`, `X-Auth-User-Id`; internalAppApi route inventory incl. admin API (`/apis/admin/v1/organizations/{org}/workspaces/{ws}/docs/{doc}/acl/permissions/...` etc.).

---

## 8. EXPERIMENTS / FEATURE FLAGS DISCOVERED

Observed values for a fresh Superhuman-origin account (treatment/get, ai_editor client):
- `ai_editor_demo_doc_h1_2026` → **control_1** (this is `AiEditorPromoDoc`)
- `ai_editor_demo_doc_h1_2026_prefilter` → **enabled_1** (gate)
- `ai_editor_canvas_augmentation_h1_2026` → test_1 (+ gate enabled_1)
- `ai_editor_multipage_h1_2026` → test_1
- `ai_editor_migration_internal` → **NOT RETURNED** (gate off) for both webeditor_chrome and ai_editor client types
- Others present in the app's request list (~200 names incl. `ai_editor_doc_sharing`, `sh_docs_proofreader_enabled`, `notetaker_web_chat`, `resume_builder_*`, `citation_finder_ui_v2`, etc.)

Interpretation: the h1 demo doc is served through the `ai_editor_demodoc_h1_2026` treatment; the h1_ctf user is in `test` (flag doc = their demo doc). The migration gate is server-side and off for fresh accounts.

---

## 9. DEMO-DOC & SEED-CONTENT SYSTEM (fully mapped)

1. New Grammarly user → dox server auto-provisions `Demo document` (demo:1, size 1076, fixed bulkAcceptDemoText content). Same for every user.
2. AI-editor users in the `test` arm of `ai_editor_demodoc_h1_2026` see a "Proofreader Demo" promo tile in the docs list; clicking it → `POST /newdoc/Untitled%20doc?agentId=proofreader&seedContentId=proofreaderDemo` (form body `csrfToken=<csrf>`, Origin/Referer coda.grammarly.com) → 302 to `/d/<docId>`; the SPA then applies the seed content client-side from server config `ProofreaderDemo` (htmlContent) via metadata POSTs + collab bulk-commit.
3. Seed allowlist is hardcoded client-side: only `proofreaderDemo`. No H1/flag seed exists client-side.
4. The server config value `ProofreaderDemo` (with htmlContent) is fetched via the app bootstrap/settings — the exact fetch endpoint for the config value is the remaining unknown (settings-registry GLOBAL scope is ACL-blocked; candidate: app bootstrap `/api/initLoad` variant).

---

## 10. THE MIGRATION SYSTEM (intended-path candidate — detailed)

### 10.1 Client flow (Denali)
```
migrateDocument({grammarlyUserId: Number(sessionUserId), grammarlyDocumentId: Number(docId)})
→ POST https://coda.grammarly.com/importdoc/migrate     [client code has NO trailing slash → 404 in practice]
```
The migration UI: docs list → doc "More actions" → "Migrate" (visible only with `?exp=denaliMigration` or the internal gate). After migration, the doc appears in Coda with the original preserved ("migrated_doc_id", "migration_status" fields exist in the client model; dox tracks `not_migration_completed` filter).

### 10.2 Server behavior observed
| Request variant | Result |
|---|---|
| POST /importdoc/migrate/ (trailing slash) coda origin, full session, correct CSRF | **403 Forbidden** (text/plain) |
| POST /importdoc/migrate (no slash) | 404 (route only with slash) |
| POST /importdoc/migrate/ from app.grammarly.com origin | 400 `InvalidCsrfToken` (origin-scoped CSRF) |
| POST /importdoc/migrate/ no CSRF | 400 SPA Error (CSRF middleware) |
| POST /importdoc/migrate/ no Origin (curl) | 400 `InvalidOriginOrReferer` |
| Any body (own doc / target / random / string-typed ids / mixed uid+doc) | 403 (gate BEFORE doc lookup) |
| Any header set (x-client-type ai_editor/denali_editor, x-client-version, x-container-id, x-page-path, X-Auth-User-Id, X-Api-Version, superuser headers, passport) | 403 |
| GET/PUT/PATCH on the path | 403 |

### 10.3 Gate analysis
- The 403 is emitted by the Coda app middleware after CSRF+Origin validation, before any document access — consistent with a **server-side Statsig gate** (`ai_editor_migration_internal`) evaluated on the session user.
- The flag is OFF for both fresh accounts (treatment/get does not return it for either client type).
- Client-side UI gate can be bypassed with `?exp=denaliMigration`, proving the UI gate is not the blocker — the server gate is.

### 10.4 Why this is almost certainly the intended path
- The endpoint's contract takes BOTH `grammarlyUserId` AND `grammarlyDocumentId` from the client. During the dox→Coda migration period, the server must look up the legacy doc by exactly these two values — if it validates ownership against the session, fine; if it (incorrectly) trusts the body userId, **any authenticated user can migrate any user's document into their own Coda account** → flag. This is a textbook CTF design.
- The only missing piece is satisfying the 403 gate (see §12.2).

---

## 11. EVIDENCE FOR "WHERE THE FLAG LIVES"

1. **ID scheme**: challenge IDs (1198436185 / 1411519194) are numeric; dox uses numeric doc + user IDs; Coda tenants use base62 doc IDs and a different numeric user ID space. The Grammarly user ID space (10-digit) contains both values.
2. **Existence oracles**: resolveBrowserLink and every Coda API treat the target identically to random → the doc does not exist in any Coda tenant.
3. **dox scoping error message** embeds the lookup key: `Cannot find document for userId = <session>, docId = <target>` — proving the doc is looked up in the dox database by (userId, docId) — i.e., the database row for (1411519194, 1198436185) is what we need.
4. **Demo-doc provisioning + H1 experiment names** (ai_editor_demodoc_h1_2026, ..._prefilter, canvas_augmentation_h1_2026, multipage_h1_2026) tie the CTF to the demo-doc mechanism for the h1 user.
5. **Migration state tracking** (`not_migration_completed` filter, `/documents/migrate` batch route, `migration_status`/`migrated_doc_id` client fields) confirms the platform's own cross-system copy primitive for legacy docs.

---

## 12. WORKING HYPOTHESES (ranked)

1. **H1 — Migration IDOR (most likely intended)**: `POST /importdoc/migrate/` with `{"grammarlyUserId":1411519194,"grammarlyDocumentId":1198436185}` migrates the flag doc into the caller's Coda account. Blocked only by the 403 feature gate.
2. **H2 — Demo-doc provisioning flaw**: the h1 demo doc (1198436185) is provisioned via a server-side flow (agent/config). If the provisioning service accepts a target userId/docId (create-demo-for-user), or the flag seed config is readable, the doc can be recreated/read. Evidence: H1 experiment names; unknown: provisioning endpoint.
3. **H3 — Token-scoped dox access**: `wss://dox.grammarly.com/documents/1198436185/ws?accessToken=<JWT>` — the token path may scope userId from token claims differently than the cookie path (untested because token minting is WAF-gated).
4. **H4 — Import-as-migration**: `importdoc/complete/v2` (or prepare) may accept a `grammarlyDocumentId` to import a legacy doc directly, bypassing the gated `migrate` route (untested with real blob).
5. **H5 — Tenant flag difference**: docs.superhuman.com (Superhuman tenant) may run `importdoc` with a different (enabled) gate; fresh-session test pending.
6. **H6 — Share-link surface**: a fresh-session docaccess oracle or a share-link format probe on the target ID (e.g. `/d/<slug>_<id>?share=`, `/s/<token>`, publish preview) may reveal a public access path.

---

## 13. RECOMMENDED NEXT STEPS (priority order, with exact commands)

### 13.1 Mint a real access token (unlocks H3 + may unlock H1)
1. Capture the browser's own `POST https://tokens.grammarly.com/oauth2/exchange` (form-encoded, `X-CSRF-Token`, Origin/Referer app.grammarly.com) via network interception on an app.grammarly.com tab.
2. If direct calls are WAF-blocked, replay through the app origin (same-origin fetch from a tab) and read the JWT from the response.
3. Test:
   - `wss://dox.grammarly.com/documents/1198436185/ws?accessToken=<JWT>` vs control doc vs random (watch for 4004 vs content).
   - `Authorization: Bearer <JWT>` on `/importdoc/migrate/` and `/importdoc/prepare/v2`.

### 13.2 Defeat the migrate gate (H1)
- Query `treatment/get` for `ai_editor_migration_internal` with MORE client types and the Coda app's own flag-request path (coda.grammarly.com origin, x-client-type ai_editor).
- Probe Statsig override mechanisms: `?statsigOverride=`, `?exp=`, `localStorage` overrides, `X-Features` header, `X-Authorization-Passport` with a real passport (read the app's passport response), `X-Container-Id` tenant swap (e.g. a tenant where the gate is on), `X-Authorization-SuperUser-*` with valid formats.
- Try `POST /importdoc/complete/v2` with a real blob + `{"grammarlyUserId":1411519194,"grammarlyDocumentId":1198436185}` fields.
- Try `POST /importdoc/prepare/v2` with `grammarlyDocumentId` semantics.

### 13.3 Fresh-session Superhuman tenant (H5)
- Re-establish a docs.superhuman.com session; from that origin POST `/importdoc/migrate/` and `/importdoc/prepare/v2` with correct Origin/CSRF; compare gate behavior with coda.grammarly.com.
- Re-test `POST /docaccess/1198436185` vs `/docaccess/9999999999` with a valid session (existence oracle).

### 13.4 H1 demo-doc provisioning (H2)
- Inspect the app bootstrap response(s) (initLoad/config) for the `ProofreaderDemo` config object and its fetch endpoint.
- Probe settings-registry GLOBAL scope keys (`ProofreaderDemo`, `demoDoc`, `promoDocument`) with full app headers.
- Look for a dox "create demo doc" service call in the Denali bundles (`/documents` POST with demo semantics, agent service endpoints).

### 13.5 Share-link format probe (H6)
- On a control doc, create a share link via `/internalAppApi/documents/{id}/sharing` POST (`{"changes":[{"type":"Create","accessType":"View","anyone":true}]}`) and observe the returned link URL format; then probe the target ID in that format (e.g. `https://coda.grammarly.com/d/<id>?share=<token>`, `/s/<token>`, publish preview `/publish-preview/<id>`).

### 13.6 Monitoring
- Keep checking the disposable inboxes for share invitations (the CTF harness may share the doc to accounts at some trigger).

---

## 14. ARTIFACT & FILE LOCATION INDEX

- **Denali bundles (all webpack chunks)**: `/tmp/opencode/agent-b/js/` and `/tmp/opencode/agent-b/js/dyn/`
  - AI-editor client + migrate/import code: `dyn/70a9f628c6cca42a57a8_default-ae.js`
  - Experiments/promo gates: `9883edde5beaebfb726e_default-i~nd~e~ae~cb~as~a.js`
  - Docs-list UI + promo config: `277669f7567c4497e8cc_default-i~cb.js`
  - Promo-doc model: `adb90b8ed1a7d0f4b813_default-i.js` (and `dyn/f23794c08943e6e4bbef_my-grammarly-am.js`)
  - Demo texts: `dyn/f5c2fe4ce0b3e8bc2ae6_demotxt.js`
  - Settings-registry client: `ae38b67dbe0e4799b78a_vendor-i~nd~e~a.js`
  - OAuth/tokens client: `d2d09fa36d9d3912d18c_vendor-i~nd~e~ae~dt~cb~as~a.js`
  - Config (aiEditor.documentURL etc.): `72baf6b45ccb636a41d5_vendor-i~nd~e~ae~nf~dt~ci~cb~as~a.js`
  - dox WS metadata parser: `7b0f3e4f6375fbb7b1d1_vendor-i~e~a~mga~ea~nda~aa.js`
- **Coda bundle (12 MB, full client)**: `/tmp/opencode/agents/agent-c/coda_browser.js`
- **Seed manager chunk**: `/tmp/opencode/agents/agent-b2/seed_chunk_284.js`
- **docs.superhuman.com bundles**: `/tmp/opencode/docsjs/` (`browser.35bf0f458662c301.entry.js`, `website...`, `postload...`), extracted route lists `routes_browser.txt`/`routes_website.txt`
- **WS captures**: `wslog_control.json` (coda collab full duplex), `/tmp/opencode/agents/agent-e/` (`collab_probe.py`, `collab_listen.py`, `collab_idor.py`, `collab_probe2.py`)
- **dox WS/REST captures**: `/tmp/opencode/agent-b/` (`capture_control.json`, `dox_documents.json`), `/tmp/opencode/agents/agent-a/`, `/tmp/opencode/agents/agent-d/` (`dl_*.out`, `coda__d*.html`, `initload_1198436185.json`, `fuzz.out`)
- **Treatment responses**: `/tmp/opencode/agents/agent-a2/treatment_response_a2.json`, `coda_treatment_response.json`
- **SSR page captures**: `/tmp/opencode/agents/agent-d/coda__d1198436185.html`, `coda__d9999999999.html`, `coda__dnt6_6EOfDO.html`
- **Cookie jars (replay; refresh before use)**: `/tmp/opencode/cookies_gram.txt`, `/tmp/opencode/cookies_gram2.txt`, `/tmp/opencode/cookies.txt`, `/tmp/opencode/agents/agent-c/cookies_c.txt`
- **Preview.is RAG search-method archives**: `/home/cran/Documents/pentest/scripts/search_method`

---

## 15. PROTOCOL CHEATSHEETS (instant replay)

### dox WS — content channel
```
wss://dox.grammarly.com/documents/<docId>/ws            (Origin: https://app.grammarly.com, cookies)
wss://dox.grammarly.com/documents/<docId>/ws?accessToken=<JWT>
→ {"doc":{"ops":[...]}, "doc_len", "title", "vsn", "demo", "created_at", "extra_params", "clientId", "op":"init"}
4004 → not accessible/not found (identical for target & random)
```

### coda collab WS
```
params = base64({"documentId":"<id-without-d>","userId":<codaUid>,"csrfToken":"<csrf>","docSocketProtocolVersion":70})
wss://coda.grammarly.com/collab/?params=<b64>&EIO=4&transport=websocket
0{...} → "40" → 40{...} → "40/document_server," → 40/document_server,{...}
→ 42/document_server,["subscribed",{...}] (accessible) | ["error",{HttpError 404}] (not)
```

### migrate (gated)
```
POST https://coda.grammarly.com/importdoc/migrate/    (trailing slash REQUIRED)
X-CSRF-Token: <coda-scoped csrf> · Content-Type: application/json · Origin/Referer: https://coda.grammarly.com
{"grammarlyUserId":<num>,"grammarlyDocumentId":<num>}  → currently 403 for all
```

### import (works)
```
POST /importdoc/prepare/v2 {"fileName","payloadHash","contentType"} → {blobId, blobUploadUrlInfo}
PUT <uploadUrl> with authorizedHeaders → POST /importdoc/complete/v2 {blobId,...}
```

### experiments
```
POST https://gateway.grammarly.com/experimentation/treatment/get
x-csrf-token · x-client-type: ai_editor · x-client-version: 0.0.1 · x-page-path · referer · x-container-id
["ai_editor_migration_internal","ai_editor_demodoc_h1_2026","ai_editor_demo_doc_h1_2026_prefilter", ...]
```

### settings registry
```
GET https://goldengate.grammarly.com/settings-registry/v1/settings/{key}/resource/USER/{uid}
x-csrf-token · x-container-id · x-client-type: ai_editor · x-client-version: 0.0.1   (ACL-enforced)
```

---

## 16. OPEN QUESTIONS / UNKNOWNS

1. Is `ai_editor_migration_internal` ever ON for any account tier, and can its server-side evaluation be influenced (headers, overrides, passport, tenant)?
2. Does `importdoc/complete/v2` (or prepare) accept a legacy `grammarlyDocumentId` (migration-by-import)?
3. How is the h1 demo doc provisioned server-side, and is its content served by a shared/global config key?
4. Is there a legacy-docs share-link surface reachable via the modern apps (fresh-session docaccess oracle)?
5. Does the Superhuman tenant (docs.superhuman.com) run `importdoc` with an enabled gate?
6. What is the exact fetch path for the `ProofreaderDemo` config (htmlContent) — app bootstrap vs settings registry vs other?
7. Does the dox WS `?accessToken=` path resolve the user from token claims (vs cookie) — and does it change ACL behavior?
8. Could the flag be exposed through a share invitation emailed to fresh accounts by the CTF harness (inbox monitoring still running)?
