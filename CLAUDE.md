# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build (produces jar in target/)
mvn clean install

# Run all tests (integration tests use Testcontainers + Docker)
mvn test

# Run a single test class
mvn test -Dtest=MagicLinkApiTest

# Run a single test method
mvn test -Dtest=MagicLinkApiTest#createMagicLinkWithExplicitLoa_acrClaimMatchesRequestedLoa

# Format code (Google Java style via Spotless; ratcheted to files changed vs. origin/main)
mvn spotless:apply

# Build without running tests
mvn clean package -DskipTests

# Run with Cypress E2E tests (includes browser-level tests)
mvn test -Pcypress-tests
```

**Java 21** is required. Tests require Docker (Testcontainers spins up a real Keycloak container).

## Architecture Overview

This is a **Keycloak SPI extension** — a JAR deployed into a Keycloak server's `providers/` directory. It registers itself via `@AutoService` annotations and Java `ServiceLoader`. No Spring, no Quarkus application framework — everything runs inside Keycloak's runtime.

### Core Components

**`MagicLink.java`** — Central utility class. All shared logic for creating action tokens, sending emails, user resolution (`getOrCreate`), redirect URI validation, and default flow setup lives here. Both the authenticator and the REST resource delegate to this class.

**Magic Link authenticator path** (`src/main/java/.../auth/magic/`):
- `AbstractMagicLinkAuthenticatorFactory` — Base factory for all magic link authenticator variants. Takes a `MagicLinkCustomizationProviderFactory` at construction time; merges its config properties after the base `MagicLinkConfig` properties and passes it to `MagicLinkAuthenticator` so the customization provider is created per-authentication with the execution config map.
- `MagicLinkAuthenticatorFactory` (provider ID: `ext-magic-form`) — Default concrete factory. Uses `DefaultMagicLinkCustomizationProviderFactory` (all users allowed, standard email template). Registers `RealmPostCreateEvent` listener.
- `MagicLinkAuthenticator` — Extends `UsernamePasswordForm`. Resolves/creates users, delegates `canAuthenticate` and `sendMagicLinkEmail` to the active `MagicLinkCustomizationProvider`, creates a `MagicLinkActionToken`, and shows a waiting screen.
- `MagicLinkActionToken` — JWT subclass encoding OIDC params (`rdu`, `scope`, `state`, `nce`, `cc`, `ccm`, `rme`, `ru`, `rm`, `loa`, `eid`). Token type: `ext-magic-link`.
- `MagicLinkActionTokenHandler` / `MagicLinkActionTokenHandlerFactory` (provider ID: `ext-magic-link`) — Called when the magic link URL is visited. Bypasses the normal browser flow entirely, so it manually replicates what Keycloak's flow machinery would do: sets AMR via `AuthenticatorUtils.updateCompletedExecutions()`, sets LOA via `AcrStore.setLevelAuthenticated()`, and merges existing session state (LOA, AMR, remember-me) into the new `AuthenticationSession` when the browser already has an active session (session continuity).
- `MagicLinkConfig` — Typed wrapper around the authenticator config map. Config properties: `CREATE_NONEXISTENT_USER_CONFIG_PROPERTY`, `UPDATE_PROFILE_ACTION_CONFIG_PROPERTY`, `UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY`, `ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY`, `ACTION_TOKEN_LIFE_SPAN`.

**Magic Link customization extension point** (`src/main/java/.../auth/magic/spi/`):
- `MagicLinkCustomizationProvider` — Interface with two extension points: `canAuthenticate()` (gate user before token creation) and `sendMagicLinkEmail()` (custom email delivery).
- `MagicLinkCustomizationProviderFactory` — Plain Java interface (not a Keycloak `ProviderFactory`). Two methods: `getConfigProperties()` (properties appended to the authenticator's admin-console panel) and `create(session, authenticatorConfig)` (config-aware instantiation). Implementations are passed directly to `AbstractMagicLinkAuthenticatorFactory` constructors — no `@AutoService`, no service loader, no SPI registration required.
- `DefaultMagicLinkCustomizationProvider` / `DefaultMagicLinkCustomizationProviderFactory` — Built-in no-op implementation; allows all users and uses the standard `magic-link-email.ftl` template. Instantiated directly by `MagicLinkAuthenticatorFactory`.
- `MagicLinkCustomizationConfig` — Abstract base class for typed config wrappers used by customization providers.

**Active Org customization** (`src/main/java/.../auth/magic/spi/activeorg/`):
- `ActiveOrgMagicLinkAuthenticatorFactory` (provider ID: `ext-magic-active-org`, display name: **"Magic Link (Active Org)"**) — Concrete factory passing `ActiveOrgMagicLinkCustomizationProviderFactory` to the base.
- `ActiveOrgMagicLinkCustomizationProvider` — Checks the `org.ro.active` user attribute against the configured `ext-magic-org-id`; denies non-members with `ACCESS_DENIED`.
- `ActiveOrgMagicLinkCustomizationProviderFactory` — Exposes two admin-console properties: `ext-magic-org-id` (org to restrict to) and `ext-magic-org-require-membership` (toggle, default `true`). Instantiated directly by `ActiveOrgMagicLinkAuthenticatorFactory`.

**Continuation flow** (`src/main/java/.../auth/magic/continuation/`):
- `MagicLinkContinuationAuthenticatorFactory` (provider ID: `magic-link-continuation-form`) / `MagicLinkContinuationAuthenticator` — Extends `UsernamePasswordForm`. Shows `view-email-continuation.ftl` with a polling URL. The original browser tab polls for completion while the magic link is clicked on another device/tab.
- `MagicLinkContinuationActionToken` — Extends `DefaultActionToken`. Carries `sessionId`, `tabId`, and `redirectUri` for cross-browser scenarios.
- `MagicLinkContinuationLinkActionTokenHandler` / `MagicLinkContinuationActionTokenHandlerFactory` (provider ID: `magic-link-continuation`) — Handles the magic link click: marks the session as confirmed and returns a confirmation template.
- `MagicLinkContinuationStatusProvider` / `MagicLinkContinuationStatusProviderFactory` (provider ID: `magic-link-continuation`) — Public REST endpoint at `realms/{realm}/magic-link-continuation/{sessionId}/{tabId}/status`. Returns JSON `{ state: pending|confirmed|expired, expires_in: … }` for the polling tab.

**Other authenticators** (`src/main/java/.../auth/`):
- `EmailOtpAuthenticator` — Standalone 6-digit OTP via email.
- `LoginTokenVerifier` / `LoginTokenVerifierFactory` (provider ID: `login-token-verifier`, display name: **"Login Token (with login_hint)"**) — Reads `login_hint=lt:{uuid}` from the OIDC auth request and verifies the token. Passes through silently (`context.attempted()`) when `login_hint` is absent or has a different prefix.
- `LoginTokenFormAuthenticator` / `LoginTokenFormAuthenticatorFactory` (provider ID: `login-token-form`, display name: **"Login Token"**) — Shows a form for manual token entry. Accepts tokens with or without the `lt:` prefix. Shows a form error on invalid/expired tokens rather than falling through silently.
- `LoginTokenDirectGrantAuthenticator` (provider ID: `direct-grant-login-token`, display name: **"Login Token Direct Grant"**) — Redeems a Login Token in a Direct Grant (ROPC) flow via the `login_token` form parameter; no browser interaction. Returns standard OAuth2 error responses (`invalid_grant`) on failure.
- `LoginTokenHelper` — Package-private class with shared constants (`RESUME_PREFIX`, `DATA_KEY_PREFIX`, `USED_KEY_PREFIX`, auth-session note names) and shared static methods (`clearLoginHint`, `displayName`, `resolveLoaLevel`, `completeAuth`, `lookupAndValidate`, `verifyDirectGrant`) used by all Login Token authenticators.

**REST Resource path** (`src/main/java/.../resources/`):
- `MagicLinkResource` — `POST realms/{realm}/magic-link`. Requires `manage-users` role. Accepts `MagicLinkRequest`, resolves the `ext-magic-form` execution by `flow_id` to populate `executionId` on the token. Registered via `MagicLinkResourceProviderFactory` (provider ID: `magic-link`).

### Key Design Constraints

**Action tokens bypass the normal flow.** When `MagicLinkActionTokenHandler.handleToken()` runs, no authenticators execute — so `authenticators-completed` (AMR) and `LOA_MAP` (ACR) are never populated by Keycloak. The handler replicates these explicitly using internal Keycloak APIs.

**LOA precedence**: explicit `token.getLoa()` always wins over the level read from a sibling `ConditionalLoaAuthenticator` in the flow. The flow-derived level is only a fallback when `loa` is not set in the token.

**Session continuity**: Keycloak always creates a new `UserSession` when an action token is redeemed (the old identity cookie is replaced). The handler reads the existing session via `AuthenticationManager.authenticateIdentityCookie()` and copies its `LOA_MAP`, `authenticators-completed`, and `remember_me` notes into the new `AuthenticationSession`, taking the max LOA.

**`flow_id` vs. `flow_alias`**: The REST API accepts `flow_id` (the internal UUID), not the human-readable alias. The `resolveFlowId` helper in tests demonstrates how to look it up from the alias via the admin client.

### Test Infrastructure

Integration tests (`src/test/java/`) use:
- **Testcontainers + `testcontainers-keycloak`** — spins up a real Keycloak container (`quay.io/keycloak/keycloak:<version>`) with the extension loaded from `target/classes`.
- **Rest-Assured** — HTTP assertions against the live Keycloak.
- **Realm fixture JSON files** in `src/test/resources/realms/` — imported fresh per test, deleted in `@AfterEach`.

The abstract base classes (`service/AbstractMagicLinkTest`, `web/AbstractMagicLinkTest`) share container lifecycle. `MagicLinkResourceTest` inherits from the `service` variant and follows the full action-token redirect chain using `java.net.http.HttpClient` with cookie support (required because Keycloak 26.x routes through a required-action page that uses the `AUTH_SESSION_ID` cookie).

### Keycloak SPI Registration

Factories use `@AutoService` to generate `META-INF/services/` entries at compile time. No manual service files needed. The annotation processor is configured in `pom.xml`.

**`MagicLinkCustomizationProviderFactory` is not a Keycloak SPI provider.** It is a plain Java interface — no `@AutoService`, no service loader, no SPI registration. Implementations are instantiated directly inside `AbstractMagicLinkAuthenticatorFactory` subclass constructors and are invisible to Keycloak's provider registry. Only the `AuthenticatorFactory` subclass itself needs `@AutoService(AuthenticatorFactory.class)`.

### Code Style

Code is formatted with the Spotless Maven plugin (Google Java style, wildcard imports forbidden, ratcheted to files changed vs. `origin/main`). Run `mvn spotless:apply` before committing. Logging uses `@JBossLog` (Lombok) which generates a `log` field backed by JBoss Logging.

---

## Login Token

Login Token implementation that coexists with Magic Link v1 without any breaking changes.

### Why Login Token exists

The original `MagicLinkActionTokenHandler` authenticates the user *directly* (bypasses the browser flow). This means `acr_values`, `ConditionalLoaAuthenticator`, and step-up authenticators cannot run. Login Token solves this by returning a **standard OIDC authorization URL** — the full browser flow runs, including step-up authenticators.

### Credential transport: two token formats

Security guarantees, the threat model and open issues live in `SECURITY-DESIGN.md`. Update it in the same change whenever a guarantee, a rejection path, the wire format, key handling or logging of tokens changes.

Keycloak silently drops a `login_hint` longer than 255 characters (`AuthzEndpointRequestParser`). A signed JWT is typically 500–700 characters and would be dropped. Login Token therefore has two compact formats, told apart by the `login_hint` itself. Both go through the same pipeline in `LoginTokenHelper` — only credential resolution in `lookupAndValidate` differs.

**Stateless format (`lt:v2.{base64url}`)** — `StatelessLoginToken` packs the credential into a binary payload and encrypts it with AES-GCM (`salt[16] ‖ ciphertext ‖ tag[16]`, realm id as additional authenticated data). The realm key never encrypts directly: `HMAC-SHA512(realmKey, context ‖ salt)` yields a one-time AES key and nonce per token, which removes AES-GCM's per-key message limit — do not "simplify" this back to encrypting with the realm key. Nothing is stored at creation. The key comes from the realm key provider(s) **named `login-token`** (`aes-generated`, priority below 100), resolved by `LoginTokenKeys`: highest-priority active key encrypts, every enabled key decrypts (rotation). Issued when the request sets `legacy: false`, or when it omits `legacy` and the SPI option `--spi-realm-restapi-extension--login-token--legacy=false` is set (default `legacy=true`). If the realm has no provider of that name, `LoginTokenKeys.ensureEncryptionKey` creates one on the first stateless mint — in its own transaction and under a component id derived from the realm id, so concurrent requests on any node cannot create two. A provider that exists but is disabled is never replaced (that is the per-realm off switch). If no key is available or the payload does not fit, `LoginTokenResource` falls back to a legacy token — issuing never fails because of the format, and every fallback is logged as a rate-limited ERROR (`logFallback`) because it silently brings back the memory problem. A legacy token id is only looked up if it is a UUID (`StatelessLoginToken.isLegacy`) — attacker-controlled input must never become a single-use store key (ids ending in `.revoked` made Keycloak throw). Never log a token id of either format — both are bearer credentials; use `StatelessLoginToken.logId` (salt prefix, first UUID block, or `<malformed:len>`).

**Legacy format (`lt:{uuid}`)** — a UUID reference to a credential kept in Infinispan. Still the default and must keep working, including notes written by plugin versions that predate `max_uses`:

1. `POST /login-token` generates a UUID, stores the credential data in `SingleUseObjectProvider` (Infinispan) under key `lt:data:{uuid}` with the requested TTL, and returns `{ "login_hint": "lt:{uuid}" }`. The caller constructs the full OIDC auth URL — owning PKCE, `redirect_uri`, `state`, `nonce`, etc.
2. `LoginTokenVerifier` reads `login_hint`, strips the `lt:` prefix, looks up the data map by UUID, validates expiry and client binding, enforces the use limit, then calls `context.success()`.

Security of the legacy format comes from the UUID's 128-bit entropy plus the Infinispan TTL; security of the stateless format from the AES-GCM key. Both use the same atomic use tracking.

**Why both exist:** the legacy format holds every issued token in the unbounded, in-memory `actionTokens` cache (two copies per entry) until it expires, so memory grows with tokens issued × lifetime — untenable for campaigns issuing millions of week-long tokens. See README "Token formats: stateless and legacy".

**Use limit (`max_uses`):** `0` = unlimited (default), `1` = single use, up to `StatelessLoginToken.MAX_USES_LIMIT` (10). The legacy request field `reusable` keeps its exact old semantics (default `true` = unlimited; `false` or explicit `null` = single use), and unlimited legacy tokens still get the `reusable=true` note so pre-`max_uses` nodes read them correctly. `LoginTokenHelper.reserveUse` claims one slot per redemption with `putIfAbsent` — `lt:used:{useId}` for the first, `lt:used:{useId}:{n}` for the n-th — because `putIfAbsent` is the only atomic primitive `SingleUseObjectProvider` offers. `useId` is the UUID of a legacy token and the salt of a stateless one. Markers live until `USE_MARKER_GRACE_SECONDS` (60 s) after the token expires, so they can never expire first. They are in-memory only: after a full cluster restart a use-limited stateless token can be redeemed again (a legacy token is gone with its markers) — accepted as an open issue for now, documented in README "Use limits and cluster restarts". An exhausted token is handled like an invalid one (`onInvalidToken`), never via `context.failure`, which would let the flow fall through with the token still in `login_hint` and prefill the username form with it. The first slot keeps the pre-`max_uses` key so old and new nodes agree during a rolling upgrade. Notes without `maxUses` (old versions) fall back to the `reusable` note.

### New components

**`LoginToken`** (`auth/token/LoginToken.java`) — Plain data class (no JWT, no `DefaultActionToken`). Used internally to carry the credential fields:
- `userId`, `expiry` (Unix epoch seconds)
- `clientId` (optional; absent = unbound "universal" token)
- `forceSessionLoa` (Integer, optional)
- `rememberMe`, `reusable`, `setEmailVerified` (Boolean, optional)
- note key `maxUses` (use limit; supersedes `reusable`)

Also defines the `KEY_*` constants used as keys in the `SingleUseObjectProvider` notes map.

**`LoginTokenResource`** (`resources/LoginTokenResource.java`) — `POST realms/{realm}/login-token`. Requires `manage-users` role. `client_id` is optional: when present, it must reference an existing client and the token is bound to it; when absent, an unbound "universal" token is minted. Returns `{ "login_hint": "lt:v2.…" }` for a stateless token or stores the credential in `SingleUseObjectProvider` and returns `{ "login_hint": "lt:{uuid}" }` for a legacy one. Rejects `max_uses` outside 0–10 and non-positive `expiration_seconds` with 400. The caller is responsible for building the full OIDC auth URL with PKCE, `redirect_uri`, `state`, `nonce`, etc. Registered via `LoginTokenResourceProviderFactory` (provider ID: `login-token`).

**`LoginTokenHelper`** (`auth/LoginTokenHelper.java`) — Package-private helper. Holds all shared constants (`RESUME_PREFIX = "lt:"`, `DATA_KEY_PREFIX = "lt:data:"`, `USED_KEY_PREFIX = "lt:used:"`, auth-session note names) and all stateless utility methods shared by both Login Token authenticators:

| Method | Description |
|--------|-------------|
| `handleTokenId(ctx, tokenId, onInvalidToken, onAutoLogout)` | Full verification pipeline: Infinispan lookup → expiry → client → user → cookie user-switch. `onInvalidToken` (Runnable) handles not-found/expired/mismatch differently per authenticator. `onAutoLogout` (Consumer\<String\>, nullable) is called when `confirmUserSwitch=false`; pass `null` to always show the confirmation form. |
| `handleUserSwitchAction(ctx, pendingToken, onLogout)` | Dispatches the user-switch form submission: `action=logout` → `onLogout`, anything else → `failWithAccessDenied`. |
| `redirectAfterLogout(ctx, tokenId, loginHint)` | Expires identity + auth-session cookies and redirects to a fresh OIDC auth URL. The `loginHint` string is the only difference between the two authenticators: verifier passes the original `login_hint` from the auth session; form passes a reconstructed `"lt:" + tokenId`. |
| `showUserSwitchForm(ctx, tokenId, current, target)` | Sets auth-session notes and renders `login-token-user-switch.ftl`. |
| `failWithAccessDenied(ctx)` | Redirects to `redirect_uri?error=access_denied` and calls `context.failure()` with a response to abort the flow immediately. |
| `completeAuth(ctx, tokenId, notes, expiryStr, user)` | Single-use enforcement, user/LOA/remember-me setup, `context.success()`. |
| `clearLoginHint(ctx)` | Removes `login_hint` client note and attempted-username auth note. |
| `resolveLoaLevel(ctx, notes)` | Reads LOA from token notes, falls back to sibling conditional, defaults to 1. |
| `displayName(user)` | Returns email if set, otherwise username. |
| `lookupAndValidate(ctx, tokenId)` | Shared resolution for browser + direct-grant paths: Infinispan lookup → expiry → client binding → user. Returns a `ResolvedToken` (OK / INVALID / USER_DISABLED); never touches the flow context. |
| `isClientBindingRequired(ctx)` | Reads the `ext-login-token-require-client-binding` execution config; defaults to `true` when unset. |
| `verifyDirectGrant(ctx, tokenId)` | Non-interactive pipeline for the Direct Grant authenticator: `lookupAndValidate` → single-use → `context.success()`. Returns `null` on success or a `DG_*` error code. |

**`LoginTokenVerifier`** (`auth/LoginTokenVerifier.java`, provider ID: `login-token-verifier`, UI display name: **"Login Token (with login_hint)"**) — Browser-flow authenticator. Place as **ALTERNATIVE** before Cookie. When `login_hint` does not start with `lt:`, calls `context.attempted()` and passes through silently.

On a matching `login_hint`, it:
1. Strips `lt:` prefix to get the tokenId (a UUID, or `v2.…` for a stateless token).
2. Resolves the notes map: `singleUse.get("lt:data:{tokenId}")` for a legacy token, `StatelessLoginToken.open(...)` for a stateless one.
3. Validates expiry against the `expiry` timestamp in the notes.
4. Validates the client binding: a stored `clientId` must match the client that started the flow (always enforced); a token without `clientId` is only accepted when the execution's "Client ID must match" config (`ext-login-token-require-client-binding`) is `false`.
5. For use-limited tokens (`max_uses` ≥ 1): claims a slot via `reserveUse` — no free slot → `context.failure(INVALID_CREDENTIALS)`. Unlimited tokens (the default) store nothing.
6. Resolves user by stored `userId`.
7. Optionally sets `user.setEmailVerified(true)` if `sev=true`.
8. Sets LOA via `AcrStore.setLevelAuthenticated()` — priority: stored `loa` > sibling `Condition – Level of Authentication`.
9. Sets remember-me auth note if `rememberMe=true`.
10. `context.success()` — subsequent step-up authenticators run in the same browser session.

**`LoginTokenFormAuthenticator`** (`auth/LoginTokenFormAuthenticator.java`, provider ID: `login-token-form`, UI display name: **"Login Token"**) — Shows a Freemarker form (`login-token-form.ftl`) for manual token entry. Accepts the token with or without the `lt:` prefix. On invalid/expired token shows the form with an error (never falls through silently). When a user-switch is needed, always shows the confirmation dialog (auto-logout is suppressed in interactive form context); after confirmation redirects to a fresh OIDC auth URL with `login_hint=lt:{tokenId}` so `LoginTokenVerifier` can complete the flow if present.

### Key design decisions

**Compact token in `login_hint`, not JWT.** Keycloak's 255-char limit on `login_hint` makes a full JWT impractical (HS512 JWTs are typically 600+ chars and would be silently dropped). The legacy UUID reference is 39 characters, a stateless token 85–115.

**Token lifetime is configurable.** `expiration_seconds` (default 300 s). For a legacy token it is the TTL passed to `SingleUseObjectProvider.put()`, and the stored `expiry` timestamp is cross-checked as a belt-and-suspenders guard. For a stateless token the encrypted `expiry` is the only enforcement. Use markers live for the token's remaining lifetime.

**No action-token endpoint.** The login token URL is a standard OIDC auth URL, not a `login-actions/action-token` URL. Magic Link v1 is completely untouched.

**Caller owns all OIDC parameters.** `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `acr_values`, `prompt=login`, etc. are the caller's responsibility. The endpoint returns only the `login_hint` value; the caller constructs the full OIDC auth URL. This ensures the entity generating the PKCE `code_verifier` is always the same entity that handles the authorization code callback — required for both same-device and cross-device (email) flows.

**Client binding is optional but sticky.** `client_id` on `POST /login-token` is optional. When present, the binding is *always* enforced on redemption — no authenticator configuration can bypass it. When absent, the token is unbound ("universal", e.g. for QR-code login where the redeeming app is not known at generation time) and is only accepted by executions whose "Client ID must match" toggle (`ext-login-token-require-client-binding`, exposed by all three Login Token authenticator factories, default `true`) is set to `false`. Recommended for unbound tokens: short `expiration_seconds`, `max_uses=1`. See README "Client binding / universal tokens" for the threat model.

**`reusable` default is `true`** (reusable), matching the v1 default.

**`setEmailVerified` default is `false`**, unlike the v1 handler which always sets it. The caller must explicitly opt in.

### LOA / step-up flow example

```
Browser Flow
└── Forms [ALTERNATIVE]
    ├── LOA=1 sub-flow [CONDITIONAL]
    │   ├── Condition – Level of Authentication (loa=1)
    │   └── Login Token Verifier [ALTERNATIVE]  ← authenticates at LOA=1
    └── LOA=2 sub-flow [CONDITIONAL]
        ├── Condition – Level of Authentication (loa=2)
        └── Email OTP [REQUIRED]                ← runs after the verifier if LOA=2 requested
```

### Infinispan usage summary

| Component | When | Key | What |
|---|---|---|---|
| `LoginTokenResource` | on generation | `lt:data:{uuid}` | stores credential data map with TTL = `expiration_seconds` |
| `LoginTokenVerifier` / `LoginTokenFormAuthenticator` | on redemption | `lt:used:{uuid}` | `putIfAbsent` for single-use guard (via `LoginTokenHelper.completeAuth`) |
| v1 `MagicLinkActionTokenHandler` | on redemption | (Keycloak-managed jti) | marks action token as used |
