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

# Format code (Google Java style)
mvn fmt:format

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

**Authenticator path** (`src/main/java/.../auth/`):
- `MagicLinkAuthenticator` / `MagicLinkAuthenticatorFactory` (provider ID: `ext-magic-form`) — Browser-flow authenticator. Extends `UsernamePasswordForm`. On submit, creates a `MagicLinkActionToken` and emails the link. Also sets `executionId` on the token so AMR is populated correctly on redemption.
- `MagicLinkContinuationAuthenticator` — Variant where the original browser tab polls for completion while the link is clicked on another device.
- `EmailOtpAuthenticator` — Standalone 6-digit OTP via email.
- `LoginTokenVerifier` / `LoginTokenVerifierFactory` (provider ID: `login-token-verifier`, display name: **"Login Token (with login_hint)"**) — Reads `login_hint=lt:{uuid}` from the OIDC auth request and verifies the token. Passes through silently (`context.attempted()`) when `login_hint` is absent or has a different prefix.
- `LoginTokenFormAuthenticator` / `LoginTokenFormAuthenticatorFactory` (provider ID: `login-token-form`, display name: **"Login Token"**) — Shows a form for manual token entry. Accepts tokens with or without the `lt:` prefix. Shows a form error on invalid/expired tokens rather than falling through silently.
- `LoginTokenHelper` — Package-private class with shared constants (`RESUME_PREFIX`, `DATA_KEY_PREFIX`, `USED_KEY_PREFIX`, auth-session note names) and shared static methods (`clearLoginHint`, `displayName`, `resolveLoaLevel`, `completeAuth`) used by both Login Token authenticators.

**Action Token path** (`src/main/java/.../auth/token/`):
- `MagicLinkActionToken` — JWT subclass encoding all OIDC params (`rdu`, `scope`, `state`, `nce`, `cc`, `ccm`, `rme`, `ru`, `rm`, `loa`, `eid`). Token type: `ext-magic-link`.
- `MagicLinkActionTokenHandler` — Called when the magic link URL is visited. Bypasses the normal browser flow entirely, so it manually replicates what Keycloak's flow machinery would do: sets AMR via `AuthenticatorUtils.updateCompletedExecutions()`, sets LOA via `AcrStore.setLevelAuthenticated()`, and merges existing session state (LOA, AMR, remember-me) into the new `AuthenticationSession` when the browser already has an active session (session continuity).

**REST Resource path** (`src/main/java/.../resources/`):
- `MagicLinkResource` — POST endpoint at `realms/{realm}/magic-link`. Requires `manage-users` role. Accepts `MagicLinkRequest`, resolves the `ext-magic-form` execution by `flow_id` to populate `executionId` on the token.
- Registered via `MagicLinkResourceProviderFactory` (provider ID: `magic-link`).

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

### Code Style

Code is formatted with `fmt-maven-plugin` (Google Java style). Run `mvn fmt:format` before committing. Logging uses `@JBossLog` (Lombok) which generates a `log` field backed by JBoss Logging.

---

## Login Token

Login Token implementation that coexists with Magic Link v1 without any breaking changes.

### Why Login Token exists

The original `MagicLinkActionTokenHandler` authenticates the user *directly* (bypasses the browser flow). This means `acr_values`, `ConditionalLoaAuthenticator`, and step-up authenticators cannot run. Login Token solves this by returning a **standard OIDC authorization URL** — the full browser flow runs, including step-up authenticators.

### Credential transport: Infinispan + UUID reference

Keycloak silently truncates any OIDC parameter longer than 255 characters (`AuthzEndpointRequestParser`). A signed JWT is typically 500–700 characters and would be dropped. Login Token therefore uses a **UUID reference in `login_hint`**:

1. `POST /login-token` generates a UUID, stores the credential data in `SingleUseObjectProvider` (Infinispan) under key `lt:data:{uuid}` with the requested TTL, and returns `{ "login_hint": "lt:{uuid}" }`. The caller constructs the full OIDC auth URL — owning PKCE, `redirect_uri`, `state`, `nonce`, etc.
2. `LoginTokenVerifier` reads `login_hint`, strips the `lt:` prefix, looks up the data map by UUID, validates expiry and client, enforces single-use if required, then calls `context.success()`.

This is the same security model as v1 action tokens: security comes from the UUID's 128-bit entropy plus Infinispan TTL and atomic single-use tracking — not from a cryptographic signature.

### New components

**`LoginToken`** (`auth/token/LoginToken.java`) — Plain data class (no JWT, no `DefaultActionToken`). Used internally to carry the credential fields:
- `userId`, `clientId`, `expiry` (Unix epoch seconds)
- `forceSessionLoa` (Integer, optional)
- `rememberMe`, `reusable`, `setEmailVerified` (Boolean, optional)

Also defines the `KEY_*` constants used as keys in the `SingleUseObjectProvider` notes map.

**`LoginTokenResource`** (`resources/LoginTokenResource.java`) — `POST realms/{realm}/login-token`. Requires `manage-users` role. Stores credential data in `SingleUseObjectProvider` and returns `{ "login_hint": "lt:{uuid}" }`. The caller is responsible for building the full OIDC auth URL with PKCE, `redirect_uri`, `state`, `nonce`, etc. Registered via `LoginTokenResourceProviderFactory` (provider ID: `login-token`).

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

**`LoginTokenVerifier`** (`auth/LoginTokenVerifier.java`, provider ID: `login-token-verifier`, UI display name: **"Login Token (with login_hint)"**) — Browser-flow authenticator. Place as **ALTERNATIVE** before Cookie. When `login_hint` does not start with `lt:`, calls `context.attempted()` and passes through silently.

On a matching `login_hint`, it:
1. Strips `lt:` prefix to get the tokenId (UUID).
2. Calls `singleUse.get("lt:data:{tokenId}")` to fetch the notes map.
3. Validates expiry against stored `expiry` timestamp.
4. Validates stored `clientId` matches the client that started the flow.
5. For single-use (default): calls `singleUse.putIfAbsent("lt:used:{tokenId}", ttl)` — returns false if already used → `context.failure(INVALID_CREDENTIALS)`.
6. Resolves user by stored `userId`.
7. Optionally sets `user.setEmailVerified(true)` if `sev=true`.
8. Sets LOA via `AcrStore.setLevelAuthenticated()` — priority: stored `loa` > sibling `Condition – Level of Authentication`.
9. Sets remember-me auth note if `rememberMe=true`.
10. `context.success()` — subsequent step-up authenticators run in the same browser session.

**`LoginTokenFormAuthenticator`** (`auth/LoginTokenFormAuthenticator.java`, provider ID: `login-token-form`, UI display name: **"Login Token"**) — Shows a Freemarker form (`login-token-form.ftl`) for manual token entry. Accepts the token with or without the `lt:` prefix. On invalid/expired token shows the form with an error (never falls through silently). When a user-switch is needed, always shows the confirmation dialog (auto-logout is suppressed in interactive form context); after confirmation redirects to a fresh OIDC auth URL with `login_hint=lt:{tokenId}` so `LoginTokenVerifier` can complete the flow if present.

### Key design decisions

**UUID in `login_hint`, not JWT.** Keycloak's 255-char limit on OIDC parameters makes a full JWT impractical (HS512 JWTs are typically 600+ chars and would be silently dropped). The UUID approach stays well within the limit and matches the security model of v1 action tokens.

**Token lifetime is configurable.** The TTL passed to `SingleUseObjectProvider.put()` is exactly `expiration_seconds` (default 300 s). Infinispan automatically expires the entry. The authenticator also cross-checks the stored `expiry` timestamp as a belt-and-suspenders guard.

**No action-token endpoint.** The login token URL is a standard OIDC auth URL, not a `login-actions/action-token` URL. Magic Link v1 is completely untouched.

**Caller owns all OIDC parameters.** `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `acr_values`, `prompt=login`, etc. are the caller's responsibility. The endpoint returns only the `login_hint` value; the caller constructs the full OIDC auth URL. This ensures the entity generating the PKCE `code_verifier` is always the same entity that handles the authorization code callback — required for both same-device and cross-device (email) flows.

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
