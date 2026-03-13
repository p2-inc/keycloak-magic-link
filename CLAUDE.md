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

The abstract base classes (`service/AbstractMagicLinkTest`, `web/AbstractMagicLinkTest`) share container lifecycle. `MagicLinkApiTest` inherits from the `service` variant and follows the full action-token redirect chain using `java.net.http.HttpClient` with cookie support (required because Keycloak 26.x routes through a required-action page that uses the `AUTH_SESSION_ID` cookie).

### Keycloak SPI Registration

Factories use `@AutoService` to generate `META-INF/services/` entries at compile time. No manual service files needed. The annotation processor is configured in `pom.xml`.

### Code Style

Code is formatted with `fmt-maven-plugin` (Google Java style). Run `mvn fmt:format` before committing. Logging uses `@JBossLog` (Lombok) which generates a `log` field backed by JBoss Logging.

---

## Magic Link v2

Parallel v2 implementation that coexists with v1 without any breaking changes.

### Why v2 exists

The original `MagicLinkActionTokenHandler` authenticates the user *directly* (bypasses the browser flow). This means `acr_values`, `ConditionalLoaAuthenticator`, and step-up authenticators cannot run. v2 solves this by returning a **standard OIDC authorization URL** — the full browser flow runs, including step-up authenticators.

### Credential transport: Infinispan + UUID reference

Keycloak silently truncates any OIDC parameter longer than 255 characters (`AuthzEndpointRequestParser`). A signed JWT is typically 500–700 characters and would be dropped. v2 therefore uses a **UUID reference in `login_hint`**:

1. `POST /magic-link-v2` generates a UUID, stores the credential data in `SingleUseObjectProvider` (Infinispan) under key `mlv2:data:{uuid}` with the requested TTL, and returns an OIDC auth URL with `login_hint=mlv2:{uuid}` (~42 chars — well within the limit).
2. `MagicLinkBFAuthenticator` reads `login_hint`, strips the `mlv2:` prefix, looks up the data map by UUID, validates expiry and client, enforces single-use if required, then calls `context.success()`.

This is the same security model as v1 action tokens: security comes from the UUID's 128-bit entropy plus Infinispan TTL and atomic single-use tracking — not from a cryptographic signature.

### New components

**`MagicLinkV2Token`** (`auth/token/MagicLinkV2Token.java`) — Plain data class (no JWT, no `DefaultActionToken`). Used internally to carry the credential fields:
- `userId`, `clientId`, `expiry` (Unix epoch seconds)
- `forceSessionLoa` (Integer, optional)
- `rememberMe`, `reusable`, `setEmailVerified` (Boolean, optional)

Also defines the `KEY_*` constants used as keys in the `SingleUseObjectProvider` notes map.

**`MagicLinkV2Resource`** (`resources/MagicLinkV2Resource.java`) — `POST realms/{realm}/magic-link-v2`. Requires `manage-users` role. Stores credential data in `SingleUseObjectProvider` and builds the OIDC auth URL with `login_hint=mlv2:{uuid}`. OIDC parameters (`redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, etc.) are passed via `additional_parameters`. Registered via `MagicLinkV2ResourceProviderFactory` (provider ID: `magic-link-v2`).

**`MagicLinkBFAuthenticator`** (`auth/MagicLinkBFAuthenticator.java`, provider ID: `ext-magic-link-browser-flow`) — Browser-flow authenticator. Place as **ALTERNATIVE** alongside username/password. When `login_hint` does not start with `mlv2:`, calls `context.attempted()` and passes through silently.

On a matching `login_hint`, it:
1. Strips `mlv2:` prefix to get the tokenId (UUID).
2. Calls `singleUse.get("mlv2:data:{tokenId}")` to fetch the notes map.
3. Validates expiry against stored `expiry` timestamp.
4. Validates stored `clientId` matches the client that started the flow.
5. For single-use (default): calls `singleUse.putIfAbsent("mlv2:used:{tokenId}", ttl)` — returns false if already used → `context.failure(INVALID_CREDENTIALS)`.
6. Resolves user by stored `userId`.
7. Optionally sets `user.setEmailVerified(true)` if `sev=true`.
8. Sets LOA via `AcrStore.setLevelAuthenticated()` — priority: stored `loa` > sibling `Condition – Level of Authentication`.
9. Sets remember-me auth note if `rememberMe=true`.
10. `context.success()` — subsequent step-up authenticators run in the same browser session.

### Key design decisions

**UUID in `login_hint`, not JWT.** Keycloak's 255-char limit on OIDC parameters makes a full JWT impractical (HS512 JWTs are typically 600+ chars and would be silently dropped). The UUID approach stays well within the limit and matches the security model of v1 action tokens.

**Token lifetime is configurable.** The TTL passed to `SingleUseObjectProvider.put()` is exactly `expiration_seconds` (default 300 s). Infinispan automatically expires the entry. The authenticator also cross-checks the stored `expiry` timestamp as a belt-and-suspenders guard.

**No action-token endpoint.** The magic link URL is a standard OIDC auth URL, not a `login-actions/action-token` URL. v1 is completely untouched.

**Caller owns OIDC parameters.** `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `acr_values`, etc. go in `additional_parameters` and are appended verbatim to the returned URL.

**`reusable` default is `false`** (single-use), opposite of the v1 default (`reusable=true`). This is the safer default.

**`setEmailVerified` default is `false`**, unlike the v1 handler which always sets it. The caller must explicitly opt in.

### LOA / step-up flow example

```
Browser Flow
└── Forms [ALTERNATIVE]
    ├── LOA=1 sub-flow [CONDITIONAL]
    │   ├── Condition – Level of Authentication (loa=1)
    │   └── Magic Link Verifier [ALTERNATIVE]  ← authenticates at LOA=1
    └── LOA=2 sub-flow [CONDITIONAL]
        ├── Condition – Level of Authentication (loa=2)
        └── Email OTP [REQUIRED]               ← runs after the verifier if LOA=2 requested
```

### Infinispan usage summary

| Component | When | Key | What |
|---|---|---|---|
| v2 `MagicLinkV2Resource` | on generation | `mlv2:data:{uuid}` | stores credential data map with TTL = `expiration_seconds` |
| v2 `MagicLinkBFAuthenticator` | on redemption | `mlv2:used:{uuid}` | `putIfAbsent` for single-use guard |
| v1 `MagicLinkActionTokenHandler` | on redemption | (Keycloak-managed jti) | marks action token as used |
