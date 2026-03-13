> :rocket: **Try it for free** in the new Phase Two [keycloak managed service](https://phasetwo.io/?utm_source=github&utm_medium=readme&utm_campaign=keycloak-magic-link). See the [announcement and demo video](https://phasetwo.io/blog/self-service/) for more information.

# keycloak-magic-link

Magic link implementation. Inspired by the [experiment](https://github.com/stianst/keycloak-experimental/tree/main/magic-link) by [@stianst](https://github.com/stianst).
It comes in two types: magic link and magic link continuation;

There is also a simple Email OTP authenticator implementation here.
This extension is used in the [Phase Two](https://phasetwo.io) cloud offering, and is released here as part of its commitment to making its [core extensions](https://phasetwo.io/docs/introduction/open-source) open source. Please consult the [license](COPYING) for information regarding use.

## Quick start

The easiest way to get started is our [Docker image](https://quay.io/repository/phasetwo/phasetwo-keycloak?tab=tags). Documentation and examples for using it are in the [phasetwo-containers](https://github.com/p2-inc/phasetwo-containers) repo. The most recent version of this extension is included.

## Magic link

This implementation differs from the original in that it creates an ActionToken that is sent as the link. This is convenient, as it does not require the user to click on the link from the same device. A common use case we heard was users entering their email address on the desktop, but then clicking on the link on their mobile, so we wanted to solve for that case.

This contains two pathways to get a Magic Link:

### Authenticator

An Authenticator that can run as a form in your login flow. This takes an email, and can optionally create a user if none exists. This implementation sends the email using a theme-resources template, which you can override. Installation can be achieved by duplicating the Browser flow, and replacing the normal Username/Password/OTP forms with the Magic Link execution type ([@tstec-polypoly](https://github.com/tstec-polypoly) provides a great step-by-step guide for setting it up https://github.com/p2-inc/keycloak-magic-link/issues/6#issuecomment-1230675741). Note that you aren't required to use a _Username form_ with this, as it extends `UsernamePasswordForm` and renders the username form page for you:

![Install Magic Link Authenticator in Browser Flow](docs/assets/magic-link-authenticator.png)

The authenticator can be configured to create a user with the given email address as username/email if none exists. It is also possible to force `UPDATE_PROFILE` and `UPDATE_PASSWORD` required actions when the user is created by this Authenticator:

![Configure Magic Link Authenticator with options](docs/assets/magic-link-config.png)

## Magic link continuation

This Magic link continuation authenticator is similar to the Magic Link authenticator in implementation, but has a different behavior. Instead of creating a session on the device where the link is clicked, the flow continues the login on the initial login page. The login page is polling the authentication page each 5 seconds until the session is confirmed or the authentication flow expires. The default expiration for the Magic link continuation flow is 10 minutes.

### Authenticator

![Install Magic Link continuation Authenticator in Browser Flow](docs/assets/magic-link-continuation-authenticator.png)

The authenticator can be configured to set the expiration of the authentication flow.

![Configure Magic Link continuation Authenticator with options](docs/assets/magic-link-continuation-config.png)

When the period is exceeded the authentication flow will reset.

![Magic Link continuation expired](docs/assets/magic-link-continuation-expiration.png)

### Keycloakify Theme Templates

If you are using Keycloakify and need the templates, you can find them in our Keycloakify Starter [fork](https://github.com/p2-inc/keycloakify-starter/tree/p2/magic-link-extension-templates) (go into the [pages](https://github.com/p2-inc/keycloakify-starter/tree/p2/magic-link-extension-templates/src/login/pages) folder).

### Resource

A Resource you can call with `manage-users` role, which allows you to specify the email, clientId, redirectUri, tokenExpiry and optionally if the email is sent, or the link is just returned to the caller.

Resources created with this API method return a URL that uses an Action Token. This will log a user in directly and skip any Authentication Flows defined.

Parameters:
| Name | Required | Default | Description |
| ----- | ----- | ----- | ----- |
| `email` | Y | | Email address associated with the User to create the magic link for. |
| `username` | N | | Username of the User to create the magic link for. Ignores email and forces `force_create`, `update_profile`, `update_password` and `send_email` to `false` if set. |
| `client_id` | Y | | Client ID the user will be logging in to. |
| `redirect_uri` | Y | | Redirect URI. Must be valid for the given client. |
| `expiration_seconds` | N | 86400 (1 day) | Amount of time the magic link is valid. |
| `force_create` | N | false | Create a user with this email address as username/email if none exists. |
| `update_profile` | N | false | Add an UPDATE_PROFILE required action if the user was created. |
| `update_password` | N | false | Add an UPDATE_PASSWORD required action if the user was created. |
| `send_email` | N | false | Send the magic link email using the built in template. |
| `scope` | N | | OIDC `scope` variable. |
| `nonce` | N | | OIDC `nonce` variable. |
| `state` | N | | OIDC `state` variable. |
| `code_challenge` | N | | OIDC `code_challenge` variable (for PKCE). |
| `remember_me` | N | false | If the user is treated as if they had checked "Remember Me" on login. Requires that it is enabled in the Realm. |
| `reusable` | N | true | If the token can be reused multiple times during its validity |
| `response_mode` | N | query | Determines how the authorization response is returned to the client: in the URL query string (query) or in the URL fragment (fragment). |

Sample request (replace your access token):

```
curl --request POST https://keycloak.host/auth/realms/test/magic-link \
 --header "Accept: application/json" \
 --header "Content-Type: application/json" \
 --header "Authorization: Bearer <access_token>" \
 --data '{"email":"foo@foo.com","client_id":"account-console","redirect_uri":"https://keycloak.host/auth/realms/test/account/","expiration_seconds":3600,"force_create":true,"update_profile":true,"update_password":true,"send_email":false}'
```

Sample response:

```
{
  "user_id": "386edecf-3e43-41fd-886c-c674eea41034",
  "link": "https://keycloak.host/auth/realms/test/login-actions/action-token?key=eyJhbG...KWuDyE&client_id=account-console",
  "sent": false
}
```

---

## Magic Link v2

Magic Link v2 is a drop-in parallel implementation that can be deployed alongside the existing Magic Link without any breaking changes or flow migration.

### Why v2?

The original Magic Link authenticates the user *directly* via the action-token handler, bypassing the standard Keycloak browser flow entirely. This means:

- `acr_values` / step-up authentication cannot be evaluated natively.
- Subsequent authenticators (e.g. TOTP for LOA=2) cannot run in the same browser session.

Magic Link v2 solves this by returning a **standard OIDC authorization URL** instead of an action-token URL. The credential is stored server-side in Infinispan; only a short UUID reference (`mlv2:{uuid}`) is placed in `login_hint`. The standard browser flow runs in full — `acr_values`, `Condition – Level of Authentication`, and all step-up logic work natively.

### How it works

```
POST /realms/{realm}/magic-link-v2
  → credential data (userId, clientId, expiry, optional LOA/rememberMe)
    stored in Infinispan under key "mlv2:data:{uuid}" with the requested TTL
  → returns: https://keycloak.host/realms/{realm}/protocol/openid-connect/auth
              ?client_id=myapp&response_type=code&login_hint=mlv2:{uuid}
              [+ any additional_parameters you supplied]

User (or app) opens the URL
  → standard OIDC browser flow starts
  → Magic Link Verifier (ext-magic-link-browser-flow) resolves the credential:
      1. Strips "mlv2:" prefix from login_hint to get the UUID
      2. Looks up credential data in Infinispan by "mlv2:data:{uuid}"
      3. Checks expiry (TTL-enforced by Infinispan + explicit timestamp check)
      4. Verifies stored clientId matches the current OIDC client
      5. Enforces single-use via putIfAbsent("mlv2:used:{uuid}", ttl)
         (unless reusable=true)
      6. Sets user, optional LOA, optional remember-me
      7. context.success() → flow continues normally
  → Any subsequent step-up authenticators run in the same browser session
```

> **Why UUID instead of a signed JWT?**  Keycloak silently ignores OIDC parameters longer than
> 255 characters. A typical HS512/RS256 JWT is 500–700 characters and would be dropped, causing
> authentication to fail silently. The UUID reference (`mlv2:{uuid}`) is ~42 characters.
> Security is equivalent to v1 action tokens: 128-bit random UUID entropy + Infinispan TTL +
> atomic single-use tracking.

### Browser flow setup

Add the **Magic Link Verifier** (`ext-magic-link-browser-flow`) as an **ALTERNATIVE** execution **before Cookie** in your browser flow. When `login_hint` does not start with `mlv2:`, the verifier calls `context.attempted()` and lets the next alternative (Cookie, then Username/Password) handle the request normally.

Placing the verifier _before_ Cookie is important: if Cookie runs first and finds an active session, Keycloak stops there and never reaches the verifier — meaning a magic link for User B would silently return User A's token.

```
Browser Flow
├── Magic Link Verifier (ext-magic-link-browser-flow)  [ALTERNATIVE]  ← add this, before Cookie
├── Cookie  [ALTERNATIVE]
├── Kerberos  [ALTERNATIVE]
└── Username/Password Form  [ALTERNATIVE]
```

For step-up / LOA flows, place the verifier inside a Conditional sub-flow:

```
Browser Flow
├── Magic Link Verifier (ext-magic-link-browser-flow)  [ALTERNATIVE]  ← before Cookie
├── Cookie  [ALTERNATIVE]
└── Authentication  [ALTERNATIVE]
    ├── LOA=1 sub-flow  [CONDITIONAL]
    │   ├── Condition – Level of Authentication  (loa=1)
    │   └── Magic Link Verifier  [ALTERNATIVE]   ← also here for LOA=1
    └── LOA=2 sub-flow  [CONDITIONAL]
        ├── Condition – Level of Authentication  (loa=2)
        └── Email OTP / TOTP  [REQUIRED]          ← runs after the verifier
```

When placed inside a Conditional sub-flow, the verifier automatically reads the configured LOA level from the sibling `Condition – Level of Authentication` as a fallback (overridden by `loa` in the API request).

### REST API — `/magic-link-v2`

Requires `manage-users` role (same as `/magic-link`).

**Parameters:**

| Name | Required | Default | Description |
| ----- | ----- | ----- | ----- |
| `email` | Y* | | Email address of the user. Mutually exclusive with `username`. |
| `username` | Y* | | Username of the user. When provided, `force_create` is ignored. |
| `client_id` | Y | | Client ID for which the authorization URL is built. |
| `expiration_seconds` | N | 300 (5 min) | Token validity in seconds. |
| `loa` | N | | Force the session to this LOA level, overriding the flow's Condition configuration. |
| `remember_me` | N | false | Set the remember-me flag on the session. |
| `force_create` | N | false | Create the user if they do not exist (email only). |
| `reusable` | N | false | Allow the token to be used more than once within its validity window. |
| `set_email_verified` | N | false | When `true`, marks the user's email as verified after the token is successfully validated. |
| `confirm_user_switch` | N | false | Controls behaviour when a different user is already logged in on the device. When `false` (default), the existing session is silently logged out and the magic link is processed automatically. When `true`, a confirmation screen is shown asking the user to approve the logout before continuing. |
| `redirect_uri` | N | | Redirect URI appended to the returned OIDC authorization URL. Takes precedence over the same key in `additional_parameters`. |
| `additional_parameters` | N | | Key/value map of extra query parameters appended to the returned URL (e.g. `scope`, `state`, `nonce`, `code_challenge`, `acr_values`). Values override defaults, including `prompt`. |

*One of `email` or `username` is required.

> **Important: place the Magic Link (v2) Verifier before the Cookie authenticator in your flow.**
> Keycloak evaluates ALTERNATIVE executions in order and stops at the first success. If Cookie
> runs before the Verifier and an active session exists, Keycloak silently returns that session's
> token — even if it belongs to a different user than the one in the magic link. Placing the
> Verifier first ensures it always gets to evaluate `login_hint` before Cookie can short-circuit
> the flow:
>
> ```
> Browser Flow
> ├── Magic Link (v2) Verifier  [ALTERNATIVE]  ← must be first
> ├── Cookie                    [ALTERNATIVE]
> ├── Kerberos                  [ALTERNATIVE]
> └── Username/Password         [ALTERNATIVE]
> ```

**Sample request:**

```
curl --request POST https://keycloak.host/realms/test/magic-link-v2 \
 --header "Accept: application/json" \
 --header "Content-Type: application/json" \
 --header "Authorization: Bearer <access_token>" \
 --data '{
   "email": "foo@example.com",
   "client_id": "myapp",
   "expiration_seconds": 300,
   "additional_parameters": {
     "redirect_uri": "https://myapp.example.com/callback",
     "scope": "openid profile",
     "state": "abc123",
     "nonce": "xyz789"
   }
 }'
```

**Sample response:**

```json
{
  "user_id": "386edecf-3e43-41fd-886c-c674eea41034",
  "link": "https://keycloak.host/realms/test/protocol/openid-connect/auth?client_id=myapp&response_type=code&login_hint=mlv2%3AeyJhbG...&redirect_uri=https%3A%2F%2Fmyapp.example.com%2Fcallback&scope=openid+profile&state=abc123&nonce=xyz789"
}
```

The caller opens `link` in the browser (or sends it to the user by email/SMS). Additional OIDC parameters not supplied via `additional_parameters` can be appended to the URL manually before opening it.

**PKCE** — pass `code_challenge` and `code_challenge_method` as `additional_parameters`:

```json
{
  "additional_parameters": {
    "redirect_uri": "...",
    "code_challenge": "<S256-challenge>",
    "code_challenge_method": "S256"
  }
}
```

### User-switch behaviour

When a magic link is opened for User B while User A is already logged in on the same device, the verifier detects the session conflict and handles it based on the `confirm_user_switch` parameter:

**Default (`confirm_user_switch: false`) — automatic logout:**
The existing session cookies are silently expired and the browser is redirected to a fresh OIDC authorization request. The magic link token is still valid (single-use mark is not set until authentication completes), so the fresh flow picks it up and logs User B in transparently — no screen is shown.

**`confirm_user_switch: true` — confirmation screen:**
A confirmation page is shown informing the user that they are currently signed in on this device and asking whether they want to continue. Two options are presented:
- **Sign out and continue** — performs the same automatic logout and redirect as the default behaviour.
- **Cancel** — aborts the flow and redirects back to the client with `error=access_denied`.

### Differences from Magic Link v1

| | Magic Link (v1) | Magic Link v2 |
|---|---|---|
| Endpoint | `POST /magic-link` | `POST /magic-link-v2` |
| Returned URL | Action-token URL (`login-actions/action-token?key=...`) | OIDC auth URL (`protocol/openid-connect/auth?...`) |
| Authentication | Direct — bypasses browser flow | Via browser flow — full flow executes |
| `acr_values` / step-up | Not supported | Fully supported |
| OIDC params in request | Supplied in API body | Supplied via `additional_parameters` or appended to URL |
| `redirect_uri` in request | Required | Optional — top-level field or via `additional_parameters` |
| `prompt=login` | Not set | Always set — prevents silent session reuse |
| `reusable` default | `true` | `false` (single-use) |
| User-switch (different user already logged in) | Not handled | Auto-logout by default; optional confirmation screen via `confirm_user_switch` |
| Flow authenticator required | No | Yes — Magic Link Verifier must be in the flow |
| Breaking change risk | — | None — v1 and v2 coexist independently |

---

## Email OTP

There is a simple authenticator to email a 6-digit OTP to the users email address. This implementation sends the email using a theme-resources template, which you can override. It is recommended to use this in an Authentication flow following the _Username form_. An example flow looks like this:
![Install Email OTP Authenticator in Browser Flow](docs/assets/email-otp-authenticator.png)

## Installation

1. Build the jar:

```
mvn clean install
```

2. Copy the jar produced in `target/` to your `providers` directory (for Quarkus) or `standalone/deployments` directory (for legacy) and rebuild/restart keycloak.

## Releases

Releases are tagged and published to [Maven Central](https://repo1.maven.org/maven2/io/phasetwo/keycloak/keycloak-magic-link/) after each merge to `main`. Jars can be downloaded from there.

If you are depending on the library in your own Maven-built project, or using a bundling tool in Maven, you can add the dependency like this:

```xml
    <dependency>
      <groupId>io.phasetwo.keycloak</groupId>
      <artifactId>keycloak-magic-link</artifactId>
      <version>VERSION</version>
    </dependency>
```

## Implementation Notes

This is a rough outline of the implementation:

- Given an email address
  - see if the email is already associated with a user
    - if yes, use that one
    - if not, create a user (this is configurable)
  - check to see if the redirectUri is valid for the client
    - if yes, continue
    - if not, throw an error
  - create an action token that encodes the user, expiry, clientId and redirectUri
  - action token handler needs to
    - invalidate the action token after single use
    - set the redirectUri
    - make sure to continue the login session after the handler

## Demo

User contributed POC using Jupyter: https://github.com/tstec-polypoly/explore-keycloak

---

All documentation, source code and other files in this repository are Copyright 2024 Phase Two, Inc.
