# Login Token — Security Architecture and Threat Model

This document describes how Login Tokens are protected, what they guarantee, what they deliberately do not guarantee, and which issues are known and open. It covers both token formats. For usage, parameters and setup see the [Login Token section of the README](README.md#login-token).

Status: reflects the implementation as of 2026-11-24. Statements marked *verified* were confirmed by a test or an experiment against Keycloak 26.7.2; everything else follows from reading the code.

## 1. What a Login Token is

A Login Token is a **bearer credential**: whoever presents it is authenticated as the user it names, without a password. A backend with the `manage-users` role mints it through `POST /realms/{realm}/login-token` and passes the returned `login_hint` to a browser (OIDC authorization request) or to a direct grant. An authenticator in the flow redeems it.

Treat a Login Token like a password that is valid for one user, optionally one client, for a limited time and a limited number of uses.

| | Legacy format | Stateless format |
| --- | --- | --- |
| `login_hint` | `lt:{uuid}` | `lt:v2.{base64url}` |
| Credential | Stored in Keycloak's single-use object store; the token is a random reference to it | Encrypted inside the token |
| What protects it | 122 bits of randomness in the UUID | AES-256-GCM under a key derived from a realm key |
| Server state per issued token | One entry until expiry | None |

## 2. Assets, actors and trust boundaries

**Assets**

- User accounts of the realm: a redeemed token yields a session for its user.
- The realm's `login-token` AES key: whoever holds it can mint a valid stateless token for any user of that realm.
- Use markers: the record that a use-limited token has been redeemed.

**Actors**

| Actor | Trust | Capability |
| --- | --- | --- |
| Minting service | Trusted | Holds a service account with `manage-users`. Decides the user, client binding, lifetime, use limit, **level of authentication** and whether the email is marked verified. |
| Realm administrator | Trusted | `manage-realm`: can add, disable, delete or replace key providers. |
| Token recipient | Authenticates as one user | Receives the token in a link. Legitimately holds a credential for their own account. |
| Network or log observer | Untrusted | May see URLs, including `login_hint`, in mail, proxies, load-balancer logs, browser history or referrers. |
| Anonymous attacker | Untrusted | Can send arbitrary `login_hint` values to the public authorization endpoint. |

**Trust boundaries**

- The mint endpoint is authenticated and authorised (`manage-users`, never the master realm). Everything it is told is trusted, including a requested LoA.
- The authorization endpoint is public. Everything that arrives in `login_hint` is attacker-controlled.
- The realm key lives in the Keycloak database. Database access equals key access.

## 3. What is guaranteed

1. **A stateless token cannot be forged or altered without the realm key.** Any change to salt, ciphertext or tag is rejected. *Verified: every single-byte modification fails.*
2. **A stateless token cannot be read by its holder.** User id, client, expiry and flags are encrypted; only the random salt is visible.
3. **A token is only valid in the realm that issued it.** The realm id is authenticated with the token.
4. **A token bound to a client is only accepted for that client.** No authenticator configuration can relax a binding that is present. *Verified.*
5. **A token is not accepted after its expiry time.** *Verified.*
6. **While the cluster keeps running, a token is redeemed at most `max_uses` times,** including under concurrent redemption. *Verified with 40 parallel redemptions for both formats.*
7. **A token for a disabled or deleted user is rejected.** The user is looked up at redemption, so disabling the account revokes all of that user's tokens.
8. **A rejected token leaves no trace in the login page.** It is removed from `login_hint` and never offered as a username. *Verified for expired, unknown and exhausted tokens.*
9. **No token is written to the log in full by this plugin,** in either format, including malformed input. Every log statement goes through one redaction function, which is unit-tested.
10. **The legacy format behaves as it did before the stateless format existed,** including for notes written by older plugin versions.
11. **Input that is not a token is rejected before it touches any store.** *Verified.*

## 4. What is not guaranteed

These are properties of the design, not defects.

- **No per-token revocation for stateless tokens.** A single token cannot be withdrawn before it expires. Available levers: disable the user, or invalidate every stateless token of the realm (section 7).
- **No protection once the link leaks.** A token is a bearer credential. An observer who obtains a valid link can start an authorization request at the bound client and will be logged in as the user. Client binding, short lifetimes and use limits narrow the window; they do not close it.
- **The minting service is fully trusted.** It can assert any LoA (`loa`), mark an email as verified (`set_email_verified`) and create users (`force_create`). A compromised minting service is equivalent to a compromised `manage-users` account.
- **Unbound ("universal") tokens are valid at every client** whose execution accepts them. The least strictly configured such client defines the security level. See the README for recommendations.

## 5. Cryptographic design of the stateless format

```
lt:v2.<base64url( salt[16] ‖ ciphertext ‖ tag[16] )>
```

| Element | Choice | Reason |
| --- | --- | --- |
| Cipher | AES-256-GCM, 128-bit tag | Authenticated encryption: confidentiality and integrity in one primitive, available in the JDK. |
| Realm key | 256-bit AES key of a realm key provider named `login-token` (`aes-generated`) | Stored with the realm, identical on every node, separate from every other key Keycloak uses. |
| Per-token key | `HMAC-SHA512(realm key, context ‖ salt)` → 32-byte AES key and 12-byte nonce | AES-GCM with random nonces is only safe for about 2³² messages per key. With a fresh 128-bit salt per token, each key/nonce pair is used once, so the limit is never approached and token volume never forces key rotation. |
| Salt | 16 bytes from `SecureRandom`, transmitted in clear | Also serves as the token's identity for use counting. |
| Additional authenticated data | `keycloak-login-token:v2:` + realm id | Binds the token to its format version and realm. |
| Payload | Binary: flags, use limit, expiry, issue time, optional LoA, user id, optional client id | Keeps `login_hint` at 85–115 characters, below Keycloak's 255-character limit beyond which the parameter is silently dropped. |

Decryption tries every enabled `login-token` key of the realm, highest priority first. Failures are indistinguishable from outside: a wrong key, a wrong realm, a modified token and a malformed token all produce the same "invalid or expired" outcome.

**Key selection.** The active key with the highest priority encrypts. Only providers *named* `login-token` are considered, so Keycloak's own AES key is never used for tokens. Keeping the provider's priority below 100 keeps Keycloak from choosing the Login Token key for its own purposes as long as the realm's default `aes-generated` provider (priority 100) exists and is active.

**Key creation.** If a realm has no provider of that name, the first stateless mint creates one in a separate transaction under a component id derived from the realm id. The database therefore accepts exactly one insert however many requests or nodes race. *Verified with 12 concurrent first requests.* A provider that exists but is disabled is never replaced.

## 6. Use limits

`max_uses` (0 = unlimited, 1–10) is enforced with markers in Keycloak's single-use object store: `lt:used:{id}` for the first use, `lt:used:{id}:{n}` for the n-th, each created with `putIfAbsent`, the store's only atomic operation. A marker is written when a token is redeemed and lives until 60 seconds after the token expires, so that neither the end of the expiry second nor clock differences between nodes can free a use while the token is still accepted.

In the default configuration that store is the embedded Infinispan `actionTokens` cache: in memory, two copies of every entry across the cluster, no persistence.

## 7. Operational controls

| Goal | Action | Effect |
| --- | --- | --- |
| Revoke all tokens of one user | Disable the user | Immediate, both formats. |
| Invalidate every outstanding stateless token of a realm | Delete the `login-token` key provider | Immediate. The next stateless mint creates a new key. |
| Stop issuing stateless tokens in a realm | Disable the `login-token` key provider | Outstanding stateless tokens stop working; every request gets a legacy token and an error is logged. |
| Stop issuing stateless tokens everywhere | Send `"legacy": true`, or remove the server default | Tokens already issued keep working. |
| Rotate the key | Add a second `login-token` provider with a higher priority (below 100); delete the old one after the longest outstanding token lifetime | No interruption. |

**Rules that the design depends on**

1. **Never share a `login-token` key provider between environments.** Each environment must generate its own key. A database clone carries the key, and a full realm export may as well; a token minted in the source environment is then valid in the copy and vice versa. If an environment is ever created from a copy of another, delete the `login-token` provider in the copy.
2. **Roll out verification before issuance.** Deploy the plugin version that understands stateless tokens and `max_uses` to every node before any caller sends `"legacy": false` or `max_uses`. An older node cannot verify a stateless token, ignores `max_uses` (issuing an unlimited token instead), and writes a stateless token it cannot resolve to its log in full.
3. **Alert on the fallback error.** `[LT] stateless login token could not be issued …` means tokens are being stored in Infinispan again. It is logged as an error at most once per minute per node.
4. **Treat URLs as sensitive.** `login_hint` is part of the query string and appears in load-balancer, proxy and access logs outside this plugin's control. Keep lifetimes as short as the use case allows and bind tokens to a client.

## 8. Threats and mitigations

| # | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| T1 | Forging a stateless token | AES-256-GCM; key never leaves the server | Compromise of the database or of a `manage-realm` account (T8). |
| T2 | Modifying a token (other user, later expiry, higher use limit or LoA) | Authentication tag over the whole payload; AAD | None known. |
| T3 | Replaying a token beyond `max_uses` | Atomic use markers that outlive the token | Markers are lost on a full cluster restart — **open issue O1**. |
| T4 | Using a token in another realm | Realm id in AAD; per-realm key | None known. |
| T5 | Using a token in another environment | Separate keys per environment | Violating rule 1 above. |
| T6 | Using a token at another client | Client binding, always enforced when present | Unbound tokens, by design. |
| T7 | Token leaks through mail, logs, history or referrer | Expiry, use limit, client binding; no logging by the plugin | A leaked, still valid token logs the finder in. Infrastructure logs contain the URL. |
| T8 | Key theft or substitution | Key is not readable through the Admin API; a dedicated provider limits the blast radius to Login Tokens | Database access, possibly a full realm export, or `manage-realm` (which can install a provider with a chosen secret) allow minting. Equivalent to what those privileges already allow for the realm's signing keys. |
| T9 | Compromised minting service | Requires `manage-users`; not available in the master realm | Full: any user, any LoA. |
| T10 | Guessing a token | 122 random bits (legacy) or a 128-bit tag (stateless) | Negligible. |
| T11 | Token ends up as a prefilled username after rejection | `login_hint` is cleared on every rejection path | None known. |
| T12 | Log disclosure | Stateless tokens are reduced to their salt, legacy tokens to their first UUID block, anything else to its length | Nodes running an older plugin version log tokens in full (rule 2). |
| T13 | Memory exhaustion by token volume | Stateless tokens store nothing at creation | A silent fallback to the legacy format restores the old behaviour; hence rule 3. Redeemed use-limited tokens still create markers, proportional to redemptions. |
| T14 | Session of another user in the same browser | A token for a different user logs the existing session out first, optionally after confirmation | None known. |
| T15 | Old and new plugin versions disagree during an upgrade | Unlimited and single-use legacy tokens are read identically by both; the first use marker keeps its original key | A legacy token with `max_uses` ≥ 2 is single use on an old node; see rule 2 for `max_uses` at mint time. |
| T16 | Malformed `login_hint` used to reach other entries of the single-use store or to provoke server errors | A token id is only looked up if it is a UUID, and only decrypted if it carries the `v2.` prefix; everything else is rejected first. *Verified, including ids ending in `.revoked`.* | None known. |

## 9. Open issues

**O1 — Use counts do not survive a full cluster restart (accepted for now).**
Use markers are in memory only. After a full restart, or if both nodes holding a marker are lost at once, the markers are gone. A legacy token is gone with them and fails closed. A stateless token is still valid and can be redeemed again, up to `max_uses` times: it fails open. Rolling restarts are not affected. *Verified: a redeemed single-use stateless token was accepted again after a container restart.*

Options considered:

| Option | Effect | Cost |
| --- | --- | --- |
| A — Reject use-limited stateless tokens issued before the cluster start time | Fails closed on a full restart, like the legacy format. Does not cover the loss of only the two nodes holding a marker. | Small: the issue time is already in the token. All use-limited stateless tokens die with a full restart. |
| B — Persist use markers in the database | Complete. | A table, a migration and a cleanup job in the plugin; one write per redemption of a use-limited token. |
| C — Document and accept | None. | None. **Current choice.** |

Until this is resolved: where single use must hold unconditionally, issue the token in the legacy format or keep its lifetime short.

**O2 — No revocation of an individual stateless token.** By design; see section 4. Option B above would also provide the storage a revocation list needs.

**O3 — Not yet tested.**

- A real multi-node cluster running old and new plugin versions side by side. The mixed-version behaviour described here was established by running the old code against notes written by the new code, on a single node.
- That outstanding stateless tokens are rejected after their key provider is *disabled* (deletion is tested).
- Throughput and memory under campaign load.
- Keycloak 26.8.0 at runtime (compiled only), FIPS mode, an external Infinispan and the database-backed single-use store of Keycloak's `stateless` preview feature.

## 10. When changing this code

- Do not encrypt with the realm key directly. The per-token derivation is what removes the AES-GCM message limit.
- Do not change the wire format in place. Introduce a new prefix (`v3.`) and keep verifying the old one for as long as tokens may be outstanding.
- Every rejection path must clear `login_hint` and must not call `context.failure` in a way that lets the flow continue with the token still attached.
- Never log a token id; use `StatelessLoginToken.logId`.
- Keep the first use-marker key (`lt:used:{id}`) and the `reusable` note for unlimited legacy tokens as long as nodes that predate `max_uses` may exist.
- A use marker must always outlive its token.
