package io.phasetwo.keycloak.magic.resources;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CLIENT_ID;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CONFIRM_USER_SWITCH;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_EXPIRY;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_LOA;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_MAX_USES;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REMEMBER_ME;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REUSABLE;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_SEV;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_USER_ID;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.LoginTokenVerifier;
import io.phasetwo.keycloak.magic.auth.token.LoginTokenKeys;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import io.phasetwo.keycloak.magic.representation.LoginTokenResponse;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.SecretKey;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

/**
 * REST endpoint for generating Login Token credentials.
 *
 * <p>Unlike the v1 {@code /magic-link} endpoint, this endpoint does <em>not</em> authenticate the
 * user directly and does <em>not</em> build an OIDC authorization URL. Instead it returns the
 * {@code login_hint} value that the caller must pass to the OIDC authorization endpoint. Two token
 * kinds exist:
 *
 * <ul>
 *   <li><b>legacy</b> ({@code lt:{uuid}}) — the credential is kept in {@link
 *       SingleUseObjectProvider} (Infinispan) for the token's lifetime;
 *   <li><b>stateless</b> ({@code lt:v2.…}) — the credential is encrypted into the token itself
 *       (see {@link StatelessLoginToken}); nothing is stored until a use-limited token is
 *       redeemed.
 * </ul>
 *
 * <p>The caller is responsible for constructing the full OIDC authorization URL, including PKCE
 * ({@code code_challenge}, {@code code_challenge_method}), {@code redirect_uri}, {@code scope},
 * {@code state}, {@code nonce}, and any other parameters required by the client. The caller
 * <strong>must</strong> include {@code prompt=login} to prevent Keycloak from short-circuiting the
 * flow with an existing session belonging to a different user.
 *
 * <p>The {@link LoginTokenVerifier} inside the browser flow resolves the credential and completes
 * authentication.
 *
 * <p>Requires the same {@code manage-users} permission as the v1 endpoint.
 */
@JBossLog
public class LoginTokenResource extends AbstractAdminResource {

  private final boolean legacyByDefault;

  public LoginTokenResource(KeycloakSession session, boolean legacyByDefault) {
    super(session);
    this.legacyByDefault = legacyByDefault;
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public LoginTokenResponse createLoginToken(final LoginTokenRequest req) {
    if (!permissions.users().canManage()) {
      throw new ForbiddenException("login token requires manage-users");
    }

    if (Config.getAdminRealm().equals(realm.getName())) {
      throw new BadRequestException("Login tokens are not allowed for the master realm");
    }

    if (req.getUserId() == null && req.getEmail() == null && req.getUsername() == null) {
      throw new BadRequestException("user_id, email, or username is required");
    }

    if (req.getExpirationSeconds() <= 0) {
      throw new BadRequestException("expiration_seconds must be positive");
    }

    int maxUses = resolveMaxUses(req);

    // client_id is optional: when present, the token is bound to that client and the binding is
    // always enforced on redemption. When absent, an unbound ("universal") token is created that
    // is only accepted by executions configured with "Client ID must match" = OFF.
    boolean clientBound = req.getClientId() != null && !req.getClientId().isBlank();
    if (clientBound) {
      ClientModel client = session.clients().getClientByClientId(realm, req.getClientId());
      if (client == null) {
        throw new NotFoundException("Client not found: " + req.getClientId());
      }
    }

    // user_id takes precedence, then username, then email.
    UserModel user;
    if (req.getUserId() != null) {
      user = session.users().getUserById(realm, req.getUserId());
      if (user == null) {
        throw new NotFoundException("User not found: " + req.getUserId());
      }
    } else {
      String emailOrUsername;
      boolean forceCreate;
      if (req.getUsername() != null) {
        emailOrUsername = req.getUsername();
        forceCreate = false;
      } else {
        emailOrUsername = req.getEmail();
        forceCreate = req.isForceCreate();
      }
      user =
          MagicLink.getOrCreate(
              session,
              realm,
              emailOrUsername,
              forceCreate,
              false,
              false,
              MagicLink.registerEvent(event, MAGIC_LINK));
      if (user == null) {
        throw new NotFoundException(
            "User not found: " + emailOrUsername + " (forceCreate=" + forceCreate + ")");
      }
    }

    long absoluteExpiry = Time.currentTime() + (long) req.getExpirationSeconds();
    boolean legacy = req.getLegacy() != null ? req.getLegacy() : legacyByDefault;

    String tokenId = null;
    if (!legacy) {
      tokenId =
          sealStateless(
              new StatelessLoginToken.Payload()
                  .setUserId(user.getId())
                  .setClientId(clientBound ? req.getClientId() : null)
                  .setExpiry(absoluteExpiry)
                  .setIssuedAt(Time.currentTime())
                  .setLoa(req.getForceSessionLoa())
                  .setMaxUses(maxUses)
                  .setRememberMe(Boolean.TRUE.equals(req.getRememberMe()))
                  .setSetEmailVerified(Boolean.TRUE.equals(req.getSetEmailVerified()))
                  .setConfirmUserSwitch(Boolean.TRUE.equals(req.getConfirmUserSwitch())));
    }

    if (tokenId == null) {
      // Legacy token: the notes map is kept in Infinispan under a random UUID key.
      tokenId = UUID.randomUUID().toString();

      Map<String, String> notes = new HashMap<>();
      notes.put(KEY_USER_ID, user.getId());
      if (clientBound) {
        notes.put(KEY_CLIENT_ID, req.getClientId());
      }
      notes.put(KEY_EXPIRY, String.valueOf(absoluteExpiry));
      notes.put(KEY_MAX_USES, String.valueOf(maxUses));
      if (maxUses == 0) {
        // Versions that predate max_uses only know this flag and treat its absence as single use.
        // Keep writing it so an unlimited token stays unlimited on such a node during a rolling
        // upgrade or after a rollback.
        notes.put(KEY_REUSABLE, "true");
      }
      if (req.getForceSessionLoa() != null) {
        notes.put(KEY_LOA, String.valueOf(req.getForceSessionLoa()));
      }
      if (Boolean.TRUE.equals(req.getRememberMe())) {
        notes.put(KEY_REMEMBER_ME, "true");
      }
      if (Boolean.TRUE.equals(req.getSetEmailVerified())) {
        notes.put(KEY_SEV, "true");
      }
      if (Boolean.TRUE.equals(req.getConfirmUserSwitch())) {
        notes.put(KEY_CONFIRM_USER_SWITCH, "true");
      }

      SingleUseObjectProvider singleUse = session.getProvider(SingleUseObjectProvider.class);
      singleUse.put(
          LoginTokenVerifier.DATA_KEY_PREFIX + tokenId, (long) req.getExpirationSeconds(), notes);
    }

    log.debugf(
        "[LT] token issued for user=%s client=%s expiry=%d loa=%s maxUses=%d legacy=%s",
        user.getId(),
        req.getClientId(),
        absoluteExpiry,
        req.getForceSessionLoa(),
        maxUses,
        !StatelessLoginToken.isStateless(tokenId));

    LoginTokenResponse resp = new LoginTokenResponse();
    resp.setLoginHint(LoginTokenVerifier.RESUME_PREFIX + tokenId);
    return resp;
  }

  /**
   * Resolves the redemption limit from {@code max_uses} (preferred) or the legacy {@code reusable}
   * flag. {@code 0} means unlimited, which is also the default when neither is set.
   */
  private static int resolveMaxUses(LoginTokenRequest req) {
    if (req.getMaxUses() != null) {
      int maxUses = req.getMaxUses();
      if (maxUses < 0 || maxUses > StatelessLoginToken.MAX_USES_LIMIT) {
        throw new BadRequestException(
            "max_uses must be between 0 (unlimited) and " + StatelessLoginToken.MAX_USES_LIMIT);
      }
      return maxUses;
    }
    // As before max_uses existed: an omitted flag defaults to true (unlimited), and only an
    // explicit true is unlimited — false and an explicit null both mean single use.
    return Boolean.TRUE.equals(req.getReusable()) ? 0 : 1;
  }

  /**
   * Encrypts the payload into a stateless token id.
   *
   * @return the token id, or {@code null} when a stateless token cannot be issued — the realm's
   *     {@value LoginTokenKeys#KEY_PROVIDER_NAME} key provider is disabled, or a payload that does not fit
   *     the compact format or Keycloak's {@code login_hint} length limit. The caller then falls back
   *     to a legacy token, so issuing never fails because of the token kind; the fallback is
   *     reported as an error in the log.
   */
  private String sealStateless(StatelessLoginToken.Payload payload) {
    Optional<SecretKey> key = LoginTokenKeys.ensureEncryptionKey(session, realm);
    if (key.isEmpty()) {
      logFallback(
          "key provider '" + LoginTokenKeys.KEY_PROVIDER_NAME + "' offers no active AES key");
      return null;
    }
    String tokenId;
    try {
      tokenId = StatelessLoginToken.seal(key.get(), realm.getId(), payload);
    } catch (IllegalArgumentException e) {
      logFallback("payload does not fit the token format: " + e.getMessage());
      return null;
    }
    if (LoginTokenVerifier.RESUME_PREFIX.length() + tokenId.length()
        > StatelessLoginToken.MAX_LOGIN_HINT_LENGTH) {
      logFallback("token exceeds the login_hint length limit");
      return null;
    }
    return tokenId;
  }

  /**
   * Reports that a legacy token was issued in place of a requested stateless one. The request
   * itself succeeds, so the log is the only place where this shows — and it matters: every such
   * token is stored in Infinispan again. Logged as an error, at most once per {@link
   * #FALLBACK_LOG_INTERVAL_MILLIS} per node so that a campaign cannot flood the log; the number of
   * occurrences in between is included in the next report.
   */
  private void logFallback(String reason) {
    if (!FALLBACK_LOG.shouldLog(System.currentTimeMillis())) {
      return;
    }
    log.errorf(
        "[LT] stateless login token could not be issued in realm '%s' (%s) — issued a legacy"
            + " token instead, which is stored in Infinispan. Unreported occurrences since the"
            + " last report: %d",
        realm.getName(), reason, FALLBACK_LOG.takeSuppressed());
  }

  static final long FALLBACK_LOG_INTERVAL_MILLIS = 60_000L;

  private static final RateLimitedLog FALLBACK_LOG =
      new RateLimitedLog(FALLBACK_LOG_INTERVAL_MILLIS);

  /** Lets one caller per interval through and counts the rest. Thread-safe. */
  static final class RateLimitedLog {
    private final long intervalMillis;
    private final AtomicLong nextAt = new AtomicLong(Long.MIN_VALUE);
    private final AtomicLong suppressed = new AtomicLong();

    RateLimitedLog(long intervalMillis) {
      this.intervalMillis = intervalMillis;
    }

    boolean shouldLog(long nowMillis) {
      long next = nextAt.get();
      if (nowMillis >= next && nextAt.compareAndSet(next, nowMillis + intervalMillis)) {
        return true;
      }
      suppressed.incrementAndGet();
      return false;
    }

    long takeSuppressed() {
      return suppressed.getAndSet(0);
    }
  }
}
