package io.phasetwo.keycloak.magic.resources;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CLIENT_ID;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CONFIRM_USER_SWITCH;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_EXPIRY;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_LOA;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_MAX_USES;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REMEMBER_ME;
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

  private final boolean statelessByDefault;

  public LoginTokenResource(KeycloakSession session, boolean statelessByDefault) {
    super(session);
    this.statelessByDefault = statelessByDefault;
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
    boolean stateless = req.getStateless() != null ? req.getStateless() : statelessByDefault;

    String tokenId = null;
    if (stateless) {
      tokenId =
          sealStateless(
              new StatelessLoginToken.Payload()
                  .setUserId(user.getId())
                  .setClientId(clientBound ? req.getClientId() : null)
                  .setExpiry(absoluteExpiry)
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
        "[LT] token issued for user=%s client=%s expiry=%d loa=%s maxUses=%d stateless=%s",
        user.getId(),
        req.getClientId(),
        absoluteExpiry,
        req.getForceSessionLoa(),
        maxUses,
        StatelessLoginToken.isStateless(tokenId));

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
    return Boolean.FALSE.equals(req.getReusable()) ? 1 : 0;
  }

  /**
   * Encrypts the payload into a stateless token id.
   *
   * @return the token id, or {@code null} when a stateless token cannot be issued — no {@value
   *     LoginTokenKeys#KEY_PROVIDER_NAME} key provider in the realm, or a payload that does not fit
   *     the compact format or Keycloak's {@code login_hint} length limit. The caller then falls back
   *     to a legacy token, so issuing never fails because of the token kind.
   */
  private String sealStateless(StatelessLoginToken.Payload payload) {
    Optional<SecretKey> key = LoginTokenKeys.encryptionKey(session, realm);
    if (key.isEmpty()) {
      log.warnf(
          "[LT] stateless token requested but realm '%s' has no active AES key provider named"
              + " '%s' — falling back to a legacy token",
          realm.getName(), LoginTokenKeys.KEY_PROVIDER_NAME);
      return null;
    }
    String tokenId;
    try {
      tokenId = StatelessLoginToken.seal(key.get(), realm.getId(), payload);
    } catch (IllegalArgumentException e) {
      log.debugf(
          "[LT] payload does not fit a stateless token (%s) — issuing a legacy token",
          e.getMessage());
      return null;
    }
    if (LoginTokenVerifier.RESUME_PREFIX.length() + tokenId.length()
        > StatelessLoginToken.MAX_LOGIN_HINT_LENGTH) {
      log.debugf(
          "[LT] stateless token exceeds the login_hint length limit — issuing a legacy token");
      return null;
    }
    return tokenId;
  }
}
