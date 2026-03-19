package io.phasetwo.keycloak.magic.resources;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.*;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.LoginTokenVerifier;
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
import java.util.UUID;
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
 * user directly and does <em>not</em> build an OIDC authorization URL. Instead it stores the
 * credential in {@link SingleUseObjectProvider} (Infinispan) under a random UUID and returns the
 * {@code login_hint} value ({@code lt:{uuid}}) that the caller must pass to the OIDC
 * authorization endpoint.
 *
 * <p>The caller is responsible for constructing the full OIDC authorization URL, including PKCE
 * ({@code code_challenge}, {@code code_challenge_method}), {@code redirect_uri}, {@code scope},
 * {@code state}, {@code nonce}, and any other parameters required by the client. The caller
 * <strong>must</strong> include {@code prompt=login} to prevent Keycloak from short-circuiting the
 * flow with an existing session belonging to a different user.
 *
 * <p>The {@link LoginTokenVerifier} inside the browser flow looks up the credential by UUID
 * and completes authentication.
 *
 * <p>Requires the same {@code manage-users} permission as the v1 endpoint.
 */
@JBossLog
public class LoginTokenResource extends AbstractAdminResource {

  public LoginTokenResource(KeycloakSession session) {
    super(session);
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

    if (req.getClientId() == null || req.getClientId().isBlank()) {
      throw new BadRequestException("client_id is required");
    }

    if (req.getUserId() == null && req.getEmail() == null && req.getUsername() == null) {
      throw new BadRequestException("user_id, email, or username is required");
    }

    ClientModel client = session.clients().getClientByClientId(realm, req.getClientId());
    if (client == null) {
      throw new NotFoundException("Client not found: " + req.getClientId());
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

    // Build the notes map stored in Infinispan under the UUID key.
    String tokenId = UUID.randomUUID().toString();
    long absoluteExpiry = Time.currentTime() + (long) req.getExpirationSeconds();

    Map<String, String> notes = new HashMap<>();
    notes.put(KEY_USER_ID, user.getId());
    notes.put(KEY_CLIENT_ID, req.getClientId());
    notes.put(KEY_EXPIRY, String.valueOf(absoluteExpiry));
    if (req.getForceSessionLoa() != null) {
      notes.put(KEY_LOA, String.valueOf(req.getForceSessionLoa()));
    }
    if (Boolean.TRUE.equals(req.getRememberMe())) {
      notes.put(KEY_REMEMBER_ME, "true");
    }
    if (Boolean.TRUE.equals(req.getReusable())) {
      notes.put(KEY_REUSABLE, "true");
    }
    if (Boolean.TRUE.equals(req.getSetEmailVerified())) {
      notes.put(KEY_SEV, "true");
    }
    if (Boolean.TRUE.equals(req.getConfirmUserSwitch())) {
      notes.put(KEY_CONFIRM_USER_SWITCH, "true");
    }

    SingleUseObjectProvider singleUse = session.getProvider(SingleUseObjectProvider.class);
    singleUse.put(LoginTokenVerifier.DATA_KEY_PREFIX + tokenId,
        (long) req.getExpirationSeconds(), notes);

    log.debugf(
        "[LT] token stored for user=%s client=%s expiry=%d loa=%s reusable=%s",
        user.getId(), req.getClientId(), absoluteExpiry,
        req.getForceSessionLoa(), req.getReusable());

    LoginTokenResponse resp = new LoginTokenResponse();
    resp.setLoginHint(LoginTokenVerifier.RESUME_PREFIX + tokenId);
    return resp;
  }
}
