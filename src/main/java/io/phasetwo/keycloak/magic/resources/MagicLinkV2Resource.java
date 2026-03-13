package io.phasetwo.keycloak.magic.resources;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.token.MagicLinkV2Token.*;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.MagicLinkBFAuthenticator;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkV2Token;
import io.phasetwo.keycloak.magic.representation.MagicLinkV2Request;
import io.phasetwo.keycloak.magic.representation.MagicLinkV2Response;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

/**
 * REST endpoint for generating Magic Link v2 authorization URLs.
 *
 * <p>Unlike the v1 {@code /magic-link} endpoint, this endpoint does <em>not</em> authenticate the
 * user directly. Instead it stores the credential in {@link SingleUseObjectProvider} (Infinispan)
 * under a random UUID and returns a standard OIDC authorization URL with
 * {@code login_hint=mlv2:{uuid}}. The {@link MagicLinkBFAuthenticator} inside the browser flow
 * looks up the credential by UUID and completes authentication.
 *
 * <p>Using a UUID in {@code login_hint} keeps the value well within Keycloak's 255-character
 * parameter limit, avoiding the silent truncation that would occur with a full JWT.
 *
 * <p>OIDC parameters ({@code redirect_uri}, {@code scope}, {@code state}, {@code nonce},
 * {@code code_challenge}, {@code acr_values}, etc.) are the caller's responsibility and must be
 * supplied via {@code additional_parameters} in the request body or appended to the returned URL.
 *
 * <p>Requires the same {@code manage-users} permission as the v1 endpoint.
 */
@JBossLog
public class MagicLinkV2Resource extends AbstractAdminResource {

  public MagicLinkV2Resource(KeycloakSession session) {
    super(session);
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public MagicLinkV2Response createMagicLinkV2(final MagicLinkV2Request req) {
    if (!permissions.users().canManage()) {
      throw new ForbiddenException("magic link v2 requires manage-users");
    }

    if (Config.getAdminRealm().equals(realm.getName())) {
      throw new BadRequestException("Magic links are not allowed for the master realm");
    }

    if (req.getClientId() == null || req.getClientId().isBlank()) {
      throw new BadRequestException("client_id is required");
    }

    if (req.getEmail() == null && req.getUsername() == null) {
      throw new BadRequestException("email or username is required");
    }

    ClientModel client = session.clients().getClientByClientId(realm, req.getClientId());
    if (client == null) {
      throw new NotFoundException("Client not found: " + req.getClientId());
    }

    // When username is provided, never auto-create (consistent with v1 behavior).
    String emailOrUsername;
    boolean forceCreate;
    if (req.getUsername() != null) {
      emailOrUsername = req.getUsername();
      forceCreate = false;
    } else {
      emailOrUsername = req.getEmail();
      forceCreate = req.isForceCreate();
    }

    UserModel user =
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

    SingleUseObjectProvider singleUse = session.getProvider(SingleUseObjectProvider.class);
    singleUse.put(MagicLinkBFAuthenticator.DATA_KEY_PREFIX + tokenId,
        (long) req.getExpirationSeconds(), notes);

    log.debugf(
        "[MLv2] token stored for user=%s client=%s expiry=%d loa=%s reusable=%s",
        user.getId(), req.getClientId(), absoluteExpiry,
        req.getForceSessionLoa(), req.getReusable());

    // Build the OIDC authorization URL.
    // login_hint=mlv2:{uuid} is well within Keycloak's 255-char limit.
    URI baseUri = session.getContext().getUri().getBaseUri();
    UriBuilder authUri =
        UriBuilder.fromUri(baseUri)
            .path("realms/{realm}/protocol/openid-connect/auth")
            .queryParam(OIDCLoginProtocol.CLIENT_ID_PARAM, req.getClientId())
            .queryParam(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, OAuth2Constants.CODE)
            .queryParam(
                OIDCLoginProtocol.LOGIN_HINT_PARAM,
                MagicLinkBFAuthenticator.RESUME_PREFIX + tokenId);

    if (req.getAdditionalParameters() != null) {
      req.getAdditionalParameters().forEach(authUri::queryParam);
    }

    String link = authUri.build(realm.getName()).toString();
    log.debugf("[MLv2] authorization URL built: %s", link);

    MagicLinkV2Response resp = new MagicLinkV2Response();
    resp.setLink(link);
    resp.setUserId(user.getId());
    return resp;
  }
}
