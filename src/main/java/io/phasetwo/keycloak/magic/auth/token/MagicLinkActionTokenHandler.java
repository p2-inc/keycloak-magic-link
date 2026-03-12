package io.phasetwo.keycloak.magic.auth.token;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Handles the magic link action token by redirecting into a standard OIDC browser flow.
 *
 * <p>Instead of creating a user session directly (which bypasses all browser-flow authenticators
 * and prevents step-up authentication in the same session), this handler:
 * <ol>
 *   <li>Validates the action token (done by the base class).</li>
 *   <li>Stores a short-lived <em>resume token</em> in {@link SingleUseObjectProvider} (Infinispan)
 *       with the pre-validated {@code userId}, {@code realmId}, and optional
 *       {@code forceSessionLoa}.</li>
 *   <li>Redirects to a standard OIDC authorization request — with all original parameters
 *       restored and {@code login_hint=mlbf-resume:{resumeId}} — so that the OIDC endpoint
 *       processes {@code acr_values} correctly and {@code ConditionalLoaAuthenticator} can
 *       evaluate step-up conditions.</li>
 *   <li>{@link io.phasetwo.keycloak.magic.auth.MagicLinkBFAuthenticator} in the browser flow
 *       picks up the resume token, calls {@code context.success()}, and lets any subsequent
 *       step-up authenticators run in the same browser session.</li>
 * </ol>
 *
 * <p><strong>PKCE note:</strong> If the client enforces PKCE, the magic-link API caller must
 * include {@code code_challenge} and {@code code_challenge_method} in the request — exactly as
 * they would for a regular OIDC flow. Magic links without PKCE require the client to have PKCE
 * enforcement disabled.
 */
@JBossLog
public class MagicLinkActionTokenHandler extends AbstractActionTokenHandler<MagicLinkActionToken> {

  public static final String LOGIN_METHOD = "login_method";

  /**
   * Prefix in {@code login_hint} carrying the resume token ID.
   * Must stay in sync with {@link io.phasetwo.keycloak.magic.auth.MagicLinkBFAuthenticator#RESUME_PREFIX}.
   */
  public static final String RESUME_PREFIX = "mlbf-resume:";

  /** Maximum TTL for the short-lived resume token (seconds). */
  private static final int RESUME_MAX_TTL_SECONDS = 300;

  public MagicLinkActionTokenHandler() {
    super(
        MagicLinkActionToken.TOKEN_TYPE,
        MagicLinkActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
  }

  @Override
  public boolean canUseTokenRepeatedly(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return token.getActionTokenPersistent();
  }

  @Override
  public Response handleToken(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    log.debugf("handleToken for iss:%s, user:%s", token.getIssuedFor(), token.getUserId());

    UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
    final ClientModel client = tokenContext.getAuthenticationSession().getClient();

    // Clicking the link proves the user controls this address.
    user.setEmailVerified(true);

    // --- Store a short-lived resume token in Infinispan ---
    int remainingSeconds = token.getExp() != null
        ? (int) Math.max(30, token.getExp() - (System.currentTimeMillis() / 1000L))
        : RESUME_MAX_TTL_SECONDS;
    int ttl = Math.min(remainingSeconds, RESUME_MAX_TTL_SECONDS);

    String resumeId = SecretGenerator.getInstance().randomString(32);
    Map<String, String> resumeData = new HashMap<>();
    resumeData.put("userId",  user.getId());
    resumeData.put("realmId", tokenContext.getRealm().getId());
    if (token.getForceSessionLoa() != null) {
      resumeData.put("forceSessionLoa", String.valueOf(token.getForceSessionLoa()));
    }
    if (Boolean.TRUE.equals(token.getRememberMe())) {
      resumeData.put("rememberMe", "true");
    }

    tokenContext.getSession()
        .getProvider(SingleUseObjectProvider.class)
        .put(resumeId, ttl, resumeData);

    log.debugf("[MagicLink] resume token stored (ttl=%ds, user=%s, forceSessionLoa=%s, acr_values=%s)",
        ttl, user.getId(), token.getForceSessionLoa(), token.getAcrValues());

    // --- Redirect to the OIDC authorization endpoint ---
    // By going through the full OIDC auth request, acr_values and all other parameters are
    // processed correctly by the OIDC endpoint, so ConditionalLoaAuthenticator can evaluate
    // step-up conditions as it would in a standard browser flow.
    String resolvedRedirectUri = token.getRedirectUri() != null
        ? token.getRedirectUri()
        : ResolveRelative.resolveRelativeUri(
            tokenContext.getSession(), client.getRootUrl(), client.getBaseUrl());

    UriBuilder authUri = UriBuilder
        .fromUri(tokenContext.getUriInfo().getBaseUri())
        .path("realms/{realm}/protocol/openid-connect/auth")
        .queryParam(OIDCLoginProtocol.CLIENT_ID_PARAM,     client.getClientId())
        .queryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM,  resolvedRedirectUri)
        .queryParam(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, OAuth2Constants.CODE)
        .queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM,    RESUME_PREFIX + resumeId);

    if (token.getScope() != null) {
      authUri.queryParam(OAuth2Constants.SCOPE, token.getScope());
    }
    if (token.getState() != null) {
      authUri.queryParam(OIDCLoginProtocol.STATE_PARAM, token.getState());
    }
    if (token.getNonce() != null) {
      authUri.queryParam(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
    }
    if (token.getCodeChallenge() != null) {
      authUri.queryParam(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, token.getCodeChallenge());
      authUri.queryParam(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM,
          token.getCodeChallengeMethod() != null ? token.getCodeChallengeMethod() : "S256");
    }
    if (token.getResponseMode() != null) {
      authUri.queryParam(OIDCLoginProtocol.RESPONSE_MODE_PARAM, token.getResponseMode());
    }
    if (token.getAcrValues() != null) {
      authUri.queryParam(OIDCLoginProtocol.ACR_PARAM, token.getAcrValues());
    }

    URI targetUri = authUri.build(tokenContext.getRealm().getName());
    log.debugf("[MagicLink] redirecting to OIDC auth endpoint: %s", targetUri);
    return Response.seeOther(targetUri).build();
  }
}
