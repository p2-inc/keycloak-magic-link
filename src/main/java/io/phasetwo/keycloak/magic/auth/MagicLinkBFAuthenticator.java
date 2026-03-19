package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.token.MagicLinkV2Token.*;

import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.authentication.authenticators.util.LoAUtil;
import org.keycloak.events.Details;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.Constants;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Authenticator that completes Magic Link v2 authentication inside the Keycloak browser flow.
 *
 * <h3>Flow</h3>
 * <ol>
 *   <li>Backend calls {@code POST /realms/{realm}/magic-link-v2} to obtain an OIDC authorization
 *       URL containing a UUID credential reference in {@code login_hint=mlv2:{uuid}}. The
 *       credential data is stored in {@link SingleUseObjectProvider} (Infinispan).</li>
 *   <li>The app opens that URL. The OIDC endpoint processes all parameters and starts the browser
 *       flow.</li>
 *   <li>This authenticator reads {@code login_hint}, looks up the credential by UUID, validates
 *       expiry and client. If an existing session for a <em>different</em> user is found, a
 *       confirmation form is shown. Otherwise the authenticator enforces single-use, sets the user
 *       and optional LOA, and calls {@code context.success()}.</li>
 *   <li>Subsequent authenticators (e.g. TOTP for LOA=2) run in the same browser session.</li>
 * </ol>
 *
 * <h3>Placement</h3>
 * Add as <strong>ALTERNATIVE</strong> <em>before Cookie</em> in the browser flow. This ensures
 * the verifier always evaluates {@code login_hint} before the Cookie authenticator can
 * short-circuit the flow with a different user's existing session.
 */
@JBossLog
public class MagicLinkBFAuthenticator implements Authenticator {

  public static final String RESUME_PREFIX   = "mlv2:";
  public static final String DATA_KEY_PREFIX = "mlv2:data:";
  private static final String USED_KEY_PREFIX = "mlv2:used:";

  /** Auth-session note: tokenId pending user-switch confirmation. */
  private static final String NOTE_PENDING_TOKEN    = "mlv2_pending_token";
  /** Auth-session note: display name of the currently logged-in user. */
  private static final String NOTE_CURRENT_USERNAME = "mlv2_current_username";
  /** Auth-session note: display name of the magic-link target user. */
  private static final String NOTE_TARGET_USERNAME  = "mlv2_target_username";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String loginHint =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

    if (loginHint == null || !loginHint.startsWith(RESUME_PREFIX)) {
      context.attempted();
      return;
    }

    String tokenId = loginHint.substring(RESUME_PREFIX.length());
    handleTokenId(context, tokenId);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    String pendingToken = context.getAuthenticationSession().getAuthNote(NOTE_PENDING_TOKEN);
    if (pendingToken == null) {
      context.attempted();
      return;
    }

    String action = context.getHttpRequest().getDecodedFormParameters().getFirst("action");
    if ("logout".equals(action)) {
      log.debugf("[MLv2] redirecting to fresh auth flow after cookie expiry for pending token '%s'",
          pendingToken);
      redirectAfterLogout(context, pendingToken);
      return;
    } else {
      // User cancelled — redirect back to the client with error=access_denied per OIDC spec.
      // We must pass a response to failure() here so Keycloak aborts the entire flow
      // immediately; without it, failure() on an ALTERNATIVE execution causes Keycloak to
      // try the next alternative (e.g. Username/Password) instead.
      String redirectUri = context.getAuthenticationSession().getRedirectUri();
      String state = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
      jakarta.ws.rs.core.UriBuilder errorUri = jakarta.ws.rs.core.UriBuilder.fromUri(redirectUri)
          .queryParam("error", "access_denied")
          .queryParam("error_description", "User+cancelled+the+magic+link+authentication");
      if (state != null && !state.isBlank()) {
        errorUri.queryParam("state", state);
      }
      context.failure(AuthenticationFlowError.ACCESS_DENIED,
          Response.seeOther(errorUri.build()).build());
    }
  }

  // -------------------------------------------------------------------------

  /**
   * Removes {@code login_hint} from the current auth session so that downstream authenticators
   * (e.g. Email OTP / Username form) do not inherit a stale or expired magic-link hint.
   */
  private static void clearLoginHint(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
    context.getAuthenticationSession().removeAuthNote(
        AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
  }

  private void handleTokenId(AuthenticationFlowContext context, String tokenId) {
    SingleUseObjectProvider singleUse =
        context.getSession().getProvider(SingleUseObjectProvider.class);

    Map<String, String> notes = singleUse.get(DATA_KEY_PREFIX + tokenId);
    if (notes == null) {
      log.warnf("[MLv2] credential not found or expired for tokenId='%s'", tokenId);
      clearLoginHint(context);
      context.attempted();
      return;
    }

    // Validate expiry
    String expiryStr = notes.get(KEY_EXPIRY);
    if (expiryStr != null) {
      if (System.currentTimeMillis() / 1000L > Long.parseLong(expiryStr)) {
        log.warnf("[MLv2] credential expired for tokenId='%s'", tokenId);
        clearLoginHint(context);
        context.attempted();
        return;
      }
    }

    // Validate client
    String storedClientId = notes.get(KEY_CLIENT_ID);
    String sessionClientId = context.getAuthenticationSession().getClient().getClientId();
    if (storedClientId != null && !storedClientId.equals(sessionClientId)) {
      log.warnf("[MLv2] client mismatch: stored='%s', flow='%s'", storedClientId, sessionClientId);
      clearLoginHint(context);
      context.attempted();
      return;
    }

    // Resolve target user
    String userId = notes.get(KEY_USER_ID);
    UserModel targetUser = context.getSession().users().getUserById(context.getRealm(), userId);
    if (targetUser == null || !targetUser.isEnabled()) {
      log.warnf("[MLv2] user '%s' not found or disabled", userId);
      clearLoginHint(context);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return;
    }

    // Check for an existing session belonging to a different user.
    AuthenticationManager.AuthResult cookie =
        AuthenticationManager.authenticateIdentityCookie(
            context.getSession(), context.getRealm(), false);
    if (cookie != null && cookie.getUser() != null
        && !cookie.getUser().getId().equals(targetUser.getId())) {

      String currentDisplay = displayName(cookie.getUser());
      String targetDisplay  = displayName(targetUser);
      log.debugf("[MLv2] user switch required: '%s' → '%s'", currentDisplay, targetDisplay);

      if ("true".equalsIgnoreCase(notes.get(KEY_CONFIRM_USER_SWITCH))) {
        // Show confirmation form — user must explicitly approve the logout.
        context.getAuthenticationSession().setAuthNote(NOTE_PENDING_TOKEN, tokenId);
        context.getAuthenticationSession().setAuthNote(NOTE_CURRENT_USERNAME, currentDisplay);
        context.getAuthenticationSession().setAuthNote(NOTE_TARGET_USERNAME, targetDisplay);

        Response challenge = context.form()
            .setAttribute("currentUsername", currentDisplay)
            .setAttribute("targetUsername", targetDisplay)
            .createForm("magic-link-user-switch.ftl");
        context.challenge(challenge);
      } else {
        // Auto-logout: silently expire session cookies and restart the auth flow.
        log.debugf("[MLv2] auto-logout: signing out '%s' to authenticate '%s'",
            currentDisplay, targetDisplay);
        redirectAfterLogout(context, tokenId);
      }
      return;
    }

    completeAuth(context, tokenId, notes, expiryStr, targetUser);
  }

  private void completeAuth(AuthenticationFlowContext context, String tokenId,
      Map<String, String> notes, String expiryStr, UserModel user) {

    // Single-use enforcement
    boolean isReusable = "true".equalsIgnoreCase(notes.get(KEY_REUSABLE));
    if (!isReusable) {
      long remainingTtl = expiryStr != null
          ? Math.max(1L, Long.parseLong(expiryStr) - (System.currentTimeMillis() / 1000L))
          : 300L;
      if (!context.getSession().getProvider(SingleUseObjectProvider.class)
          .putIfAbsent(USED_KEY_PREFIX + tokenId, remainingTtl)) {
        log.warnf("[MLv2] token already used: '%s'", tokenId);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        return;
      }
    }

    context.setUser(user);
    context.getAuthenticationSession().setAuthenticatedUser(user);
    if ("true".equalsIgnoreCase(notes.get(KEY_SEV))) {
      user.setEmailVerified(true);
      user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.name());
    }

    Integer loaLevel = resolveLoaLevel(context, notes);
    if (loaLevel != null) {
      new AcrStore(context.getSession(), context.getAuthenticationSession())
          .setLevelAuthenticated(loaLevel);
      log.debugf("[MLv2] LOA %d set for user '%s'", loaLevel, user.getId());
      // Persist LOA_MAP directly to the UserSession note.
      // ConditionalLoaAuthenticator.onTopFlowSuccess() normally does this, but may not be
      // invoked when the LOA conditional sub-flow is skipped (because magic link already
      // satisfied the requested LOA). Without this, auth-cookie cannot satisfy subsequent
      // re-auth requests and the login form is shown unnecessarily.
      context.getAuthenticationSession().setUserSessionNote(
          Constants.LOA_MAP,
          context.getAuthenticationSession().getAuthNote(Constants.LOA_MAP));
    }

    if ("true".equalsIgnoreCase(notes.get(KEY_REMEMBER_ME))) {
      context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
    }

    clearLoginHint(context);
    String displayEmail = user.getEmail() != null ? user.getEmail() : user.getUsername();
    context.getAuthenticationSession().setAuthNote(
        AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, displayEmail);
    log.debugf("[MLv2] authentication complete for user '%s'", user.getId());
    context.success();
  }

  /**
   * Expires the identity and auth-session cookies, then issues a 302 redirect to a fresh OIDC
   * authorization request carrying the same {@code login_hint}. The magic link token has not been
   * consumed yet, so the fresh flow will pick it up and complete authentication for the target
   * user.
   *
   * <p>The old user session is intentionally left alive in Infinispan; removing it inside this
   * request would conflict with Keycloak's session-persistence worker, producing a duplicate-key
   * DB error. It will expire naturally via its TTL.
   */
  private void redirectAfterLogout(AuthenticationFlowContext context, String tokenId) {
    // Collect all auth-session params before expiring cookies (the auth session object
    // remains valid in-memory for this request even after the cookie is expired).
    String loginHint =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
    String clientId   = context.getAuthenticationSession().getClient().getClientId();
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    String scope      = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);

    // Expire the Keycloak identity cookies (KEYCLOAK_IDENTITY / KEYCLOAK_SESSION) AND the
    // auth-session cookie (AUTH_SESSION_ID). Without expiring AUTH_SESSION_ID, the redirect
    // causes the browser to send the old auth-session cookie to the new auth request.
    // Keycloak then reuses the existing root auth session (linked to the old user's user session),
    // triggering a "different_user_authenticated" error even in the fresh flow.
    AuthenticationManager.expireIdentityCookie(context.getSession());
    context.getSession().getProvider(org.keycloak.cookie.CookieProvider.class)
        .expire(org.keycloak.cookie.CookieType.AUTH_SESSION_ID);

    jakarta.ws.rs.core.UriBuilder authUri =
        jakarta.ws.rs.core.UriBuilder
            .fromUri(context.getSession().getContext().getUri().getBaseUri())
            .path("realms/{realm}/protocol/openid-connect/auth")
            .queryParam("client_id",     clientId)
            .queryParam("response_type", "code")
            .queryParam("login_hint",    loginHint)
            .queryParam("prompt",        "login")
            .queryParam("redirect_uri",  redirectUri);
    if (scope != null && !scope.isBlank()) {
      authUri.queryParam("scope", scope);
    }

    log.debugf("[MLv2] cookie expiry + redirect for token '%s'", tokenId);
    context.challenge(Response.seeOther(authUri.build(context.getRealm().getName())).build());
  }

  private static String displayName(UserModel user) {
    if (user.getEmail() != null && !user.getEmail().isBlank()) return user.getEmail();
    return user.getUsername();
  }

  private Integer resolveLoaLevel(AuthenticationFlowContext context, Map<String, String> notes) {
    String loaStr = notes.get(KEY_LOA);
    if (loaStr != null) {
      try {
        return Integer.parseInt(loaStr);
      } catch (NumberFormatException ignored) {}
    }

    String parentFlowId = context.getExecution().getParentFlow();
    List<AuthenticationExecutionModel> loaConditions =
        AuthenticatorUtil.getExecutionsByType(
            context.getRealm(), parentFlowId, ConditionalLoaAuthenticatorFactory.PROVIDER_ID);

    if (!loaConditions.isEmpty()) {
      String configId = loaConditions.get(0).getAuthenticatorConfig();
      Integer level = LoAUtil.getLevelFromLoaConditionConfiguration(
          context.getRealm().getAuthenticatorConfigById(configId));
      if (level != null) {
        log.debugf("[MLv2] LOA %d read from sibling Condition - Level of Authentication", level);
        return level;
      }
    }

    // Default: Magic Link always grants at least LoA 1.
    // Without this, the session has no LoA and every subsequent auth request
    // triggers the Level-2 condition even when only LoA 1 was required.
    log.debugf("[MLv2] no explicit LOA in token and no sibling condition found — defaulting to LOA 1");
    return 1;
  }

  // -------------------------------------------------------------------------

  @Override public boolean requiresUser() { return false; }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
  @Override public void close() {}
}
