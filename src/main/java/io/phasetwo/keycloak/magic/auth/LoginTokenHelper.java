package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.token.LoginToken.*;

import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.authentication.authenticators.util.LoAUtil;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Package-private helpers shared by Login Token authenticators.
 *
 * <p>Contains the shared constants (Infinispan key prefixes, auth-session note names) and all
 * stateless utility methods used by both {@link LoginTokenVerifier} (login_hint-based) and {@link
 * LoginTokenFormAuthenticator} (form-based).
 *
 * <h3>Core shared flow</h3>
 *
 * <ul>
 *   <li>{@link #handleTokenId} — full token verification pipeline; callers supply lambdas for the
 *       two points that differ between the two authenticators.
 *   <li>{@link #handleUserSwitchAction} — logout / cancel dispatch for the user-switch
 *       confirmation form.
 *   <li>{@link #redirectAfterLogout} — cookie expiry + fresh OIDC auth redirect.
 *   <li>{@link #completeAuth} — single-use enforcement, user/LOA/remember-me setup,
 *       {@code context.success()}.
 * </ul>
 */
@JBossLog
class LoginTokenHelper {

  // Infinispan key prefixes
  static final String RESUME_PREFIX   = "lt:";
  static final String DATA_KEY_PREFIX = "lt:data:";
  static final String USED_KEY_PREFIX = "lt:used:";

  // Auth-session notes
  /** tokenId pending user-switch confirmation. */
  static final String NOTE_PENDING_TOKEN    = "lt_pending_token";
  /** Display name of the currently logged-in (cookie) user. */
  static final String NOTE_CURRENT_USERNAME = "lt_current_username";
  /** Display name of the login token target user. */
  static final String NOTE_TARGET_USERNAME  = "lt_target_username";

  private LoginTokenHelper() {}

  // -------------------------------------------------------------------------
  // Core verification pipeline
  // -------------------------------------------------------------------------

  /**
   * Full Login Token verification: Infinispan lookup → expiry → client → user → cookie
   * user-switch check → {@link #completeAuth}.
   *
   * <p>The two parameters capture the only behavioural differences between the two authenticators:
   *
   * @param onInvalidToken called when the token is not found, expired, or client-mismatched.
   *     {@link LoginTokenVerifier}: {@code clearLoginHint + context.attempted()}. {@link
   *     LoginTokenFormAuthenticator}: re-show form with an error message.
   * @param onAutoLogout called with the {@code tokenId} when a different user is already logged in
   *     AND the token's {@code confirmUserSwitch} flag is {@code false}. Pass {@code null} to
   *     always show the confirmation form regardless of that flag (used by the form authenticator).
   */
  static void handleTokenId(
      AuthenticationFlowContext context,
      String tokenId,
      Runnable onInvalidToken,
      Consumer<String> onAutoLogout) {

    SingleUseObjectProvider singleUse =
        context.getSession().getProvider(SingleUseObjectProvider.class);

    Map<String, String> notes = singleUse.get(DATA_KEY_PREFIX + tokenId);
    if (notes == null) {
      log.warnf("[LT] credential not found or expired for tokenId='%s'", tokenId);
      onInvalidToken.run();
      return;
    }

    // Validate expiry
    String expiryStr = notes.get(KEY_EXPIRY);
    if (expiryStr != null && System.currentTimeMillis() / 1000L > Long.parseLong(expiryStr)) {
      log.warnf("[LT] credential expired for tokenId='%s'", tokenId);
      onInvalidToken.run();
      return;
    }

    // Validate client
    String storedClientId = notes.get(KEY_CLIENT_ID);
    String sessionClientId = context.getAuthenticationSession().getClient().getClientId();
    if (storedClientId != null && !storedClientId.equals(sessionClientId)) {
      log.warnf("[LT] client mismatch: stored='%s', flow='%s'", storedClientId, sessionClientId);
      onInvalidToken.run();
      return;
    }

    // Resolve target user
    String userId = notes.get(KEY_USER_ID);
    UserModel targetUser = context.getSession().users().getUserById(context.getRealm(), userId);
    if (targetUser == null || !targetUser.isEnabled()) {
      log.warnf("[LT] user '%s' not found or disabled", userId);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return;
    }

    // Check for an existing session belonging to a different user.
    AuthenticationManager.AuthResult cookie =
        AuthenticationManager.authenticateIdentityCookie(
            context.getSession(), context.getRealm(), false);
    if (cookie != null
        && cookie.getUser() != null
        && !cookie.getUser().getId().equals(targetUser.getId())) {

      String currentDisplay = displayName(cookie.getUser());
      String targetDisplay  = displayName(targetUser);
      log.debugf("[LT] user switch required: '%s' → '%s'", currentDisplay, targetDisplay);

      boolean confirmFlag = "true".equalsIgnoreCase(notes.get(KEY_CONFIRM_USER_SWITCH));
      if (onAutoLogout != null && !confirmFlag) {
        // Auto-logout: caller (LoginTokenVerifier) handles the redirect.
        log.debugf("[LT] auto-logout: signing out '%s' to authenticate '%s'",
            currentDisplay, targetDisplay);
        onAutoLogout.accept(tokenId);
      } else {
        // Show confirmation form (always for the form authenticator; conditionally for the
        // verifier when confirmUserSwitch=true).
        showUserSwitchForm(context, tokenId, currentDisplay, targetDisplay);
      }
      return;
    }

    completeAuth(context, tokenId, notes, expiryStr, targetUser);
  }

  // -------------------------------------------------------------------------
  // User-switch confirmation form handling
  // -------------------------------------------------------------------------

  /**
   * Sets auth-session notes and renders {@code login-token-user-switch.ftl} to ask the user
   * whether they want to sign out of the current session and continue as the target user.
   */
  static void showUserSwitchForm(
      AuthenticationFlowContext context,
      String tokenId,
      String currentDisplay,
      String targetDisplay) {
    context.getAuthenticationSession().setAuthNote(NOTE_PENDING_TOKEN, tokenId);
    context.getAuthenticationSession().setAuthNote(NOTE_CURRENT_USERNAME, currentDisplay);
    context.getAuthenticationSession().setAuthNote(NOTE_TARGET_USERNAME, targetDisplay);

    Response challenge =
        context
            .form()
            .setAttribute("currentUsername", currentDisplay)
            .setAttribute("targetUsername", targetDisplay)
            .createForm("login-token-user-switch.ftl");
    context.challenge(challenge);
  }

  /**
   * Dispatches the user-switch confirmation form submission: {@code action=logout} delegates to
   * {@code onLogout}; any other value (i.e. "cancel") calls {@link #failWithAccessDenied}.
   *
   * @param onLogout called with {@code pendingToken} when the user confirms the logout.
   *     {@link LoginTokenVerifier}: redirects using the original {@code login_hint} from the auth
   *     session. {@link LoginTokenFormAuthenticator}: redirects using a reconstructed
   *     {@code login_hint=lt:{tokenId}}.
   */
  static void handleUserSwitchAction(
      AuthenticationFlowContext context,
      String pendingToken,
      Consumer<String> onLogout) {
    String action = context.getHttpRequest().getDecodedFormParameters().getFirst("action");
    if ("logout".equals(action)) {
      onLogout.accept(pendingToken);
    } else {
      failWithAccessDenied(context);
    }
  }

  /**
   * Redirects the browser back to the client's {@code redirect_uri} with {@code
   * error=access_denied}. Called when the user clicks "Cancel" on the user-switch confirmation
   * form.
   *
   * <p>A response is passed to {@code failure()} so Keycloak aborts the entire flow immediately;
   * without it, {@code failure()} on an ALTERNATIVE execution causes Keycloak to try the next
   * alternative instead of returning an error to the client.
   */
  static void failWithAccessDenied(AuthenticationFlowContext context) {
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    String state =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
    jakarta.ws.rs.core.UriBuilder errorUri =
        jakarta.ws.rs.core.UriBuilder.fromUri(redirectUri)
            .queryParam("error", "access_denied")
            .queryParam(
                "error_description", "User+cancelled+the+login+token+authentication");
    if (state != null && !state.isBlank()) {
      errorUri.queryParam("state", state);
    }
    context.failure(
        AuthenticationFlowError.ACCESS_DENIED,
        Response.seeOther(errorUri.build()).build());
  }

  // -------------------------------------------------------------------------
  // Post-confirmation redirect
  // -------------------------------------------------------------------------

  /**
   * Expires identity and auth-session cookies, then issues a 302 redirect to a fresh OIDC
   * authorization request.
   *
   * <p>The old user session is intentionally left alive in Infinispan; removing it inside this
   * request would conflict with Keycloak's session-persistence worker, producing a duplicate-key
   * DB error. It will expire naturally via its TTL.
   *
   * @param loginHint the {@code login_hint} value to include in the redirect URL.
   *     {@link LoginTokenVerifier}: the original {@code login_hint} from the auth session client
   *     note (already contains {@code lt:{tokenId}}).
   *     {@link LoginTokenFormAuthenticator}: {@code "lt:" + tokenId} reconstructed from the
   *     tokenId (the user typed the token manually, so no OIDC login_hint was set).
   */
  static void redirectAfterLogout(
      AuthenticationFlowContext context, String tokenId, String loginHint) {
    // Collect all auth-session params before expiring cookies (the auth session object
    // remains valid in-memory for this request even after the cookie is expired).
    String clientId    = context.getAuthenticationSession().getClient().getClientId();
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    String scope       =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);

    // Expire the Keycloak identity cookies (KEYCLOAK_IDENTITY / KEYCLOAK_SESSION) AND the
    // auth-session cookie (AUTH_SESSION_ID). Without expiring AUTH_SESSION_ID, the redirect
    // causes the browser to send the old auth-session cookie to the new auth request.
    // Keycloak then reuses the existing root auth session (linked to the old user's user session),
    // triggering a "different_user_authenticated" error even in the fresh flow.
    AuthenticationManager.expireIdentityCookie(context.getSession());
    context
        .getSession()
        .getProvider(org.keycloak.cookie.CookieProvider.class)
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

    log.debugf("[LT] cookie expiry + redirect for token '%s'", tokenId);
    context.challenge(
        Response.seeOther(authUri.build(context.getRealm().getName())).build());
  }

  // -------------------------------------------------------------------------
  // Auth completion
  // -------------------------------------------------------------------------

  /**
   * Removes {@code login_hint} and the attempted-username auth note from the current auth session
   * so downstream authenticators do not inherit a stale or expired login token hint.
   */
  static void clearLoginHint(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
    context.getAuthenticationSession().removeAuthNote(
        AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
  }

  static String displayName(UserModel user) {
    if (user.getEmail() != null && !user.getEmail().isBlank()) return user.getEmail();
    return user.getUsername();
  }

  static Integer resolveLoaLevel(AuthenticationFlowContext context, Map<String, String> notes) {
    String loaStr = notes.get(KEY_LOA);
    if (loaStr != null) {
      try {
        return Integer.parseInt(loaStr);
      } catch (NumberFormatException ignored) {
      }
    }

    String parentFlowId = context.getExecution().getParentFlow();
    List<AuthenticationExecutionModel> loaConditions =
        AuthenticatorUtil.getExecutionsByType(
            context.getRealm(), parentFlowId, ConditionalLoaAuthenticatorFactory.PROVIDER_ID);

    if (!loaConditions.isEmpty()) {
      String configId = loaConditions.get(0).getAuthenticatorConfig();
      Integer level =
          LoAUtil.getLevelFromLoaConditionConfiguration(
              context.getRealm().getAuthenticatorConfigById(configId));
      if (level != null) {
        log.debugf("[LT] LOA %d read from sibling Condition - Level of Authentication", level);
        return level;
      }
    }

    // Default: Login Token always grants at least LoA 1.
    // Without this, the session has no LoA and every subsequent auth request
    // triggers the Level-2 condition even when only LoA 1 was required.
    log.debugf(
        "[LT] no explicit LOA in token and no sibling condition found — defaulting to LOA 1");
    return 1;
  }

  /**
   * Enforces single-use, sets the user, applies optional email-verification / LOA / remember-me,
   * and calls {@code context.success()}.
   *
   * <p>On duplicate-use the method calls {@code context.failure(INVALID_CREDENTIALS)} and returns
   * without calling success.
   */
  static void completeAuth(
      AuthenticationFlowContext context,
      String tokenId,
      Map<String, String> notes,
      String expiryStr,
      UserModel user) {

    // Single-use enforcement
    boolean isReusable = "true".equalsIgnoreCase(notes.get(KEY_REUSABLE));
    if (!isReusable) {
      long remainingTtl =
          expiryStr != null
              ? Math.max(1L, Long.parseLong(expiryStr) - (System.currentTimeMillis() / 1000L))
              : 300L;
      if (!context
          .getSession()
          .getProvider(SingleUseObjectProvider.class)
          .putIfAbsent(USED_KEY_PREFIX + tokenId, remainingTtl)) {
        log.warnf("[LT] token already used: '%s'", tokenId);
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
      log.debugf("[LT] LOA %d set for user '%s'", loaLevel, user.getId());
      // Persist LOA_MAP directly to the UserSession note.
      // ConditionalLoaAuthenticator.onTopFlowSuccess() normally does this, but may not be
      // invoked when the LOA conditional sub-flow is skipped (because login token already
      // satisfied the requested LOA). Without this, auth-cookie cannot satisfy subsequent
      // re-auth requests and the login form is shown unnecessarily.
      context
          .getAuthenticationSession()
          .setUserSessionNote(
              Constants.LOA_MAP,
              context.getAuthenticationSession().getAuthNote(Constants.LOA_MAP));
    }

    if ("true".equalsIgnoreCase(notes.get(KEY_REMEMBER_ME))) {
      context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
    }

    clearLoginHint(context);
    String displayEmail = user.getEmail() != null ? user.getEmail() : user.getUsername();
    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, displayEmail);
    log.debugf("[LT] authentication complete for user '%s'", user.getId());
    context.success();
  }
}
