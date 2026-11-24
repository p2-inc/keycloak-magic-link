package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CLIENT_ID;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CONFIRM_USER_SWITCH;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_EXPIRY;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_LOA;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_MAX_USES;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REMEMBER_ME;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REUSABLE;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_SEV;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_USER_ID;

import io.phasetwo.keycloak.magic.auth.token.LoginTokenKeys;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
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
 *   <li>{@link #handleUserSwitchAction} — logout / cancel dispatch for the user-switch confirmation
 *       form.
 *   <li>{@link #redirectAfterLogout} — cookie expiry + fresh OIDC auth redirect.
 *   <li>{@link #completeAuth} — use-limit enforcement, user/LOA/remember-me setup, {@code
 *       context.success()}.
 * </ul>
 */
@JBossLog
class LoginTokenHelper {

  // Infinispan key prefixes
  static final String RESUME_PREFIX = "lt:";
  static final String DATA_KEY_PREFIX = "lt:data:";
  static final String USED_KEY_PREFIX = "lt:used:";

  /** How long a use marker is kept beyond the token's expiry. */
  static final long USE_MARKER_GRACE_SECONDS = 60L;

  /**
   * Execution config key for the "Client ID must match" toggle shared by all Login Token
   * authenticators. Default (unset or {@code "true"}): only tokens carrying a {@code clientId} are
   * accepted, and it must equal the client of the current session. When {@code "false"}, tokens
   * created <em>without</em> a {@code client_id} ("universal" tokens, e.g. for QR-code login) are
   * accepted as well — but a client binding that <em>is</em> present on the token is still
   * enforced; a mismatch is always rejected.
   */
  static final String REQUIRE_CLIENT_BINDING_CONFIG_PROPERTY =
      "ext-login-token-require-client-binding";

  // Direct-grant verification result codes (see verifyDirectGrant)
  /** Token missing, expired, client-mismatched, or already redeemed. */
  static final String DG_INVALID_TOKEN = "invalid_token";

  /** Resolved user does not exist or is disabled. */
  static final String DG_USER_DISABLED = "user_disabled";

  // Auth-session notes
  /** tokenId pending user-switch confirmation. */
  static final String NOTE_PENDING_TOKEN = "lt_pending_token";

  /** Display name of the currently logged-in (cookie) user. */
  static final String NOTE_CURRENT_USERNAME = "lt_current_username";

  /** Display name of the login token target user. */
  static final String NOTE_TARGET_USERNAME = "lt_target_username";

  private LoginTokenHelper() {}

  // -------------------------------------------------------------------------
  // Shared lookup + validation
  // -------------------------------------------------------------------------

  /** Outcome of {@link #lookupAndValidate}. */
  enum LookupStatus {
    OK,
    /** Token not found, expired, malformed, or client-mismatched. */
    INVALID,
    /** Token resolved to a user that does not exist or is disabled. */
    USER_DISABLED
  }

  /** Result of {@link #lookupAndValidate}; the data fields are only set when {@code status == OK}. */
  static final class ResolvedToken {
    final LookupStatus status;
    final Map<String, String> notes;
    final String expiryStr;
    final UserModel user;

    /**
     * Identity under which redemptions are counted: the UUID of a legacy token, the nonce of a
     * stateless one.
     */
    final String useId;

    private ResolvedToken(
        LookupStatus status,
        Map<String, String> notes,
        String expiryStr,
        UserModel user,
        String useId) {
      this.status = status;
      this.notes = notes;
      this.expiryStr = expiryStr;
      this.user = user;
      this.useId = useId;
    }

    static ResolvedToken invalid() {
      return new ResolvedToken(LookupStatus.INVALID, null, null, null, null);
    }

    static ResolvedToken userDisabled() {
      return new ResolvedToken(LookupStatus.USER_DISABLED, null, null, null, null);
    }

    static ResolvedToken ok(
        Map<String, String> notes, String expiryStr, UserModel user, String useId) {
      return new ResolvedToken(LookupStatus.OK, notes, expiryStr, user, useId);
    }
  }

  /**
   * Shared token resolution used by both the browser ({@link #handleTokenId}) and direct-grant
   * ({@link #verifyDirectGrant}) flows: credential resolution (Infinispan lookup for a legacy
   * token, decryption for a stateless one) → expiry → client binding → user resolution. Does not perform the cookie user-switch check or the single-use reservation, and
   * never touches the flow context — each caller decides how to signal the outcome.
   *
   * <p>Client binding: a {@code clientId} stored on the token must always match the session's
   * client. A token <em>without</em> a stored {@code clientId} is only accepted when the
   * execution's {@link #REQUIRE_CLIENT_BINDING_CONFIG_PROPERTY} config is set to {@code false}.
   *
   * <p>A present-but-non-numeric {@code expiry} note is treated as {@link LookupStatus#INVALID}
   * rather than propagating a {@link NumberFormatException}.
   */
  static ResolvedToken lookupAndValidate(AuthenticationFlowContext context, String tokenId) {
    // Never log a token id itself: it is a bearer credential in both formats.
    String logId = StatelessLoginToken.logId(tokenId);

    Map<String, String> notes;
    String useId;
    if (StatelessLoginToken.isStateless(tokenId)) {
      Optional<StatelessLoginToken.Payload> payload =
          StatelessLoginToken.open(
              LoginTokenKeys.decryptionKeys(context.getSession(), context.getRealm()),
              context.getRealm().getId(),
              tokenId);
      if (payload.isEmpty()) {
        log.warnf("[LT] stateless token could not be decrypted for tokenId='%s'", logId);
        return ResolvedToken.invalid();
      }
      notes = payload.get().toNotes();
      useId = payload.get().getUseId();
    } else {
      notes =
          context
              .getSession()
              .getProvider(SingleUseObjectProvider.class)
              .get(DATA_KEY_PREFIX + tokenId);
      if (notes == null) {
        log.warnf("[LT] credential not found or expired for tokenId='%s'", logId);
        return ResolvedToken.invalid();
      }
      useId = tokenId;
    }

    String expiryStr = notes.get(KEY_EXPIRY);
    if (expiryStr != null) {
      long expiry;
      try {
        expiry = Long.parseLong(expiryStr);
      } catch (NumberFormatException e) {
        log.warnf("[LT] malformed expiry '%s' for tokenId='%s'", expiryStr, logId);
        return ResolvedToken.invalid();
      }
      if (System.currentTimeMillis() / 1000L > expiry) {
        log.warnf("[LT] credential expired for tokenId='%s'", logId);
        return ResolvedToken.invalid();
      }
    }

    String storedClientId = notes.get(KEY_CLIENT_ID);
    if (storedClientId == null) {
      // Unbound ("universal") token: only accepted when this execution explicitly opted out of
      // client binding via the "Client ID must match" config toggle.
      if (isClientBindingRequired(context)) {
        log.warnf(
            "[LT] unbound token rejected for tokenId='%s' (execution requires client binding)",
            logId);
        return ResolvedToken.invalid();
      }
    } else {
      // A client binding present on the token is ALWAYS enforced, regardless of the
      // "Client ID must match" toggle — the token creator explicitly requested it.
      String sessionClientId = context.getAuthenticationSession().getClient().getClientId();
      if (!storedClientId.equals(sessionClientId)) {
        log.warnf("[LT] client mismatch: stored='%s', flow='%s'", storedClientId, sessionClientId);
        return ResolvedToken.invalid();
      }
    }

    String userId = notes.get(KEY_USER_ID);
    UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
    if (user == null || !user.isEnabled()) {
      log.warnf("[LT] user '%s' not found or disabled", userId);
      return ResolvedToken.userDisabled();
    }

    return ResolvedToken.ok(notes, expiryStr, user, useId);
  }

  /**
   * Reads the "Client ID must match" toggle from the execution's authenticator config. Defaults to
   * {@code true} (strict) when no config is attached to the execution or the property is unset —
   * accepting unbound tokens is an explicit per-execution opt-in.
   */
  static boolean isClientBindingRequired(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null || config.getConfig() == null) {
      return true;
    }
    String value = config.getConfig().get(REQUIRE_CLIENT_BINDING_CONFIG_PROPERTY);
    if (value == null) {
      return true;
    }
    return Boolean.parseBoolean(value);
  }

  /**
   * Builds the "Client ID must match" {@link ProviderConfigProperty} shown in the admin console
   * for all three Login Token authenticator factories.
   */
  static ProviderConfigProperty requireClientBindingConfigProperty() {
    ProviderConfigProperty prop = new ProviderConfigProperty();
    prop.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    prop.setName(REQUIRE_CLIENT_BINDING_CONFIG_PROPERTY);
    prop.setLabel("Client ID must match");
    prop.setHelpText(
        "When ON (default), a login token must carry a client_id and it must match the client of"
            + " the current session. When OFF, tokens created without a client_id (universal"
            + " tokens, e.g. for QR-code login) are accepted as well. A client_id that is present"
            + " on the token is always enforced, even when this option is OFF.");
    prop.setDefaultValue("true");
    return prop;
  }

  // -------------------------------------------------------------------------
  // Core verification pipeline
  // -------------------------------------------------------------------------

  /**
   * Full Login Token verification: credential resolution → expiry → client → user → cookie user-switch
   * check → {@link #completeAuth}.
   *
   * <p>The two parameters capture the only behavioural differences between the two authenticators:
   *
   * @param onInvalidToken called when the token is not found, expired, or client-mismatched. {@link
   *     LoginTokenVerifier}: {@code clearLoginHint + context.attempted()}. {@link
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

    ResolvedToken resolved = lookupAndValidate(context, tokenId);
    switch (resolved.status) {
      case INVALID:
        onInvalidToken.run();
        return;
      case USER_DISABLED:
        // Do not leave the token behind as a username suggestion for the next authenticator.
        clearLoginHint(context);
        context.failure(AuthenticationFlowError.USER_DISABLED);
        return;
      default:
        break;
    }

    Map<String, String> notes = resolved.notes;
    String expiryStr = resolved.expiryStr;
    UserModel targetUser = resolved.user;

    // Check for an existing session belonging to a different user.
    AuthenticationManager.AuthResult cookie =
        AuthenticationManager.authenticateIdentityCookie(
            context.getSession(), context.getRealm(), false);
    if (cookie != null
        && cookie.getUser() != null
        && !cookie.getUser().getId().equals(targetUser.getId())) {

      String currentDisplay = displayName(cookie.getUser());
      String targetDisplay = displayName(targetUser);
      log.debugf("[LT] user switch required: '%s' → '%s'", currentDisplay, targetDisplay);

      boolean confirmFlag = "true".equalsIgnoreCase(notes.get(KEY_CONFIRM_USER_SWITCH));
      if (onAutoLogout != null && !confirmFlag) {
        // Auto-logout: caller (LoginTokenVerifier) handles the redirect.
        log.debugf(
            "[LT] auto-logout: signing out '%s' to authenticate '%s'",
            currentDisplay, targetDisplay);
        onAutoLogout.accept(tokenId);
      } else {
        // Show confirmation form (always for the form authenticator; conditionally for the
        // verifier when confirmUserSwitch=true).
        showUserSwitchForm(context, tokenId, currentDisplay, targetDisplay);
      }
      return;
    }

    completeAuth(context, resolved.useId, notes, expiryStr, targetUser, onInvalidToken);
  }

  // -------------------------------------------------------------------------
  // User-switch confirmation form handling
  // -------------------------------------------------------------------------

  /**
   * Sets auth-session notes and renders {@code login-token-user-switch.ftl} to ask the user whether
   * they want to sign out of the current session and continue as the target user.
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
   * @param onLogout called with {@code pendingToken} when the user confirms the logout. {@link
   *     LoginTokenVerifier}: redirects using the original {@code login_hint} from the auth session.
   *     {@link LoginTokenFormAuthenticator}: redirects using a reconstructed {@code
   *     login_hint=lt:{tokenId}}.
   */
  static void handleUserSwitchAction(
      AuthenticationFlowContext context, String pendingToken, Consumer<String> onLogout) {
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
    String state = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
    jakarta.ws.rs.core.UriBuilder errorUri =
        jakarta.ws.rs.core.UriBuilder.fromUri(redirectUri)
            .queryParam("error", "access_denied")
            .queryParam("error_description", "User+cancelled+the+login+token+authentication");
    if (state != null && !state.isBlank()) {
      errorUri.queryParam("state", state);
    }
    context.failure(
        AuthenticationFlowError.ACCESS_DENIED, Response.seeOther(errorUri.build()).build());
  }

  // -------------------------------------------------------------------------
  // Post-confirmation redirect
  // -------------------------------------------------------------------------

  /**
   * Expires identity and auth-session cookies, then issues a 302 redirect to a fresh OIDC
   * authorization request.
   *
   * <p>The old user session is intentionally left alive in Infinispan; removing it inside this
   * request would conflict with Keycloak's session-persistence worker, producing a duplicate-key DB
   * error. It will expire naturally via its TTL.
   *
   * @param loginHint the {@code login_hint} value to include in the redirect URL. {@link
   *     LoginTokenVerifier}: the original {@code login_hint} from the auth session client note
   *     (already contains {@code lt:{tokenId}}). {@link LoginTokenFormAuthenticator}: {@code "lt:"
   *     + tokenId} reconstructed from the tokenId (the user typed the token manually, so no OIDC
   *     login_hint was set).
   */
  static void redirectAfterLogout(
      AuthenticationFlowContext context, String tokenId, String loginHint) {
    // Collect all auth-session params before expiring cookies (the auth session object
    // remains valid in-memory for this request even after the cookie is expired).
    String clientId = context.getAuthenticationSession().getClient().getClientId();
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    String scope = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
    String codeChallenge =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
    String codeChallengeMethod =
        context
            .getAuthenticationSession()
            .getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM);
    String state = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
    String nonce = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);

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
        jakarta.ws.rs.core.UriBuilder.fromUri(
                context.getSession().getContext().getUri().getBaseUri())
            .path("realms/{realm}/protocol/openid-connect/auth")
            .queryParam("client_id", clientId)
            .queryParam("response_type", "code")
            .queryParam("login_hint", loginHint)
            .queryParam("prompt", "login")
            .queryParam("redirect_uri", redirectUri);
    if (scope != null && !scope.isBlank()) {
      authUri.queryParam("scope", scope);
    }
    if (codeChallenge != null && !codeChallenge.isBlank()) {
      authUri.queryParam("code_challenge", codeChallenge);
    }
    if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
      authUri.queryParam("code_challenge_method", codeChallengeMethod);
    }
    if (state != null && !state.isBlank()) {
      authUri.queryParam("state", state);
    }
    if (nonce != null && !nonce.isBlank()) {
      authUri.queryParam("nonce", nonce);
    }

    log.debugf("[LT] cookie expiry + redirect for token '%s'", StatelessLoginToken.logId(tokenId));
    context.challenge(Response.seeOther(authUri.build(context.getRealm().getName())).build());
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
    context
        .getAuthenticationSession()
        .removeAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
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
   * Enforces the token's use limit, sets the user, applies optional email-verification / LOA /
   * remember-me, and calls {@code context.success()}.
   *
   * <p>A token whose uses are exhausted is handled exactly like an expired or unknown one: {@code
   * onInvalidToken} runs and success is not called. Failing the execution instead would let the
   * flow fall through to the next alternative with the token still in {@code login_hint}, where
   * the username form would offer it as the username.
   *
   * @param useId identity under which redemptions are counted, see {@link ResolvedToken#useId}.
   * @param onInvalidToken the caller's reaction to an unusable token, see {@link #handleTokenId}.
   */
  static void completeAuth(
      AuthenticationFlowContext context,
      String useId,
      Map<String, String> notes,
      String expiryStr,
      UserModel user,
      Runnable onInvalidToken) {

    if (!reserveUse(context, useId, notes, expiryStr)) {
      onInvalidToken.run();
      return;
    }

    applyAuthenticatedUser(context, notes, user);
  }

  /**
   * Number of redemptions the token allows; {@code 0} means unlimited. Tokens stored by a version
   * that predates {@code maxUses} carry only the {@code reusable} flag: unlimited when {@code
   * true}, single use otherwise. A malformed or negative value is treated as single use, so a
   * damaged note can never widen a token's use limit.
   */
  static int maxUses(Map<String, String> notes) {
    String value = notes.get(KEY_MAX_USES);
    if (value == null) {
      return "true".equalsIgnoreCase(notes.get(KEY_REUSABLE)) ? 0 : 1;
    }
    try {
      int maxUses = Integer.parseInt(value);
      return maxUses < 0 ? 1 : Math.min(StatelessLoginToken.MAX_USES_LIMIT, maxUses);
    } catch (NumberFormatException e) {
      return 1;
    }
  }

  /**
   * Atomically claims one of the token's allowed redemptions. Each redemption occupies one slot in
   * {@link SingleUseObjectProvider} — {@code lt:used:{useId}} for the first, {@code
   * lt:used:{useId}:{n}} for the n-th — created with {@code putIfAbsent}, the only atomic primitive
   * the provider offers. Concurrent redemptions therefore never share a slot. Slots live until the
   * token expires; unlimited tokens store nothing.
   *
   * <p>This method has no side effect on the flow context — the caller decides how to signal an
   * exhausted token (the browser authenticators fail without a response; the direct-grant
   * authenticator returns an OAuth error response).
   *
   * @return {@code false} if every allowed redemption was already claimed, {@code true} otherwise.
   */
  static boolean reserveUse(
      AuthenticationFlowContext context,
      String useId,
      Map<String, String> notes,
      String expiryStr) {
    int maxUses = maxUses(notes);
    if (maxUses == 0) {
      return true;
    }
    // The markers must outlive the token: it is accepted until the end of its expiry second, and
    // nodes do not share one clock. A marker that expired first would hand the uses back.
    long remainingTtl =
        (expiryStr != null
                ? Math.max(0L, Long.parseLong(expiryStr) - (System.currentTimeMillis() / 1000L))
                : 300L)
            + USE_MARKER_GRACE_SECONDS;
    SingleUseObjectProvider singleUse =
        context.getSession().getProvider(SingleUseObjectProvider.class);
    for (int slot = 1; slot <= maxUses; slot++) {
      String key = slot == 1 ? USED_KEY_PREFIX + useId : USED_KEY_PREFIX + useId + ":" + slot;
      if (singleUse.putIfAbsent(key, remainingTtl)) {
        return true;
      }
    }
    log.warnf("[LT] token use limit (%d) reached", maxUses);
    return false;
  }

  /**
   * Sets the authenticated user on the context, applies optional email-verification / LOA /
   * remember-me from the token notes, and calls {@code context.success()}. Assumes a redemption
   * has already been claimed via {@link #reserveUse}.
   */
  private static void applyAuthenticatedUser(
      AuthenticationFlowContext context, Map<String, String> notes, UserModel user) {
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
              Constants.LOA_MAP, context.getAuthenticationSession().getAuthNote(Constants.LOA_MAP));
    }

    if ("true".equalsIgnoreCase(notes.get(KEY_REMEMBER_ME))) {
      // Only honor remember_me when the realm has it enabled. Since Keycloak 26.5.0
      // (also backported to 26.4.2 / 26.2.12), AuthenticationManager.isSessionValid()
      // treats sessions created with rememberMe=true as invalid when the realm has
      // remember me disabled — the subsequent code exchange then fails with
      // "Session not active".
      if (context.getRealm().isRememberMe()) {
        context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
      } else {
        log.debugf(
            "[LT] ignoring remember_me: remember me is disabled for realm '%s'",
            context.getRealm().getName());
      }
    }

    clearLoginHint(context);
    String displayEmail = user.getEmail() != null ? user.getEmail() : user.getUsername();
    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, displayEmail);
    log.debugf("[LT] authentication complete for user '%s'", user.getId());
    context.success();
  }

  // -------------------------------------------------------------------------
  // Direct-grant verification (non-interactive, no browser)
  // -------------------------------------------------------------------------

  /**
   * Verifies a Login Token in a non-interactive Direct Grant (Resource Owner Password Credentials)
   * flow. Runs the same credential resolution → expiry → client → user-resolution → use limit → {@code
   * context.success()} pipeline as {@link #handleTokenId}, but deliberately omits the cookie
   * user-switch check and never renders a browser challenge — a direct grant has no browser session
   * to switch and cannot present forms or redirects.
   *
   * <p>On success {@code context.success()} has already been called and this method returns {@code
   * null}. On failure the context is left untouched (so the caller can attach an OAuth error
   * response) and a machine-readable result code is returned. The specific reason is logged but
   * collapsed into a generic {@link #DG_INVALID_TOKEN} for invalid/expired/client/used tokens to
   * avoid leaking which check failed.
   *
   * @return {@code null} on success, otherwise {@link #DG_INVALID_TOKEN} or {@link
   *     #DG_USER_DISABLED}.
   */
  static String verifyDirectGrant(AuthenticationFlowContext context, String tokenId) {
    ResolvedToken resolved = lookupAndValidate(context, tokenId);
    switch (resolved.status) {
      case INVALID:
        return DG_INVALID_TOKEN;
      case USER_DISABLED:
        return DG_USER_DISABLED;
      default:
        break;
    }

    if (!reserveUse(context, resolved.useId, resolved.notes, resolved.expiryStr)) {
      return DG_INVALID_TOKEN;
    }

    applyAuthenticatedUser(context, resolved.notes, resolved.user);
    return null;
  }
}
