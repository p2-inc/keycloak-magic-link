package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.LoginTokenHelper.*;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Browser-flow authenticator that presents a form for manual Login Token entry.
 *
 * <p>Accepts the token with or without the {@code lt:} prefix — the prefix is added automatically
 * if absent. On validation failure the form is re-shown with an error message; the flow never falls
 * through to the next alternative silently.
 *
 * <h3>User-switch behaviour</h3>
 *
 * When a user-switch is needed (an active session exists for a different user), the confirmation
 * form ({@code login-token-user-switch.ftl}) is always shown regardless of the token's {@code
 * confirmUserSwitch} flag. Auto-logout without confirmation is inappropriate in an interactive form
 * context. After the user confirms, session cookies are expired and the browser is redirected to a
 * fresh OIDC auth URL with {@code login_hint=lt:{tokenId}} so that {@link LoginTokenVerifier} can
 * complete authentication automatically if it is present in the same flow.
 *
 * <h3>Placement</h3>
 *
 * Add as <strong>ALTERNATIVE</strong> or <strong>REQUIRED</strong> in the browser flow. Unlike
 * {@link LoginTokenVerifier}, this authenticator always shows UI — do not place it before Cookie
 * unless you want every unauthenticated visit to show the token form.
 *
 * <p>All shared logic lives in {@link LoginTokenHelper}.
 */
@JBossLog
public class LoginTokenFormAuthenticator implements Authenticator {

  /** Form field name for the token input. */
  static final String FORM_FIELD = "login_token";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    context.challenge(context.form().createForm("login-token-form.ftl"));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // User-switch confirmation re-posts to this action.
    String pendingToken = context.getAuthenticationSession().getAuthNote(NOTE_PENDING_TOKEN);
    if (pendingToken != null) {
      LoginTokenHelper.handleUserSwitchAction(
          context,
          pendingToken,
          tid -> {
            log.debugf(
                "[LT-form] user-switch confirmed, expiring cookies and redirecting for token '%s'",
                tid);
            // Reconstruct login_hint from tokenId — the user typed the token manually, so no
            // OIDC login_hint was present in the original auth request.
            LoginTokenHelper.redirectAfterLogout(context, tid, RESUME_PREFIX + tid);
          });
      return;
    }

    // Initial token form submission.
    String input = context.getHttpRequest().getDecodedFormParameters().getFirst(FORM_FIELD);
    if (input == null || input.isBlank()) {
      showFormError(context, "loginTokenRequired");
      return;
    }

    String tokenId = input.trim();
    if (tokenId.startsWith(RESUME_PREFIX)) {
      tokenId = tokenId.substring(RESUME_PREFIX.length());
    }

    // Pass null for onAutoLogout — form always shows confirmation, never auto-logs-out.
    LoginTokenHelper.handleTokenId(
        context,
        tokenId,
        () -> showFormError(context, "loginTokenInvalid"),
        null);
  }

  // -------------------------------------------------------------------------

  private void showFormError(AuthenticationFlowContext context, String errorKey) {
    context.challenge(
        context.form().setError(errorKey).createForm("login-token-form.ftl"));
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
