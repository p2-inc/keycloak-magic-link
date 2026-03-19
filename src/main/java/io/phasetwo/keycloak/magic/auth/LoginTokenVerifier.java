package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.LoginTokenHelper.*;

import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

/**
 * Authenticator that completes Login Token authentication inside the Keycloak browser flow via
 * {@code login_hint}.
 *
 * <h3>Flow</h3>
 *
 * <ol>
 *   <li>Backend calls {@code POST /realms/{realm}/login-token} to obtain a UUID credential
 *       reference stored in {@link org.keycloak.models.SingleUseObjectProvider} (Infinispan).
 *   <li>The app opens an OIDC auth URL with {@code login_hint=lt:{uuid}}.
 *   <li>This authenticator reads {@code login_hint}, looks up the credential by UUID, validates
 *       expiry and client. If an existing session for a <em>different</em> user is found, a
 *       confirmation form is shown (or the session is expired silently if {@code
 *       confirmUserSwitch=false}). Otherwise the authenticator enforces single-use, sets the user
 *       and optional LOA, and calls {@code context.success()}.
 *   <li>Subsequent authenticators (e.g. TOTP for LOA=2) run in the same browser session.
 * </ol>
 *
 * <h3>Placement</h3>
 *
 * Add as <strong>ALTERNATIVE</strong> <em>before Cookie</em> in the browser flow so that
 * {@code login_hint} is evaluated before the Cookie authenticator can short-circuit the flow with a
 * different user's existing session.
 *
 * <p>All shared logic lives in {@link LoginTokenHelper}. For manual token entry via a UI form see
 * {@link LoginTokenFormAuthenticator}.
 */
@JBossLog
public class LoginTokenVerifier implements Authenticator {

  /**
   * Public delegates kept for backward compatibility — {@code LoginTokenResource} and any other
   * code outside the {@code auth} package references these constants.
   */
  public static final String RESUME_PREFIX   = LoginTokenHelper.RESUME_PREFIX;
  public static final String DATA_KEY_PREFIX = LoginTokenHelper.DATA_KEY_PREFIX;

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String loginHint =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

    if (loginHint == null || !loginHint.startsWith(RESUME_PREFIX)) {
      context.attempted();
      return;
    }

    String tokenId = loginHint.substring(RESUME_PREFIX.length());
    LoginTokenHelper.handleTokenId(
        context,
        tokenId,
        () -> { clearLoginHint(context); context.attempted(); },
        tid -> {
          String hint =
              context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
          log.debugf("[LT] auto-logout for token '%s'", tid);
          LoginTokenHelper.redirectAfterLogout(context, tid, hint);
        });
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    String pendingToken = context.getAuthenticationSession().getAuthNote(NOTE_PENDING_TOKEN);
    if (pendingToken == null) {
      context.attempted();
      return;
    }

    LoginTokenHelper.handleUserSwitchAction(
        context,
        pendingToken,
        tid -> {
          String hint =
              context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
          log.debugf(
              "[LT] user-switch confirmed, expiring cookies and redirecting for token '%s'", tid);
          LoginTokenHelper.redirectAfterLogout(context, tid, hint);
        });
  }

  // -------------------------------------------------------------------------

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
