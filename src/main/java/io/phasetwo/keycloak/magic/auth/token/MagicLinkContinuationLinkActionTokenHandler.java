package io.phasetwo.keycloak.magic.auth.token;

import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.SESSION_CONFIRMED;

import io.phasetwo.keycloak.magic.auth.model.MagicLinkContinuationBean;
import io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/** Handles the magic link continuation action token */
@JBossLog
public class MagicLinkContinuationLinkActionTokenHandler
    extends AbstractActionTokenHandler<MagicLinkContinuationActionToken> {

  public MagicLinkContinuationLinkActionTokenHandler() {
    super(
        MagicLinkContinuationActionToken.TOKEN_TYPE,
        MagicLinkContinuationActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  @Override
  public Response handleToken(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    log.debugf("HandleToken for iss:%s, user:%s", token.getIssuedFor(), token.getUserId());
    UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();

    final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    final ClientModel client = authSession.getClient();

    user.setEmailVerified(true);
    KeycloakSession session = tokenContext.getSession();
    AuthenticationSessionProvider provider = session.authenticationSessions();
    RootAuthenticationSessionModel rootAuthenticationSession =
        provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);

    if (rootAuthenticationSession != null) {
      AuthenticationSessionModel authenticationFlowSession =
          rootAuthenticationSession.getAuthenticationSession(client, token.getTabId());
      if (authenticationFlowSession != null) {
        authenticationFlowSession.setAuthNote(SESSION_CONFIRMED, "true");
        Cookie cookie =
            session
                .getContext()
                .getRequestHeaders()
                .getCookies()
                .get(MagicLinkConstants.AUTH_SESSION_ID);

        boolean sameBrowser = cookie != null && cookie.getValue().equals(token.getSessionId());
        MagicLinkContinuationBean magicLinkContinuationBean =
            new MagicLinkContinuationBean(sameBrowser, token.getRedirectUri());
        tokenContext.getEvent().success();

        return loginFormsProvider
            .setAttribute("magicLinkContinuation", magicLinkContinuationBean)
            .createForm("email-confirmation.ftl");
      }
    }

    tokenContext.getEvent().error("Expired magic link continuation session!");
    return loginFormsProvider.createForm("email-confirmation-error.ftl");
  }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    log.debugf("startFreshAuthenticationSession %s", token.getIssuedFor());

    ClientModel client =
        tokenContext
            .getSession()
            .clients()
            .getClientByClientId(tokenContext.getRealm(), token.getIssuedFor());
    AuthenticationSessionProvider provider = tokenContext.getSession().authenticationSessions();
    RootAuthenticationSessionModel rootAuthenticationSession =
        provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    if (rootAuthenticationSession == null) {
      AuthenticationSessionModel authSession =
          tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
      authSession.setAuthNote(AuthenticationManager.INVALIDATE_ACTION_TOKEN, "true");
      return authSession;
    }

    AuthenticationSessionModel authSession =
        rootAuthenticationSession.createAuthenticationSession(client);
    return authSession;
  }
}
