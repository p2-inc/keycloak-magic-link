package io.phasetwo.keycloak.magic.auth.token;

import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Handles the magic link action token by logging the user in and forwarding to the redirect uri.
 */
@JBossLog
public class ExpandedMagicLinkActionTokenHandler
        extends AbstractActionTokenHandler<ExpandedMagicLinkActionToken> {

    public static final String VALID_SESSION = "VALID_SESSION";

    public ExpandedMagicLinkActionTokenHandler() {
        super(
                ExpandedMagicLinkActionToken.TOKEN_TYPE,
                ExpandedMagicLinkActionToken.class,
                Messages.INVALID_REQUEST,
                EventType.EXECUTE_ACTION_TOKEN,
                Errors.INVALID_REQUEST);
    }

    @Override
    public Response handleToken(
            ExpandedMagicLinkActionToken token,
            ActionTokenContext<ExpandedMagicLinkActionToken> tokenContext) {

        log.infof("handleToken for iss:%s, user:%s", token.getIssuedFor(), token.getUserId());
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();

        final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        final RootAuthenticationSessionModel rootSession = authSession.getParentSession();
        final ClientModel client = authSession.getClient();

        user.setEmailVerified(true);
        KeycloakSession session = tokenContext.getSession();
        AuthenticationSessionProvider provider = session.authenticationSessions();
        RootAuthenticationSessionModel m = provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());

        log.infof("root session orig %s, handler %s", rootSession.getId(), m.getId());
        
        AuthenticationSessionModel asm = m.getAuthenticationSession(client, token.getTabId());

        asm.setAuthNote(VALID_SESSION, "true");

        LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);
        return loginFormsProvider.createForm("email-confirmation.ftl");
    }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(ExpandedMagicLinkActionToken token, ActionTokenContext<ExpandedMagicLinkActionToken> tokenContext) {
    log.infof("startFreshAuthenticationSession %s", token.getIssuedFor());

    ClientModel client = tokenContext.getSession().clients().getClientByClientId(tokenContext.getRealm(), token.getIssuedFor());
    AuthenticationSessionProvider provider = tokenContext.getSession().authenticationSessions();
    RootAuthenticationSessionModel m = provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    AuthenticationSessionModel authSession = m.createAuthenticationSession(client);
    
    //AuthenticationSessionModel authSession = tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
    //authSession.setAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS, "true");
    return authSession;
  }
    

}
