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
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import java.util.Map;

/**
 * Handles the magic link continuation action token
 */
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
        user.setEmailVerified(true);

        SingleUseObjectProvider singleUseObjects = tokenContext.getSession().singleUseObjects();
        LoginFormsProvider loginFormsProvider =  tokenContext.getSession().getProvider(LoginFormsProvider.class);
        var session = singleUseObjects.get(token.getSessionId());
        if (session != null) {
            singleUseObjects.replace(token.getSessionId(), Map.of(SESSION_CONFIRMED, "true"));
            Cookie cookie =
                    tokenContext.getSession()
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

        tokenContext.getEvent().error("Expired magic link continuation session!");
        return loginFormsProvider.createForm("email-confirmation-error.ftl");
    }
}
