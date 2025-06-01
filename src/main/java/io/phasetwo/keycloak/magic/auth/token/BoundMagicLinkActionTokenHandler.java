package io.phasetwo.keycloak.magic.auth.token;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.cookie.CookieType;
import org.keycloak.events.Errors;

@JBossLog
public class BoundMagicLinkActionTokenHandler extends MagicLinkActionTokenHandler {

  public BoundMagicLinkActionTokenHandler() {
    super();
  }

  @Override
  public Response handleToken(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    log.debugf("Handling bound magic link token");

    if (token instanceof BoundMagicLinkActionToken boundToken) {
      // Check if the session ID in the cookie matches the one in the token
      Cookie cookie = tokenContext.getRequest().getHttpHeaders().getCookies().get(CookieType.AUTH_SESSION_ID.getName());
      if (cookie == null || !cookie.getValue().equals(boundToken.getCookieSid())) {
        log.warn("Auth session cookie missing or doesn't match the token");
        tokenContext.getEvent().error(Errors.INVALID_CODE);
        return tokenContext.getSession().getProvider(org.keycloak.forms.login.LoginFormsProvider.class)
            .setError("invalidMagicLinkCookie")
            .createErrorPage(Response.Status.BAD_REQUEST);
      }
      log.debug("Cookie authentication successful");
    }

    return super.handleToken(token, tokenContext);
  }
}
