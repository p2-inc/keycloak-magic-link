package io.phasetwo.keycloak.magic.auth.token;

import io.phasetwo.keycloak.magic.MagicLink;
import java.util.Map;
import java.util.OptionalInt;
import javax.ws.rs.core.MultivaluedMap;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class MagicLinkAuthenticator extends AbstractUsernameFormAuthenticator
    implements Authenticator {

  static final String CREATE_NONEXISTENT_USER_CONFIG_PROPERTY = "ext-magic-create-nonexistent-user";

  @Override
  public void action(AuthenticationFlowContext context) {
    log.info("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = formData.getFirst("email");
    String clientId = context.getSession().getContext().getClient().getClientId();
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    log.infof("Attempting MagicLinkAuthenticator for %s, %s, %s", email, clientId, redirectUri);

    UserModel user =
        MagicLink.getOrCreate(context.getSession(), email, isForceCreate(context, false));
    MagicLinkActionToken token =
        MagicLink.createActionToken(user, clientId, redirectUri, OptionalInt.empty());
    String link = MagicLink.linkFromActionToken(context.getSession(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.infof("sent email to %s? %b. Link? %s", email, sent, link);

    context.setUser(user);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    if (v == null || "".equals(v)) return defaultValue;

    return v.trim().toLowerCase().equals("true");
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.info("MagicLinkAuthenticator.authenticate");
    /*
      String sessionKey = context.getAuthenticationSession().getAuthNote("email-key");
    if (sessionKey != null) {
      String requestKey = context.getHttpRequest().getUri().getQueryParameters().getFirst("key");
      if (requestKey != null) {
        if (requestKey.equals(sessionKey)) {
          context.success();
        } else {
          context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
      } else {
        context.challenge(context.form().createForm("view-email.ftl"));
      }
    } else {
      context.challenge(context.form().createForm("login-email-only.ftl"));
    }
    */
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
