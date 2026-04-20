package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.TURNSTILE_FAILED;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class ConditionalTurnstileFailedAuthenticator implements ConditionalAuthenticator {

  public static final String CONF_NEGATE = "negate";

  public static final ConditionalTurnstileFailedAuthenticator SINGLETON =
      new ConditionalTurnstileFailedAuthenticator();

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    String turnstileFailed = context.getAuthenticationSession().getAuthNote(TURNSTILE_FAILED);
    boolean matched = "true".equals(turnstileFailed);

    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config != null && Boolean.parseBoolean(config.getConfig().get(CONF_NEGATE))) {
      matched = !matched;
    }

    log.tracef("ConditionalTurnstileFailed: matchCondition=%b", matched);
    return matched;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    context.success();
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
