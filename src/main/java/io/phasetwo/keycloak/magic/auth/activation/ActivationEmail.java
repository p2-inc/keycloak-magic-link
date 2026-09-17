package io.phasetwo.keycloak.magic.auth.activation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import io.phasetwo.keycloak.magic.MagicLink;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Builds and sends account-activation emails carrying a standard Keycloak {@link
 * ExecuteActionsActionToken}, so the emailed link opens the required actions directly in whatever
 * browser it is clicked in (handled entirely by Keycloak core) and then redirects back to the
 * client.
 */
@JBossLog
final class ActivationEmail {

  static final String EMAIL_TEMPLATE = "activation-email.ftl";
  static final String EMAIL_SUBJECT_KEY = "activationEmailSubject";

  private ActivationEmail() {}

  /** Serializes an execute-actions token for the user and returns the action token URL. */
  static String buildLink(
      AuthenticationFlowContext context, UserModel user, List<String> actions, int lifespanSecs) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    ExecuteActionsActionToken token =
        new ExecuteActionsActionToken(
            user.getId(),
            user.getEmail(),
            Time.currentTime() + lifespanSecs,
            actions,
            authSession.getRedirectUri(),
            authSession.getClient().getClientId());
    return context
        .getActionTokenUrl(
            token.serialize(context.getSession(), context.getRealm(), context.getUriInfo()))
        .toString();
  }

  /** Renders and sends the activation email within the current transaction. */
  static void send(
      AuthenticationFlowContext context, UserModel user, String link, int lifespanSecs) {
    RealmModel realm = context.getRealm();
    String realmName = MagicLink.getRealmName(realm);
    String clientName = MagicLink.getClientName(context.getAuthenticationSession().getClient());
    // the template provider mutates this map, so it must not be immutable
    Map<String, Object> bodyAttr = Maps.newHashMap();
    bodyAttr.put("realmName", realmName);
    bodyAttr.put("clientName", clientName);
    bodyAttr.put("activationLink", link);
    bodyAttr.put("linkExpirationMinutes", Long.toString(TimeUnit.SECONDS.toMinutes(lifespanSecs)));
    try {
      context
          .getSession()
          .getProvider(EmailTemplateProvider.class)
          .setRealm(realm)
          .setUser(user)
          .setAuthenticationSession(context.getAuthenticationSession())
          .send(
              EMAIL_SUBJECT_KEY, ImmutableList.of(realmName, clientName), EMAIL_TEMPLATE, bodyAttr);
    } catch (EmailException e) {
      log.error("Failed to send account activation email", e);
    }
  }
}
