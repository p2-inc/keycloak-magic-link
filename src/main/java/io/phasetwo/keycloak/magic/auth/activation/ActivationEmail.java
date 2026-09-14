package io.phasetwo.keycloak.magic.auth.activation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import io.phasetwo.keycloak.magic.MagicLink;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.executors.ExecutorsProvider;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Builds and sends account-activation emails carrying a standard Keycloak {@link
 * ExecuteActionsActionToken}, so the emailed link opens the required actions directly in whatever
 * browser it is clicked in (handled entirely by Keycloak core) and then redirects back to the
 * client.
 *
 * <p>The SMTP send runs on a background executor so the login response does not reveal, through
 * timing, whether an email was actually sent.
 */
@JBossLog
final class ActivationEmail {

  static final String EMAIL_TEMPLATE = "activation-email.ftl";
  static final String EMAIL_SUBJECT_KEY = "activationEmailSubject";
  static final String EXECUTOR_TASK_TYPE = "ext-activation-email";

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

  /** Renders and sends the activation email in a background transaction. */
  static void sendAsync(
      AuthenticationFlowContext context, UserModel user, String link, int lifespanSecs) {
    KeycloakSessionFactory factory = context.getSession().getKeycloakSessionFactory();
    String realmId = context.getRealm().getId();
    String userId = user.getId();
    String realmName = MagicLink.getRealmName(context.getRealm());
    String clientName = MagicLink.getClientName(context.getAuthenticationSession().getClient());
    String expirationMinutes = Long.toString(TimeUnit.SECONDS.toMinutes(lifespanSecs));

    ExecutorService executor =
        context.getSession().getProvider(ExecutorsProvider.class).getExecutor(EXECUTOR_TASK_TYPE);
    executor.execute(
        () ->
            KeycloakModelUtils.runJobInTransaction(
                factory,
                session -> {
                  RealmModel realm = session.realms().getRealm(realmId);
                  if (realm == null) return;
                  session.getContext().setRealm(realm);
                  UserModel u = session.users().getUserById(realm, userId);
                  if (u == null) return;
                  // the template provider mutates this map, so it must not be immutable
                  Map<String, Object> bodyAttr = Maps.newHashMap();
                  bodyAttr.put("realmName", realmName);
                  bodyAttr.put("clientName", clientName);
                  bodyAttr.put("activationLink", link);
                  bodyAttr.put("linkExpirationMinutes", expirationMinutes);
                  try {
                    session
                        .getProvider(EmailTemplateProvider.class)
                        .setRealm(realm)
                        .setUser(u)
                        .send(
                            EMAIL_SUBJECT_KEY,
                            ImmutableList.of(realmName, clientName),
                            EMAIL_TEMPLATE,
                            bodyAttr);
                  } catch (EmailException e) {
                    log.error("Failed to send account activation email", e);
                  }
                }));
  }
}
