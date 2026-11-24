package io.phasetwo.keycloak.magic.auth.activation;

import io.phasetwo.keycloak.magic.MagicLink;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.DefaultActionTokenKey;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

/**
 * Reset-credentials-flow replacement for Keycloak's built-in Send Reset Email execution.
 *
 * <p>Activated accounts get the stock behavior unchanged (delegated to {@link
 * ResetCredentialEmail}): a standard password-reset email. Accounts that are still pending
 * activation (per {@link ActivationCriteria}) get the activation email instead — the same
 * execute-actions email the {@link ActivationGateAuthenticator} sends — so a not-yet-activated
 * user who tries "forgot password" is routed to activation rather than a reset that cannot help
 * them.
 *
 * <p>Both branches show Keycloak's generic "you should receive an email shortly" message, and the
 * unknown-user case is delegated untouched, so nothing here discloses whether an account exists.
 */
@JBossLog
public final class ActivationOrResetEmailAuthenticator implements Authenticator {

  private final ResetCredentialEmail delegate = new ResetCredentialEmail();

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    String actionTokenUserId =
        context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);

    // Unknown users, users without a usable email, and re-entry via a reset action token all
    // keep the stock behavior.
    if (user == null
        || !user.isEnabled()
        || MagicLink.trimToNull(user.getEmail()) == null
        || (actionTokenUserId != null && user.getId().equals(actionTokenUserId))) {
      delegate.authenticate(context);
      return;
    }

    ActivationCriteria config = new ActivationCriteria(context.getAuthenticatorConfig());
    if (!config.isPending(user)) {
      delegate.authenticate(context);
      return;
    }

    int lifespan = config.getTokenLifespan(context.getRealm());
    String link = ActivationEmail.buildLink(context, user, config.emailActions(user), lifespan);
    ActivationEmail.send(context, user, link, lifespan);

    context
        .getEvent()
        .clone()
        .event(EventType.SEND_VERIFY_EMAIL)
        .user(user)
        .detail(Details.USERNAME, user.getUsername())
        .detail(Details.EMAIL, user.getEmail())
        .success();

    context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    delegate.action(context);
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
