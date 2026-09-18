package io.phasetwo.keycloak.magic.auth.activation;

import static org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

/**
 * Email-first browser-flow authenticator that routes login by account status.
 *
 * <p>Renders the email-only login form (or consumes an attempted username set by a previous
 * authenticator), then branches:
 *
 * <ul>
 *   <li><b>Activated account</b> — sets the user on the flow and succeeds, so the next execution
 *       (typically Password Form) prompts for the credential.
 *   <li><b>Pending account</b> (per {@link ActivationCriteria}) — sends an activation email whose
 *       link performs the outstanding required actions directly in the browser it is opened in,
 *       and shows a confirmation screen with a resend button.
 *   <li><b>Unknown, disabled, or email-less account</b> — shows the <em>same</em> confirmation
 *       screen without sending anything, so the response does not disclose whether the account
 *       exists (the same stance {@code MagicLinkAuthenticator} takes for invalid emails).
 * </ul>
 */
@JBossLog
public final class ActivationGateAuthenticator extends UsernamePasswordForm {

  static final String EMAIL_SENT_AT_NOTE = "ext-activation-email-sent-at";
  static final String VIEW_TEMPLATE = "view-activation-sent.ftl";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("ActivationGateAuthenticator.authenticate");
    String attemptedUsername = MagicLink.getAttemptedUsername(context);
    if (attemptedUsername == null) {
      super.authenticate(context);
    } else {
      log.debugf(
          "Found attempted username %s from previous authenticator, skipping login form",
          attemptedUsername);
      action(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.debug("ActivationGateAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = MagicLink.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    if (email == null) {
      // resend posts carry no username field; fall back to what was attempted earlier
      email =
          MagicLink.trimToNull(context.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME));
    }
    if (email == null) {
      email = MagicLink.getAttemptedUsername(context);
    }

    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, email);

    ActivationCriteria config = new ActivationCriteria(context.getAuthenticatorConfig());
    UserModel user =
        KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), email);

    if (user == null || !user.isEnabled() || MagicLink.trimToNull(user.getEmail()) == null) {
      String error =
          user == null
              ? Errors.USER_NOT_FOUND
              : (!user.isEnabled() ? Errors.USER_DISABLED : Errors.INVALID_EMAIL);
      context
          .getEvent()
          .detail(ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(error);
      context.forceChallenge(context.form().createForm(VIEW_TEMPLATE));
      return;
    }

    if (config.isPending(user)) {
      maybeSendActivationEmail(context, config, user);
      context.challenge(context.form().createForm(VIEW_TEMPLATE));
      return;
    }

    context.setUser(user);
    context.success();
  }

  private void maybeSendActivationEmail(
      AuthenticationFlowContext context, ActivationCriteria config, UserModel user) {
    String sentAt = context.getAuthenticationSession().getAuthNote(EMAIL_SENT_AT_NOTE);
    int now = Time.currentTime();
    if (sentAt != null) {
      try {
        if (now - Integer.parseInt(sentAt) < config.getResendCooldownSeconds()) {
          log.debugf("Skipping activation email to %s: resend cooldown active", user.getEmail());
          return;
        }
      } catch (NumberFormatException e) {
        // fall through and send
      }
    }

    int lifespan = config.getTokenLifespan(context.getRealm());
    List<String> actions = config.emailActions(user);
    String link = ActivationEmail.buildLink(context, user, actions, lifespan);
    ActivationEmail.send(context, user, link, lifespan);
    context.getAuthenticationSession().setAuthNote(EMAIL_SENT_AT_NOTE, Integer.toString(now));

    context
        .newEvent()
        .event(EventType.SEND_VERIFY_EMAIL)
        .user(user)
        .detail(Details.USERNAME, user.getUsername())
        .detail(Details.EMAIL, user.getEmail())
        .success();
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) forms.setFormData(formData);
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    return context.getRealm().isLoginWithEmailAllowed()
        ? Messages.INVALID_USERNAME_OR_EMAIL
        : Messages.INVALID_USERNAME;
  }
}
