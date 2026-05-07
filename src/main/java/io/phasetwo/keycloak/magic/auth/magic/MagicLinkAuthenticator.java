package io.phasetwo.keycloak.magic.auth.magic;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProvider;
import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProviderFactory;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

/**
 * Browser-flow authenticator for the standard magic link flow.
 *
 * <p>On form submission, resolves (or creates) the user, delegates pre-send validation and email
 * dispatch to the active {@link MagicLinkCustomizationProvider}, then presents the
 * {@code view-email.ftl} waiting screen.
 */
@JBossLog
public final class MagicLinkAuthenticator extends UsernamePasswordForm {

  private final MagicLinkCustomizationProviderFactory customizationProviderFactory;

  MagicLinkAuthenticator(MagicLinkCustomizationProviderFactory customizationProviderFactory) {
    this.customizationProviderFactory = customizationProviderFactory;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.authenticate");
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
    log.debug("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = MagicLink.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    if (email == null) {
      email = MagicLink.getAttemptedUsername(context);
    }
    log.debugf("email in action is %s", email);

    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    MagicLinkConfig config = new MagicLinkConfig(context.getAuthenticatorConfig());
    String clientId = context.getSession().getContext().getClient().getClientId();
    EventBuilder event = context.newEvent();

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            config.isForceCreate(),
            config.isUpdateProfile(),
            config.isUpdatePassword(),
            MagicLink.registerEvent(event, MAGIC_LINK));

    if (user == null
        || MagicLink.trimToNull(user.getEmail()) == null
        || !MagicLink.isValidEmail(user.getEmail())) {
      context
          .getEvent()
          .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_EMAIL);
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      log.debugf("user attempted to login with username/email: %s", email);
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    log.debugf("user is %s %s", user.getEmail(), user.isEnabled());

    if (!enabledUser(context, user)) {
      return;
    }

    MagicLinkCustomizationProvider customization =
        customizationProviderFactory.create(context.getSession(), config.raw());

    if (!customization.canAuthenticate(context, user, config)) {
      return;
    }

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            clientId,
            config.getTokenLifespan(),
            rememberMe(context),
            context.getAuthenticationSession(),
            config.isTokenPersistent());
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = customization.sendMagicLinkEmail(context.getSession(), user, link, config);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean rememberMe(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String rememberMe = formData.getFirst("rememberMe");
    return context.getRealm().isRememberMe()
        && rememberMe != null
        && rememberMe.equalsIgnoreCase("on");
  }

  @Override
  protected boolean validateForm(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("validateForm");
    return validateUser(context, formData);
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("challenge");
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) forms.setFormData(formData);
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    log.debug("createLoginForm");
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    log.debug("getDefaultChallengeMessage");
    return context.getRealm().isLoginWithEmailAllowed()
        ? Messages.INVALID_USERNAME_OR_EMAIL
        : Messages.INVALID_USERNAME;
  }
}
