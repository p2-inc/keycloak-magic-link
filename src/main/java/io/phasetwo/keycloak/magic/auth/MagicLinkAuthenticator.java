package io.phasetwo.keycloak.magic.auth;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import java.util.Map;
import java.util.OptionalInt;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

@JBossLog
public class MagicLinkAuthenticator extends UsernamePasswordForm {

  static final String CREATE_NONEXISTENT_USER_CONFIG_PROPERTY = "ext-magic-create-nonexistent-user";
  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";
  static final String UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY = "ext-magic-update-password-action";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.authenticate");
    String attemptedUsername = getAttemptedUsername(context);
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

    String email = trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    // check for empty email
    if (email == null) {
      // - first check for email from previous authenticator
      email = getAttemptedUsername(context);
    }
    // - throw error if still empty
    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }
    String clientId = context.getSession().getContext().getClient().getClientId();

    EventBuilder event = context.newEvent();

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context, false),
            isUpdateProfile(context, false),
            isUpdatePassword(context, false),
            MagicLink.registerEvent(event));

    // check for no/invalid email address
    if (user == null
        || trimToNull(user.getEmail()) == null
        || !isValidEmail(user.getEmail())
        || !user.isEnabled()) {
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.INVALID_EMAIL);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    // check for enabled user
    if (!enabledUser(context, user)) {
      return; // the enabledUser method sets the challenge
    }

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            clientId,
            OptionalInt.empty(),
            rememberMe(context),
            context.getAuthenticationSession());
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
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

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdateProfile(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdatePassword(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean is(AuthenticationFlowContext context, String propName, boolean defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(propName);
    if (v == null || "".equals(v)) return defaultValue;

    return v.trim().toLowerCase().equals("true");
  }

  private static boolean isValidEmail(String email) {
    try {
      InternetAddress a = new InternetAddress(email);
      a.validate();
      return true;
    } catch (AddressException e) {
      return false;
    }
  }

  private String getAttemptedUsername(AuthenticationFlowContext context) {
    if (context.getUser() != null && context.getUser().getEmail() != null) {
      return context.getUser().getEmail();
    }
    String username =
        trimToNull(context.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME));
    if (username != null) {
      if (isValidEmail(username)) {
        return username;
      }
      UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
      if (user != null && user.getEmail() != null) {
        return user.getEmail();
      }
    }
    return null;
  }

  private static String trimToNull(final String s) {
    if (s == null) {
      return null;
    }
    String trimmed = s.trim();
    if ("".equalsIgnoreCase(trimmed)) trimmed = null;
    return trimmed;
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
