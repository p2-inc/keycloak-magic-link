package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.EMAIL_OTP;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import com.google.common.collect.ImmutableList;
import io.phasetwo.keycloak.magic.MagicLink;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

@JBossLog
public class EmailOtpAuthenticator extends UsernamePasswordForm {

  public static final String USER_AUTH_NOTE_OTP_CODE = "user-auth-note-otp-code";
  public static final String FORM_PARAM_OTP_CODE = "otp";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("EmailOtpAuthenticator.authenticate");
    String attemptedUsername = MagicLink.getAttemptedUsername(context);
    if (attemptedUsername == null) {
      // No user identified yet — show the email/username input form
      super.authenticate(context);
    } else {
      log.debugf(
          "Found attempted username %s from previous authenticator, skipping login form",
          attemptedUsername);
      // User already identified — proceed directly to send OTP and show code form
      sendOtpAndChallenge(context, attemptedUsername, null, false);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.debug("EmailOtpAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    // If the user submitted a resend request, clear the code and re-send
    if (formData.containsKey("resend")) {
      context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
      String email = MagicLink.getAttemptedUsername(context);
      if (email == null) {
        context.getEvent().error(Errors.USER_NOT_FOUND);
        Response challengeResponse =
            challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
        return;
      }
      sendOtpAndChallenge(context, email, null, false);
      return;
    }

    // If there's already an OTP code in the session, we're on the OTP form — validate it
    String existingCode = context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE);
    if (existingCode != null) {
      validateOtpCode(context, formData);
      return;
    }

    // Otherwise, we're on the email input form — extract the email
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

    // Look up or create the user
    EventBuilder event = context.newEvent();
    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context, false),
            false,
            false,
            MagicLink.registerEvent(event, EMAIL_OTP));

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
      log.debugf("user attempted to login with invalid email: %s", email);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    // Check if user is enabled before proceeding
    if (!enabledUser(context, user)) {
      return;
    }

    context.setUser(user);
    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);

    // Send OTP and show the code entry form
    sendOtpAndChallenge(context, email, null, false);
  }

  private void sendOtpAndChallenge(
      AuthenticationFlowContext context,
      String email,
      FormMessage errorMessage,
      boolean triggerBruteForce) {
    sendOtp(context, email);

    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (errorMessage != null) {
      form.setErrors(ImmutableList.of(errorMessage));
    }

    Response response = form.createForm("otp-form.ftl");

    if (triggerBruteForce) {
      context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
      return;
    }

    if (errorMessage != null) {
      context.forceChallenge(response);
      return;
    }

    context.challenge(response);
  }

  private void sendOtp(AuthenticationFlowContext context, String email) {
    if (context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE) != null) {
      log.debugf("Skipping sending OTP email to %s because auth note isn't empty", email);
      return;
    }

    String code = SecretGenerator.getInstance().randomString(6, SecretGenerator.DIGITS);
    EventBuilder event = context.newEvent();

    UserModel user = context.getUser();
    if (user == null) {
      user =
          MagicLink.getOrCreate(
              context.getSession(),
              context.getRealm(),
              email,
              isForceCreate(context, false),
              false,
              false,
              MagicLink.registerEvent(event, EMAIL_OTP));

      if (user == null) {
        log.debugf("User with email %s not found.", email);
        context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.USER_NOT_FOUND);
        context.failure(AuthenticationFlowError.INVALID_USER);
        return;
      }

      context.setUser(user);
    }

    boolean sent = MagicLink.sendOtpEmail(context.getSession(), user, code);
    if (sent) {
      log.debugf("Sent OTP code to email %s", user.getEmail());
      context.getAuthenticationSession().setAuthNote(USER_AUTH_NOTE_OTP_CODE, code);
    }
  }

  private void validateOtpCode(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    UserModel user = context.getUser();
    if (user == null) {
      log.warn("No user found in authentication context while validating OTP code");
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.USER_NOT_FOUND);
      context.failure(AuthenticationFlowError.INVALID_USER);
      return;
    }

    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().user(user);
      context.getEvent().error(bruteForceError);
      String email = MagicLink.getAttemptedUsername(context);
      if (email == null) {
        context.failure(AuthenticationFlowError.INVALID_USER);
        return;
      }
      sendOtpAndChallenge(
          context,
          email,
          new FormMessage(disabledByBruteForceError(bruteForceError)),
          false);
      return;
    }

    String code = formData.getFirst(FORM_PARAM_OTP_CODE);
    log.debugf("Got %s for OTP code in form", code);
    try {
      if (code != null
          && code.equals(
              context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE))) {
        context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
        user.setEmailVerified(true);
        context.success();
        return;
      }
    } catch (Exception e) {
      log.warn("Error comparing OTP code to form", e);
    }

    context.getEvent().user(user).event(EventType.LOGIN_ERROR).error(Errors.INVALID_CODE);
    String email = MagicLink.getAttemptedUsername(context);
    if (email == null) {
      context.failure(AuthenticationFlowError.INVALID_USER);
      return;
    }
    sendOtpAndChallenge(
        context,
        email,
        new FormMessage(Messages.INVALID_ACCESS_CODE),
        true);
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

  protected String disabledByBruteForceError(String error) {
    if (Errors.USER_TEMPORARILY_DISABLED.equals(error)) {
      return EmailOtpMessages.ACCOUNT_TEMPORARILY_DISABLED_EMAIL_OTP;
    }
    return EmailOtpMessages.ACCOUNT_PERMANENTLY_DISABLED_EMAIL_OTP;
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }
}