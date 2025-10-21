package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.EMAIL_OTP;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;

import com.google.common.collect.ImmutableList;
import io.phasetwo.keycloak.magic.MagicLink;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
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
import org.keycloak.services.messages.Messages;

@JBossLog
public class EmailOtpAuthenticator implements Authenticator {

  public static final String USER_AUTH_NOTE_OTP_CODE = "user-auth-note-otp-code";
  public static final String FORM_PARAM_OTP_CODE = "otp";

  public void authenticate(AuthenticationFlowContext context) {
    challenge(context, null, false);
  }

  private void challenge(
      AuthenticationFlowContext context, FormMessage errorMessage, boolean triggerBruteForce) {
    var email = MagicLink.getAttemptedUsername(context);
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
      user = MagicLink.getOrCreate(
        context.getSession(),
        context.getRealm(),
        email,
        isForceCreate(context, false),
        false,
        false,
        MagicLink.registerEvent(event, EMAIL_OTP));

      if (user == null) {
        log.debugf("User with email %s not found.", context.getUser().getEmail());
        return;
      }

      context.setUser(user);
    }

    boolean sent = MagicLink.sendOtpEmail(context.getSession(), user, code);
    if (sent) {
      log.debugf("Sent OTP code %s to email %s", code, context.getUser().getEmail());
      context.getAuthenticationSession().setAuthNote(USER_AUTH_NOTE_OTP_CODE, code);
    }
  }

  public void action(AuthenticationFlowContext context) {
    log.debug("EmailOtpAuthenticator.action");

    UserModel user = context.getUser();
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().user(user);
      context.getEvent().error(bruteForceError);
      challenge(context, new FormMessage(disabledByBruteForceError(bruteForceError)), false);
      return;
    }

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (formData.containsKey("resend")) {
      context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
      challenge(context, null, false);
      return;
    }

    String code = formData.getFirst(FORM_PARAM_OTP_CODE);
    log.debugf("Got %s for OTP code in form", code);
    try {
      if (code != null
          && code.equals(context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE))) {
        context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
        context.getAuthenticationSession().getAuthenticatedUser().setEmailVerified(true);
        context.success();
        return;
      }
    } catch (Exception e) {
      log.warn("Error comparing OTP code to form", e);
    }

    context.getEvent().user(user).event(EventType.LOGIN_ERROR).error(Errors.INVALID_CODE);
    challenge(context, new FormMessage(Messages.INVALID_ACCESS_CODE), true);
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
