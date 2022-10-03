package io.phasetwo.keycloak.magic.auth;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.LoginFormsUtil;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

@JBossLog
public class MagicLinkAuthenticator extends UsernamePasswordForm implements Authenticator {

  static final String CREATE_NONEXISTENT_USER_CONFIG_PROPERTY = "ext-magic-create-nonexistent-user";
  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (context.getUser() != null) {
      // We can skip the form when user is re-authenticating. Unless current user has some IDP set,
      // so he can re-authenticate with that IDP
      List<IdentityProviderModel> identityProviders =
          LoginFormsUtil.filterIdentityProviders(
              context.getRealm().getIdentityProvidersStream(), context.getSession(), context);
      if (identityProviders.isEmpty()) {
        context.success();
        return;
      }
    }

    String attemptedUsername = getAttemptedUsername(context);
    if (attemptedUsername == null) {
      super.authenticate(context);
    } else {
      log.debugf(
          "Found attempted username %s from previous authenticator, skipping login form",
          attemptedUsername);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.info("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    boolean previousAuthenticator = false;
    String email = trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    // check for empty email
    if (email == null) {
      // - first check for email from previous authenticator
      email = getAttemptedUsername(context);
      if (email != null) previousAuthenticator = true;
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
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    log.debugf("Attempting MagicLinkAuthenticator for %s, %s, %s", email, clientId, redirectUri);

    EventBuilder event = context.newEvent();

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context, false),
            isUpdateProfile(context, false),
            MagicLink.registerEvent(event));
    // check for no/invalid email address
    if (user == null || trimToNull(user.getEmail()) == null || !isValidEmail(user.getEmail())) {
      context.getEvent().error(Errors.INVALID_EMAIL);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    MagicLinkActionToken token =
        MagicLink.createActionToken(user, clientId, redirectUri, OptionalInt.empty());
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    if (!previousAuthenticator) {
      context.clearUser();
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    }
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdateProfile(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, defaultValue);
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
    return trimToNull(context.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME));
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
