package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.TURNSTILE_FAILED;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.getClientIpAddress;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.isTurnstileCaptchaConfigured;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

@JBossLog
public class CloudflareTurnstileUsernamePasswordAuthenticator extends UsernamePasswordForm
    implements Authenticator {

  public static final String CF_VERIFY_EMAIL_ON_FAIL = "verify_email_on_captcha_fail";

  public CloudflareTurnstileUsernamePasswordAuthenticator(KeycloakSession session) {
    super(session);
  }

  public CloudflareTurnstileUsernamePasswordAuthenticator() {
    super();
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    boolean captchaRequired = isTurnstileCaptchaConfigured(authenticatorConfig);

    if (captchaRequired) {
      enableCloudflareTurnstile(context);
    }

    super.authenticate(context);
  }

  private void enableCloudflareTurnstile(AuthenticationFlowContext context) {
    CloudflareTurnstile.Config turnstileConfig =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());
    LoginFormsProvider form = context.form();

    form.setAttribute("turnstileRequired", true);
    form.setAttribute("turnstileSiteKey", turnstileConfig.getSiteKey());
    form.setAttribute("turnstileAction", turnstileConfig.getAction());
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    boolean captchaRequired = isTurnstileCaptchaConfigured(authenticatorConfig);
    boolean validRecaptcha = false;

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    boolean isPasskeySubmission =
        formData.containsKey(org.keycloak.WebAuthnConstants.AUTHENTICATOR_DATA)
            || formData.containsKey(org.keycloak.WebAuthnConstants.ERROR);

    if (captchaRequired && !isPasskeySubmission) {
      String captcha = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
      log.trace("Got captcha: " + captcha);
      String turnstileResponse = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
      String ipAddress = getClientIpAddress(context);
      CloudflareTurnstile.Config turnstileConfig =
          CloudflareTurnstile.readConfig(authenticatorConfig.getConfig());

      validRecaptcha =
          CloudflareTurnstile.validate(
              turnstileConfig, turnstileResponse, ipAddress, context.getSession());
    }
    String executionIdBefore = context.getExecution().getId();

    super.action(context);

    if (isPasskeySubmission) {
      return;
    }

    boolean flowSucceeded =
        (context.getUser() != null) || (!executionIdBefore.equals(context.getExecution().getId()));

    if (captchaRequired && !validRecaptcha && flowSucceeded) {
      var user = context.getUser();
      context.getAuthenticationSession().setAuthNote(TURNSTILE_FAILED, "true");

      boolean verifyEmailOnFail =
          Boolean.parseBoolean(
              authenticatorConfig.getConfig().getOrDefault(CF_VERIFY_EMAIL_ON_FAIL, "false"));
      // rudimentary MFA fallback for environments without 2FA flows; disabled by default
      if (verifyEmailOnFail) {
        user.setEmailVerified(false);
        user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
      }
    }
  }

  @Override
  protected Response challenge(AuthenticationFlowContext context, String error, String field) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    boolean captchaRequired = isTurnstileCaptchaConfigured(authenticatorConfig);
    if (captchaRequired) {
      enableCloudflareTurnstile(context);
    }
    return super.challenge(context, error, field);
  }
}
