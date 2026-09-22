package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.TURNSTILE_FAILED;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.getClientIpAddress;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.isTurnstileCaptchaConfigured;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.WebAuthnConstants;
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

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    boolean passkeySubmission = isPasskeySubmission(formData);

    String executionIdBefore = context.getExecution().getId();

    // super.action() re-renders the form through several paths — a bad password goes through
    // challenge(context, error, field), while a failed passkey goes straight to the error callback
    // baked into UsernamePasswordForm's WebAuthnConditionalUIAuthenticator. Seeding the shared
    // LoginFormsProvider up front covers all of them.
    if (captchaRequired) {
      enableCloudflareTurnstile(context);
    }

    super.action(context);

    // A passkey submission carries no Turnstile token; super.action() has already handed it to the
    // WebAuthn authenticator, so there is nothing left to verify.
    if (passkeySubmission || !captchaRequired) {
      return;
    }

    // Only spend a Turnstile verification once the credentials themselves have passed.
    boolean flowSucceeded =
        (context.getUser() != null) || (!executionIdBefore.equals(context.getExecution().getId()));
    if (!flowSucceeded) {
      return;
    }

    String turnstileResponse = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    log.trace("Got captcha: " + turnstileResponse);
    String ipAddress = getClientIpAddress(context);
    CloudflareTurnstile.Config turnstileConfig =
        CloudflareTurnstile.readConfig(authenticatorConfig.getConfig());

    boolean validRecaptcha =
        CloudflareTurnstile.validate(
            turnstileConfig, turnstileResponse, ipAddress, context.getSession());

    if (!validRecaptcha) {
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

  /**
   * Mirrors the passkey branch of {@link UsernamePasswordForm#action(AuthenticationFlowContext)}: a
   * WebAuthn form post carries authenticator data (or an error) instead of a password, so no
   * Turnstile token is expected on it.
   */
  private boolean isPasskeySubmission(MultivaluedMap<String, String> formData) {
    return webauthnAuth != null
        && webauthnAuth.isPasskeysEnabled()
        && (formData.containsKey(WebAuthnConstants.AUTHENTICATOR_DATA)
            || formData.containsKey(WebAuthnConstants.ERROR));
  }
}
