package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.getClientIpAddress;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.getMissingConfigKeys;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.isTurnstileCaptchaConfigured;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

@JBossLog
public class CloudflareTurnstileFormAction implements FormAction {

  @Override
  public void buildPage(FormContext context, LoginFormsProvider form) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    log.debugf("CloudflareTurnstileFormAction initiated");
    if (!isTurnstileCaptchaConfigured(config)) {
      form.addError(new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
      return;
    }

    // Always render the widget: validate() requires a token on every submission.
    CloudflareTurnstile.Config turnstileConfig = CloudflareTurnstile.readConfig(config.getConfig());

    form.setAttribute("turnstileRequired", true);
    form.setAttribute("turnstileSiteKey", turnstileConfig.getSiteKey());
    form.setAttribute("turnstileAction", turnstileConfig.getAction());

    log.debug("buildPage() completed successfully");
  }

  @Override
  public void validate(ValidationContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();

    // Fail closed: registration stays blocked until the Turnstile setup is finished.
    if (!isTurnstileCaptchaConfigured(config)) {
      log.warnf(
          "Cloudflare Turnstile is not configured for registration; missing or blank: %s",
          getMissingConfigKeys(config));
      fail(context, formData, CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED);
      return;
    }

    // CloudflareTurnstile.validate() rejects a blank token before calling siteverify.
    String turnstileResponse = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    CloudflareTurnstile.Config turnstileConfig = CloudflareTurnstile.readConfig(config.getConfig());
    if (CloudflareTurnstile.validate(
        turnstileConfig, turnstileResponse, getClientIpAddress(context), context.getSession())) {
      context.success();
      return;
    }

    fail(context, formData, Messages.RECAPTCHA_FAILED);
  }

  private void fail(
      ValidationContext context, MultivaluedMap<String, String> formData, String message) {
    formData.remove(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    context.error(Errors.INVALID_REGISTRATION);
    context.validationError(
        formData, List.of(new FormMessage(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, message)));
    context.excludeOtherErrors();
  }

  @Override
  public void success(FormContext context) {}

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // No required actions
  }

  @Override
  public void close() {
    //
  }
}
