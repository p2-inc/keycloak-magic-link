package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.*;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

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

    if (context.getUser() != null) {
      log.debugf("User exists");
      return;
    }

    // Get configuration
    CloudflareTurnstile.Config turnstileConfig =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());

    form.setAttribute("turnstileRequired", true);
    form.setAttribute("turnstileSiteKey", turnstileConfig.getSiteKey());
    form.setAttribute("turnstileAction", turnstileConfig.getAction());

    log.debug("buildPage() completed successfully");
  }

  @Override
  public void validate(ValidationContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();

    if (config == null) {
      log.warn("No authenticator configuration found for Turnstile Form Action");
      return;
    }

    // Verify Turnstile token
    String turnstileResponse = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    String ipAddress = getClientIpAddress(context);
    CloudflareTurnstile.Config turnstileConfig = CloudflareTurnstile.readConfig(config.getConfig());
    var valid =
        CloudflareTurnstile.validate(
            turnstileConfig, turnstileResponse, ipAddress, context.getSession());

    if (!Validation.isBlank(turnstileResponse) && valid) {
      context.success();
      return;
    }

    List<FormMessage> errors = new ArrayList<>();
    errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
    context.error(Errors.INVALID_REGISTRATION);
    context.validationError(formData, errors);
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
