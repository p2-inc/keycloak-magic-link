package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.failNotConfigured;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.isTurnstileCaptchaConfigured;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.validate;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

@JBossLog
public class CloudflareTurnstileAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (!isTurnstileCaptchaConfigured(context.getAuthenticatorConfig())) {
      failNotConfigured(context);
      return;
    }
    context.challenge(createChallenge(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (!isTurnstileCaptchaConfigured(context.getAuthenticatorConfig())) {
      failNotConfigured(context);
      return;
    }

    CloudflareTurnstile.Config config =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String captcha = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);

    if (validate(config, captcha, context.getConnection().getRemoteAddr(), context.getSession())) {
      context.success();
      return;
    }

    log.debug("Turnstile token was missing or rejected; showing the challenge again");
    context.failureChallenge(
        AuthenticationFlowError.INVALID_CREDENTIALS,
        createChallenge(context, CloudflareTurnstile.MSG_CAPTCHA_FAILED));
  }

  private Response createChallenge(AuthenticationFlowContext context, String error) {
    CloudflareTurnstile.Config config =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());
    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (error != null) {
      form.addError(new FormMessage(error));
    }
    prepareForm(form, config, resolveLanguage(context));
    return form.createForm("cf-captcha.ftl");
  }

  private String resolveLanguage(AuthenticationFlowContext context) {
    if (context.getUser() != null) {
      return context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
    } else if (context.getRealm() != null && context.getRealm().getDefaultLocale() != null) {
      return context.getRealm().getDefaultLocale();
    }
    return "en";
  }

  private void prepareForm(
      LoginFormsProvider form, CloudflareTurnstile.Config config, String lang) {
    form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
    form.setAttribute("captchaRequired", true)
        .setAttribute("captchaSiteKey", config.getSiteKey())
        .setAttribute("captchaAction", config.getAction())
        .setAttribute("captchaLanguage", lang);
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
}
