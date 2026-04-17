package io.phasetwo.keycloak.magic.auth.cloudflare;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;

import java.util.Map;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.isTurnstileCaptchaConfigured;

@JBossLog
public class CloudflareTurnstileAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    challenge(context);
  }

  private void challenge(AuthenticationFlowContext context) {

    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (!isTurnstileCaptchaConfigured(context.getAuthenticatorConfig())) {
      form.addError(new FormMessage(null, CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
      return;
    }

    CloudflareTurnstile.Config config =
            CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());

    String lang =
        context.getUser() != null
            ? context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag()
            : "en";
    prepareForm(form, config, lang);

    Response response = form.createForm("cf-captcha.ftl");
    context.challenge(response);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String captcha = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    LoginFormsProvider form = context.form();
    if (!isTurnstileCaptchaConfigured(context.getAuthenticatorConfig())) {
        form.addError(new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
        return;
    }

    CloudflareTurnstile.Config config =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());

    if (Validation.isBlank(captcha)
        || !validate(
            config, captcha, context.getConnection().getRemoteAddr(), context.getSession())) {
      formData.remove(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
        form.addError(new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_FAILED));
    } else {
      context.success();
    }
  }

  public boolean validate(
          CloudflareTurnstile.Config config, String captcha, String remoteAddr, KeycloakSession session) {
      try {
          Map response =
                  SimpleHttp.doPost("https://challenges.cloudflare.com/turnstile/v0/siteverify", session)
                          .param("secret", config.getSecret())
                          .param("response", captcha)
                          .param("remoteip", remoteAddr)
                          .asJson(Map.class);

          log.debugf("Turnstile response: %s", response);

          return Boolean.TRUE.equals(response.get("success"));
      } catch (Exception e) {
          log.warnf(e, "Failed to validate Turnstile response: %s", e.getMessage());
          return false;
      }
  }

  public static void prepareForm(
          LoginFormsProvider form, CloudflareTurnstile.Config config, String lang) {
      form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
      form.setAttribute("captchaRequired", true)
              .setAttribute("captchaSiteKey", config != null ? config.getSiteKey() : null)
              .setAttribute("captchaAction", config != null ? config.getAction() : null)
              .setAttribute("captchaLanguage", lang != null ? lang : "en");
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
