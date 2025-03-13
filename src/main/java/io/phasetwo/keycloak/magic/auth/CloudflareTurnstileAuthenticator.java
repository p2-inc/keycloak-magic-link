package io.phasetwo.keycloak.magic.auth;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;

@JBossLog
public class CloudflareTurnstileAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    challenge(context, null);
  }

  private void challenge(AuthenticationFlowContext context, FormMessage errorMessage) {
    CloudflareTurnstile.Config config =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());
    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (config == null) {
      form.addError(new FormMessage(null, CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
      return;
    }

    String lang =
        context.getUser() != null
            ? context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag()
            : "en";
    CloudflareTurnstile.prepareForm(form, config, lang);

    Response response = form.createForm("cf-captcha.ftl");
    context.challenge(response);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String captcha = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);

    CloudflareTurnstile.Config config =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());
    if (config == null) {
      challenge(context, new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
      return;
    }

    if (Validation.isBlank(captcha)
        || !CloudflareTurnstile.validate(
            config, captcha, context.getConnection().getRemoteAddr(), context.getSession())) {
      formData.remove(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
      challenge(context, new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_FAILED));
    } else {
      context.success();
    }
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
