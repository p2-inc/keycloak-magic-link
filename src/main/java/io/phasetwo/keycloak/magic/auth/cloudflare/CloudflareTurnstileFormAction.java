package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.*;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

@JBossLog
public class CloudflareTurnstileFormAction implements FormAction {

  private static final Logger LOGGER = Logger.getLogger(CloudflareTurnstileFormAction.class);

  @Override
  public void buildPage(FormContext context, LoginFormsProvider form) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    LOGGER.debugf("CloudflareTurnstileFormAction initiated");
    if (!isTurnstileCaptchaConfigured(config)) {
      form.addError(new FormMessage(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED));
      return;
    }

    if (context.getUser() != null) {
      LOGGER.debugf("User exists");
      return;
    }

    // Get configuration
    CloudflareTurnstile.Config turnstileConfig =
        CloudflareTurnstile.readConfig(context.getAuthenticatorConfig().getConfig());

    form.setAttribute("turnstileRequired", true);
    form.setAttribute("turnstileSiteKey", turnstileConfig.getSiteKey());
    form.setAttribute("turnstileAction", turnstileConfig.getAction());

    LOGGER.debug("buildPage() completed successfully");
  }

  @Override
  public void validate(ValidationContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();

    if (config == null) {
      LOGGER.warn("No authenticator configuration found for Turnstile Form Action");
      return;
    }

    // Verify Turnstile token
    String turnstileResponse = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
    String ipAddress = getClientIpAddress(context);
    TurnstileResponse assessment = null;
    try {
      HttpPost request = buildAssessmentRequest(ipAddress, turnstileResponse, config.getConfig());
      HttpClient httpClient =
          context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
      HttpResponse response = httpClient.execute(request);

      if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
        LOGGER.errorf("Could not create reCAPTCHA assessment: %s", response.getStatusLine());
        EntityUtils.consumeQuietly(response.getEntity());
        throw new Exception(response.getStatusLine().getReasonPhrase());
      }

      assessment =
          JsonSerialization.readValue(response.getEntity().getContent(), TurnstileResponse.class);
      LOGGER.tracef("Got assessment response: %s", assessment);

    } catch (Exception e) {
      ServicesLogger.LOGGER.recaptchaFailed(e);
    }

    if (!Validation.isBlank(turnstileResponse) && assessment != null) {
      if (assessment.isSuccess()
              && config.getConfig().getOrDefault(CF_ACTION, "login").equals(assessment.getAction())) {
        context.success();
        return;
      }
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
