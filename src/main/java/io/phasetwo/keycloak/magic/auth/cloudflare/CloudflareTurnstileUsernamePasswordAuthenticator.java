package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.*;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

@JBossLog
public class CloudflareTurnstileUsernamePasswordAuthenticator extends UsernamePasswordForm
    implements Authenticator {
  private static final Logger LOGGER =
      Logger.getLogger(CloudflareTurnstileUsernamePasswordAuthenticator.class);

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
    if (captchaRequired) {
      MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
      String captcha = formData.getFirst(CloudflareTurnstile.CF_TURNSTILE_RESPONSE);
      log.trace("Got captcha: " + captcha);

      validRecaptcha = validate(context);
    }
    String executionIdBefore = context.getExecution().getId();

    super.action(context);

    boolean flowSucceeded =
        (context.getUser() != null) || (!executionIdBefore.equals(context.getExecution().getId()));

    if (captchaRequired && !validRecaptcha && flowSucceeded) {
      // we could implement a challenge based on the last configured credential. Verify email is a
      // default
      context.getUser().setEmailVerified(false);
      context.getUser().addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
    }
  }

  @Override
  protected Response challenge(AuthenticationFlowContext context, String error, String field) {
    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
    if (Boolean.parseBoolean(authenticationSession.getAuthNote("USERNAME_HIDDEN"))) {
      field = "password";
    }

    if (error != null) {
      if (field != null) {
        form.addError(new FormMessage(field, error));
      } else {
        form.setError(error);
      }
    }
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    boolean captchaRequired = isTurnstileCaptchaConfigured(authenticatorConfig);
    if (captchaRequired) {
      enableCloudflareTurnstile(context);
    }

    return this.createLoginForm(form);
  }

  protected boolean validate(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();

    if (config == null) {
      LOGGER.warn("No authenticator configuration found for Turnstile Authenticator Action");
      return false;
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
        LOGGER.errorf("Could not create Turnstile assessment: %s", response.getStatusLine());
        EntityUtils.consumeQuietly(response.getEntity());
        throw new Exception(response.getStatusLine().getReasonPhrase());
      }

      assessment =
          JsonSerialization.readValue(response.getEntity().getContent(), TurnstileResponse.class);
      LOGGER.tracef("Got assessment response: %s", assessment);

      return assessment.isSuccess()
          && config.getConfig().getOrDefault(CF_ACTION, "login").equals(assessment.getAction());
    } catch (Exception e) {
      ServicesLogger.LOGGER.recaptchaFailed(e);

      return false;
    }
  }
}
