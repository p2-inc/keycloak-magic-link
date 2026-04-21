package io.phasetwo.keycloak.magic.auth.util;

import com.google.common.collect.ImmutableList;
import io.phasetwo.keycloak.magic.auth.cloudflare.TurnstileAssessmentRequest;
import io.phasetwo.keycloak.magic.auth.cloudflare.TurnstileResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

@JBossLog
public class CloudflareTurnstile {

  public static final String MSG_CAPTCHA_FAILED = "captchaFailed";
  public static final String MSG_CAPTCHA_NOT_CONFIGURED = "captchaNotConfigured";
  public static final String CF_TURNSTILE_RESPONSE = "cf-turnstile-response";

  public static final String CF_SITE_KEY = "cloudflare_site_key";
  public static final String CF_SITE_SECRET = "cloudflare_secret";
  public static final String CF_ACTION = "cloudflare_action";
  public static final String DEFAULT_CF_ACTION = "login";
  public static final String CF_SITEVERIFY_URL = "cloudflare_siteverify_url";
  public static final String DEFAULT_CF_SITEVERIFY_URL =
      "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  public static final String TURNSTILE_FAILED = "turnstile_failed";

  public static class Config {
    private final String siteKey;
    private final String secret;
    private final String action;
    private final String siteverifyUrl;

    public Config(String siteKey, String secret, String action, String siteverifyUrl) {
      this.siteKey = siteKey;
      this.secret = secret;
      this.action = action;
      this.siteverifyUrl = siteverifyUrl;
    }

    public String getSiteKey() {
      return siteKey;
    }

    public String getSecret() {
      return secret;
    }

    public String getAction() {
      return action;
    }

    public String getSiteverifyUrl() {
      return siteverifyUrl;
    }
  }

  public static Config readConfig(Map<String, String> config) {
    return new Config(
        config.get(CF_SITE_KEY),
        config.get(CF_SITE_SECRET),
        config.get(CF_ACTION),
        Optional.ofNullable(config.get(CF_SITEVERIFY_URL)).orElse(DEFAULT_CF_SITEVERIFY_URL));
  }

  public static List<ProviderConfigProperty> configProperties;

  static {
    ImmutableList.Builder<ProviderConfigProperty> builder =
        new ImmutableList.Builder<ProviderConfigProperty>();
    ProviderConfigProperty prop = new ProviderConfigProperty();
    prop.setName(CF_SITE_KEY);
    prop.setLabel("Turnstile Site Key");
    prop.setHelpText("Cloudflare Turnstile Site Key");
    prop.setType(ProviderConfigProperty.STRING_TYPE);
    builder.add(prop);

    prop = new ProviderConfigProperty();
    prop.setName(CF_SITE_SECRET);
    prop.setLabel("Turnstile Secret");
    prop.setHelpText("Cloudflare Turnstile Secret");
    prop.setType(ProviderConfigProperty.STRING_TYPE);
    builder.add(prop);

    prop = new ProviderConfigProperty();
    prop.setName(CF_ACTION);
    prop.setLabel("Action");
    prop.setHelpText(
        "A value that can be used to differentiate widgets under the same Site Key in analytics.");
    prop.setType(ProviderConfigProperty.STRING_TYPE);
    prop.setDefaultValue(DEFAULT_CF_ACTION);
    builder.add(prop);

    prop = new ProviderConfigProperty();
    prop.setName(CF_SITEVERIFY_URL);
    prop.setLabel("Siteverify URL");
    prop.setHelpText("Cloudflare Turnstile siteverify endpoint URL.");
    prop.setType(ProviderConfigProperty.STRING_TYPE);
    prop.setDefaultValue(DEFAULT_CF_SITEVERIFY_URL);
    builder.add(prop);

    configProperties = builder.build();
  }

  public static String getClientIpAddress(AuthenticationFlowContext context) {
    return context.getConnection().getRemoteAddr();
  }

  public static String getClientIpAddress(ValidationContext context) {
    return context.getConnection().getRemoteAddr();
  }

  private static HttpPost buildAssessmentRequest(String ipAddress, String captcha, Config config)
      throws IOException {
    HttpPost request = new HttpPost(config.getSiteverifyUrl());
    TurnstileAssessmentRequest body =
        new TurnstileAssessmentRequest(config.getSecret(), captcha, ipAddress);
    request.setEntity(new StringEntity(JsonSerialization.writeValueAsString(body)));
    request.setHeader("Content-type", "application/json; charset=utf-8");
    return request;
  }

  public static boolean isTurnstileCaptchaConfigured(AuthenticatorConfigModel authenticatorConfig) {
    if (authenticatorConfig == null) {
      log.debug("Authentication model config is null");
      return false;
    }

    Map<String, String> config = authenticatorConfig.getConfig();
    return !StringUtil.isNullOrEmpty(config.get(CF_SITE_KEY))
        && !StringUtil.isNullOrEmpty(config.get(CF_SITE_KEY))
        && !StringUtil.isNullOrEmpty(config.get(CF_ACTION));
  }

  public static boolean validate(
      CloudflareTurnstile.Config config,
      String turnstileResponse,
      String remoteAddr,
      KeycloakSession session) {

    try {
      HttpPost request = buildAssessmentRequest(remoteAddr, turnstileResponse, config);
      HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
      HttpResponse response = httpClient.execute(request);

      if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
        log.errorf("Could not create Turnstile assessment: %s", response.getStatusLine());
        EntityUtils.consumeQuietly(response.getEntity());
        throw new Exception(response.getStatusLine().getReasonPhrase());
      }

      var assessment =
          JsonSerialization.readValue(response.getEntity().getContent(), TurnstileResponse.class);
      log.tracef("Got assessment response: %s", assessment);

      return assessment.isSuccess() && config.getAction().equals(assessment.getAction());
    } catch (Exception e) {
      ServicesLogger.LOGGER.recaptchaFailed(e);

      return false;
    }
  }
}
