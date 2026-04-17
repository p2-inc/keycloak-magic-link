package io.phasetwo.keycloak.magic.auth.util;

import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import io.phasetwo.keycloak.magic.auth.cloudflare.TurnstileAssessmentRequest;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;
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

  public static class Config {
    private final String siteKey;
    private final String secret;
    private final String action;

    public Config(String siteKey, String secret, String action) {
      this.siteKey = siteKey;
      this.secret = secret;
      this.action = action;
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
  }

  public static Config readConfig(Map<String, String> config) {
    return new Config(config.get(CF_SITE_KEY), config.get(CF_SITE_SECRET), config.get(CF_ACTION));
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

    configProperties = builder.build();
  }

    public static String getClientIpAddress(AuthenticationFlowContext context) {
        return context.getConnection().getRemoteAddr();
    }

    public static String getClientIpAddress(ValidationContext context) {
        return context.getConnection().getRemoteAddr();
    }

    public static HttpPost buildAssessmentRequest(String ipAddress, String captcha, Map<String, String> config) throws IOException {
        String url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

        HttpPost request = new HttpPost(url);
        TurnstileAssessmentRequest body = new TurnstileAssessmentRequest(config.get(CloudflareTurnstile.CF_SITE_SECRET),
                captcha,ipAddress);
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
}
