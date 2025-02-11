package io.phasetwo.keycloak.magic.auth.util;

import com.google.common.collect.ImmutableList;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;
import org.keycloak.models.KeycloakSession;

@JBossLog
public class CloudflareTurnstile {

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

  public static final String MSG_CAPTCHA_FAILED = "captchaFailed";
  public static final String MSG_CAPTCHA_NOT_CONFIGURED = "captchaNotConfigured";
  public static final String CF_TURNSTILE_RESPONSE = "cf-turnstile-response";
  private static final String TURNSTILE_DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"; // https://developers.cloudflare.com/turnstile/troubleshooting/testing/
  private static final String CF_SITE_KEY = "site.key";
  private static final String CF_SITE_SECRET = "secret";
  private static final String ACTION = "action";
  private static final String DEFAULT_ACTION = "login";

  public static List<ProviderConfigProperty> configProperties;

  static {
    ImmutableList.Builder<ProviderConfigProperty> builder = new ImmutableList.Builder<ProviderConfigProperty>();
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
    prop.setName(ACTION);
    prop.setLabel("Action");
    prop.setHelpText("A value that can be used to differentiate widgets under the same Site Key in analytics.");
    prop.setType(ProviderConfigProperty.STRING_TYPE);
    prop.setDefaultValue(DEFAULT_ACTION);
    builder.add(prop);

    configProperties = builder.build();
  }

  public static boolean validate(Config config, String captcha, String remoteAddr, KeycloakSession session) {
    try {
      Map<String, Object> response = SimpleHttp
                                     .doPost("https://challenges.cloudflare.com/turnstile/v0/siteverify", session)
                                     .param("secret", config.getSecret())
                                     .param("response", captcha)
                                     .param("remoteip", remoteAddr)
                                     .asJson(Map.class);

      log.debugf("Turnstile response: %s", response);

      return Boolean.TRUE.equals(response.get("success")) &&
          (TURNSTILE_DUMMY_TOKEN.equals(captcha) || config.getAction().equals(response.get("action")));
    } catch (Exception e) {
      log.warnf(e, "Failed to validate Turnstile response: %s", e.getMessage());
      return false;
    }
  }
  
  public static Config readConfig(Map<String, String> config) {
    String siteKey = config.get(CF_SITE_KEY);
    if (siteKey == null) return null;
    String secret = config.get(CF_SITE_SECRET);
    if (secret == null) return null;
    String action = config.get(ACTION);
    return new Config(siteKey, secret, action);
  }

  public static LoginFormsProvider prepareForm(LoginFormsProvider form, Config config, String lang) {
    form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
    return form.setAttribute("captchaRequired", true)
        .setAttribute("captchaSiteKey", config != null ? config.getSiteKey() : null)
        .setAttribute("captchaAction", config != null ? config.getAction() : null)
        .setAttribute("captchaLanguage", lang != null ? lang : "en");
  }
}
