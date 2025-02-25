package io.phasetwo.keycloak.magic.auth.util;

import com.google.common.collect.ImmutableList;
import java.util.List;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

@JBossLog
public class CloudflareTurnstile {

  public static final String MSG_CAPTCHA_FAILED = "captchaFailed";
  public static final String MSG_CAPTCHA_NOT_CONFIGURED = "captchaNotConfigured";
  public static final String CF_TURNSTILE_RESPONSE = "cf-turnstile-response";

  private static final String CF_SITE_KEY = "cloudflare_site_key";
  private static final String CF_SITE_SECRET = "cloudflare_secret";
  private static final String CF_ACTION = "cloudflare_action";
  private static final String DEFAULT_CF_ACTION = "login";

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

  private static final String TURNSTILE_DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX";

  public static boolean validate(
      Config config, String captcha, String remoteAddr, KeycloakSession session) {
    try {
      Map<String, Object> response =
          SimpleHttp.doPost("https://challenges.cloudflare.com/turnstile/v0/siteverify", session)
              .param("secret", config.getSecret())
              .param("response", captcha)
              .param("remoteip", remoteAddr)
              .asJson(Map.class);

      log.debugf("Turnstile response: %s", response);

      return Boolean.TRUE.equals(response.get("success"))
          && (TURNSTILE_DUMMY_TOKEN.equals(captcha)
              || config.getAction().equals(response.get("action")));
    } catch (Exception e) {
      log.warnf(e, "Failed to validate Turnstile response: %s", e.getMessage());
      return false;
    }
  }

  public static LoginFormsProvider prepareForm(
      LoginFormsProvider form, Config config, String lang) {
    form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
    return form.setAttribute("captchaRequired", true)
        .setAttribute("captchaSiteKey", config != null ? config.getSiteKey() : null)
        .setAttribute("captchaAction", config != null ? config.getAction() : null)
        .setAttribute("captchaLanguage", lang != null ? lang : "en");
  }
}
