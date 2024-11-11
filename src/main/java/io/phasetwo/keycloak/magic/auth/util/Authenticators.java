package io.phasetwo.keycloak.magic.auth.util;

import com.google.common.base.Strings;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public final class Authenticators {
  public static boolean is(
      AuthenticationFlowContext context, String propName, boolean defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(propName);
    if (Strings.isNullOrEmpty(v)) return defaultValue;

    return Boolean.parseBoolean(v.trim());
  }

  public static String get(
          AuthenticationFlowContext context, String propName, String defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(propName);
    if (Strings.isNullOrEmpty(v)) return defaultValue;

    return v.trim();
  }
}
