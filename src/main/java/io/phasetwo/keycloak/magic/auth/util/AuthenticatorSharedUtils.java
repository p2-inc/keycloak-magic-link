package io.phasetwo.keycloak.magic.auth.util;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;

public final class AuthenticatorSharedUtils {
    public static boolean is(AuthenticationFlowContext context, String propName, boolean defaultValue) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) return defaultValue;

        Map<String, String> config = authenticatorConfig.getConfig();
        if (config == null) return defaultValue;

        String v = config.get(propName);
        if (v == null || "".equals(v)) return defaultValue;

        return v.trim().toLowerCase().equals("true");
    }
}
