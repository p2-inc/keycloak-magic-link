package io.phasetwo.keycloak.magic.auth.magic.spi;

import com.google.auto.service.AutoService;
import java.util.List;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for the default magic link customization — no extra config properties, all users allowed,
 * standard email template.
 */
public final class DefaultMagicLinkCustomizationProviderFactory
    implements MagicLinkCustomizationProviderFactory {

  public static final String PROVIDER_ID = "default";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }

  @Override
  public MagicLinkCustomizationProvider create(
      KeycloakSession session, Map<String, String> authenticatorConfig) {
    return new DefaultMagicLinkCustomizationProvider();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
