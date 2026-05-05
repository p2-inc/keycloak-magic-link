package io.phasetwo.keycloak.magic.auth.magic.spi;

import java.util.List;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;

/**
 * Factory for {@link MagicLinkCustomizationProvider} implementations.
 *
 * <p>Register via {@code @AutoService(ProviderFactory.class)} so the implementation is discovered
 * by Keycloak's service loader. To activate a custom implementation, pass an instance of the
 * factory to a concrete
 * {@link io.phasetwo.keycloak.magic.auth.magic.AbstractMagicLinkAuthenticatorFactory} subclass.
 *
 * <p>The config properties returned by {@link #getConfigProperties()} are automatically appended
 * to the authenticator's configuration panel in the Keycloak admin UI.
 */
public interface MagicLinkCustomizationProviderFactory {

  /**
   * Config properties contributed by this customization to the authenticator's configuration.
   * These are displayed in the Keycloak admin console beneath the base magic link properties.
   */
  List<ProviderConfigProperty> getConfigProperties();

  /**
   * Creates a provider configured with the raw authenticator config map.
   * Implementations should prefer this over {@link #create(KeycloakSession)}.
   *
   * @param session the active Keycloak session
   * @param authenticatorConfig the raw key-value config from the authenticator execution
   */
  MagicLinkCustomizationProvider create(KeycloakSession session, Map<String, String> authenticatorConfig);

  /** Delegates to {@link #create(KeycloakSession, Map)} with an empty config map. */
  default MagicLinkCustomizationProvider create(KeycloakSession session) {
    return create(session, Map.of());
  }
}
