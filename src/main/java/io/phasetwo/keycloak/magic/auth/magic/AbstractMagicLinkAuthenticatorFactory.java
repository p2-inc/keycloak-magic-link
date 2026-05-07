package io.phasetwo.keycloak.magic.auth.magic;

import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProviderFactory;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Base factory for standard magic link authenticator variants.
 *
 * <p>Subclasses supply a {@link MagicLinkCustomizationProviderFactory} at construction time.
 * This factory contributes additional {@link ProviderConfigProperty} entries (appended after the
 * base {@link MagicLinkConfig#CONFIG_PROPERTIES}) and is passed to the
 * {@link MagicLinkAuthenticator} so it can create the provider at authentication time with the
 * per-execution config map.
 *
 * <p>Minimal concrete subclass:
 * <pre>{@code
 * @AutoService(AuthenticatorFactory.class)
 * public final class AcmeMagicLinkAuthenticatorFactory extends AbstractMagicLinkAuthenticatorFactory {
 *
 *     public static final String PROVIDER_ID = "ext-magic-acme";
 *
 *     public AcmeMagicLinkAuthenticatorFactory() {
 *         super(new AcmeMagicLinkCustomizationProviderFactory());
 *     }
 *
 *     @Override public String getId()          { return PROVIDER_ID; }
 *     @Override public String getDisplayType() { return "Magic Link (Acme)"; }
 *     @Override public String getHelpText()    { return "Magic link restricted to Acme users."; }
 * }
 * }</pre>
 */
public abstract class AbstractMagicLinkAuthenticatorFactory implements AuthenticatorFactory {

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  private final MagicLinkCustomizationProviderFactory customizationProviderFactory;

  protected AbstractMagicLinkAuthenticatorFactory(
      MagicLinkCustomizationProviderFactory customizationProviderFactory) {
    this.customizationProviderFactory = customizationProviderFactory;
  }

  /** No-arg constructor for subclasses that manage their own {@link #create} and {@link #getConfigProperties}. */
  protected AbstractMagicLinkAuthenticatorFactory() {
    this.customizationProviderFactory = null;
  }

  @Override
  public final boolean isConfigurable() {
    return true;
  }

  @Override
  public final boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public final AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public final String getReferenceCategory() {
    return "alternate-auth";
  }

  /**
   * Returns the base {@link MagicLinkConfig#CONFIG_PROPERTIES} followed by any additional
   * properties declared by the active {@link MagicLinkCustomizationProviderFactory}.
   */
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    if (customizationProviderFactory == null) return MagicLinkConfig.CONFIG_PROPERTIES;
    return Stream.concat(
            MagicLinkConfig.CONFIG_PROPERTIES.stream(),
            customizationProviderFactory.getConfigProperties().stream())
        .collect(Collectors.toList());
  }

  /** Creates a {@link MagicLinkAuthenticator} wired to the active customization factory. */
  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkAuthenticator(customizationProviderFactory);
  }

  @Override
  public final void init(Config.Scope config) {}

  /** Override to register {@code RealmPostCreateEvent} listeners or other factory-level hooks. */
  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public final void close() {}
}
