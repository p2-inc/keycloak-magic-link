package io.phasetwo.keycloak.magic.auth.magic.spi.activeorg;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProvider;
import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProviderFactory;
import java.util.List;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for {@link ActiveOrgMagicLinkCustomizationProvider}.
 *
 * <p>Exposes two config properties in the authenticator's admin-console panel:
 * <ul>
 *   <li>{@code ext-magic-org-id} — the organization ID users must belong to</li>
 *   <li>{@code ext-magic-org-require-membership} — whether to deny non-members</li>
 * </ul>
 */
public final class ActiveOrgMagicLinkCustomizationProviderFactory
    implements MagicLinkCustomizationProviderFactory {

  public static final String PROVIDER_ID = "active-org";

  private static final ProviderConfigProperty ORG_ID_PROP;
  private static final ProviderConfigProperty REQUIRE_MEMBERSHIP_PROP;

  static {
    ORG_ID_PROP = new ProviderConfigProperty();
    ORG_ID_PROP.setType(ProviderConfigProperty.STRING_TYPE);
    ORG_ID_PROP.setName(ActiveOrgMagicLinkCustomizationConfig.ORG_ID_PROPERTY);
    ORG_ID_PROP.setLabel("Organization ID");
    ORG_ID_PROP.setHelpText(
        "Restrict magic link authentication to members of this organization. "
            + "Membership is checked via the user attribute org.ro.active.");

    REQUIRE_MEMBERSHIP_PROP = new ProviderConfigProperty();
    REQUIRE_MEMBERSHIP_PROP.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    REQUIRE_MEMBERSHIP_PROP.setName(ActiveOrgMagicLinkCustomizationConfig.REQUIRE_MEMBERSHIP_PROPERTY);
    REQUIRE_MEMBERSHIP_PROP.setLabel("Require organization membership");
    REQUIRE_MEMBERSHIP_PROP.setHelpText(
        "If enabled, denies authentication for users who are not members of the configured organization.");
    REQUIRE_MEMBERSHIP_PROP.setDefaultValue(true);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(ORG_ID_PROP, REQUIRE_MEMBERSHIP_PROP);
  }

  @Override
  public MagicLinkCustomizationProvider create(
      KeycloakSession session, Map<String, String> authenticatorConfig) {
    return new ActiveOrgMagicLinkCustomizationProvider(
        session, new ActiveOrgMagicLinkCustomizationConfig(authenticatorConfig));
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
