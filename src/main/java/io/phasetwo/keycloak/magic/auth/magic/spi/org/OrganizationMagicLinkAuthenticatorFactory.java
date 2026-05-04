package io.phasetwo.keycloak.magic.auth.magic.spi.org;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.magic.AbstractMagicLinkAuthenticatorFactory;
import org.keycloak.authentication.AuthenticatorFactory;

/**
 * Registers the organization-scoped magic link authenticator as a standalone Keycloak authenticator
 * (provider ID: {@code ext-magic-org}, display name: {@code Magic Link (Organization)}).
 *
 * <p>Wires {@link OrganizationMagicLinkCustomizationProviderFactory} into
 * {@link AbstractMagicLinkAuthenticatorFactory} so that the admin console shows this as a separate
 * option from the default Magic Link authenticator. Configuration fields (organization ID and
 * require-membership toggle) are appended to the authenticator's configuration panel automatically.
 */
@AutoService(AuthenticatorFactory.class)
public final class OrganizationMagicLinkAuthenticatorFactory
    extends AbstractMagicLinkAuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-magic-org";

  public OrganizationMagicLinkAuthenticatorFactory() {
    super(new OrganizationMagicLinkCustomizationProviderFactory());
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Magic Link (Organization)";
  }

  @Override
  public String getHelpText() {
    return "Magic link authenticator that restricts authentication to members of a configured organization.";
  }
}
