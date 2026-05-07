package io.phasetwo.keycloak.magic.auth.magic.spi.activeorg;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.magic.AbstractMagicLinkAuthenticatorFactory;
import org.keycloak.authentication.AuthenticatorFactory;

/**
 * Registers the active-org–scoped magic link authenticator as a standalone Keycloak authenticator
 * (provider ID: {@code ext-magic-active-org}, display name: {@code Magic Link (Active Org)}).
 */
@AutoService(AuthenticatorFactory.class)
public final class ActiveOrgMagicLinkAuthenticatorFactory
    extends AbstractMagicLinkAuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-magic-active-org";

  public ActiveOrgMagicLinkAuthenticatorFactory() {
    super(new ActiveOrgMagicLinkCustomizationProviderFactory());
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Magic Link (Active Org)";
  }

  @Override
  public String getHelpText() {
    return "Magic link authenticator that restricts authentication to members of the user's active organization.";
  }
}
