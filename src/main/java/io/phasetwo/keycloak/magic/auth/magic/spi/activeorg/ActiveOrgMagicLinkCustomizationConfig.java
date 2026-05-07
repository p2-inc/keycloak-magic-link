package io.phasetwo.keycloak.magic.auth.magic.spi.activeorg;

import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationConfig;
import java.util.Map;

/** Typed config for {@link ActiveOrgMagicLinkCustomizationProvider}. */
public final class ActiveOrgMagicLinkCustomizationConfig extends MagicLinkCustomizationConfig {

  static final String ORG_ID_PROPERTY = "ext-magic-org-id";
  static final String REQUIRE_MEMBERSHIP_PROPERTY = "ext-magic-org-require-membership";

  ActiveOrgMagicLinkCustomizationConfig(Map<String, String> config) {
    super(config);
  }

  public String getOrganizationId() {
    return getString(ORG_ID_PROPERTY, null);
  }

  public boolean isRequireMembership() {
    return getBoolean(REQUIRE_MEMBERSHIP_PROPERTY, true);
  }
}
