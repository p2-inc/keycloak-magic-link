package io.phasetwo.keycloak.magic.auth.magic.spi.org;

import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationConfig;
import java.util.Map;

/**
 * Typed config for {@link OrganizationMagicLinkCustomizationProvider}.
 *
 * <p>Reads the organization ID and membership-enforcement flag from the authenticator config map.
 */
public final class OrganizationMagicLinkCustomizationConfig extends MagicLinkCustomizationConfig {

  static final String ORG_ID_PROPERTY = "ext-magic-org-id";
  static final String REQUIRE_MEMBERSHIP_PROPERTY = "ext-magic-org-require-membership";

  OrganizationMagicLinkCustomizationConfig(Map<String, String> config) {
    super(config);
  }

  /**
   * The organization identifier users must belong to, or {@code null} if not configured (in which
   * case the membership check is skipped).
   */
  public String getOrganizationId() {
    return getString(ORG_ID_PROPERTY, null);
  }

  /**
   * Whether authentication is denied for users who are not members of the configured organization.
   * Defaults to {@code true}.
   */
  public boolean isRequireMembership() {
    return getBoolean(REQUIRE_MEMBERSHIP_PROPERTY, true);
  }
}
