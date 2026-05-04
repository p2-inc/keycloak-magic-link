package io.phasetwo.keycloak.magic.auth.magic.spi;

import com.google.common.base.Strings;
import java.util.Map;

/**
 * Base class for typed config wrappers used by {@link MagicLinkCustomizationProvider}
 * implementations.
 *
 * <p>Subclasses define their own config-key constants and expose typed accessors, keeping
 * raw-map access confined to this base class. For example:
 *
 * <pre>{@code
 * public class AcmeCustomizationConfig extends MagicLinkCustomizationConfig {
 *     static final String TENANT_ID_PROPERTY = "ext-magic-acme-tenant-id";
 *
 *     public AcmeCustomizationConfig(Map<String, String> config) { super(config); }
 *
 *     public String getTenantId() { return getString(TENANT_ID_PROPERTY, null); }
 * }
 * }</pre>
 */
public abstract class MagicLinkCustomizationConfig {

  private final Map<String, String> config;

  protected MagicLinkCustomizationConfig(Map<String, String> config) {
    this.config = config != null ? config : Map.of();
  }

  protected boolean getBoolean(String key, boolean defaultValue) {
    String val = config.get(key);
    return Strings.isNullOrEmpty(val) ? defaultValue : Boolean.parseBoolean(val.trim());
  }

  protected String getString(String key, String defaultValue) {
    String val = config.get(key);
    return Strings.isNullOrEmpty(val) ? defaultValue : val.trim();
  }

  /** Raw map, use sparingly — prefer typed accessors defined in the subclass. */
  protected Map<String, String> raw() {
    return config;
  }
}
