package io.phasetwo.keycloak.magic.auth.magic;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.common.base.Strings;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Typed wrapper around the authenticator config map for the standard magic link flow.
 * Also owns the static {@link ProviderConfigProperty} definitions consumed by
 * {@link AbstractMagicLinkAuthenticatorFactory#getConfigProperties()}.
 */
public final class MagicLinkConfig {

  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";
  static final String UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY = "ext-magic-update-password-action";
  static final String ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY = "ext-magic-allow-token-reuse";
  static final String ACTION_TOKEN_LIFE_SPAN = "ext-magic-token-life-span";

  private static final ProviderConfigProperty FORCE_CREATE_PROPERTY;
  private static final ProviderConfigProperty UPDATE_PROFILE_PROPERTY;
  private static final ProviderConfigProperty UPDATE_PASSWORD_PROPERTY;
  private static final ProviderConfigProperty TOKEN_PERSISTENT_PROPERTY;
  private static final ProviderConfigProperty TOKEN_LIFESPAN_PROPERTY;

  static {
    FORCE_CREATE_PROPERTY = new ProviderConfigProperty();
    FORCE_CREATE_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    FORCE_CREATE_PROPERTY.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    FORCE_CREATE_PROPERTY.setLabel("Force create user");
    FORCE_CREATE_PROPERTY.setHelpText(
        "Creates a new user when an email is provided that does not match an existing user.");
    FORCE_CREATE_PROPERTY.setDefaultValue(true);

    UPDATE_PROFILE_PROPERTY = new ProviderConfigProperty();
    UPDATE_PROFILE_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    UPDATE_PROFILE_PROPERTY.setName(UPDATE_PROFILE_ACTION_CONFIG_PROPERTY);
    UPDATE_PROFILE_PROPERTY.setLabel("Update profile on create");
    UPDATE_PROFILE_PROPERTY.setHelpText("Add an UPDATE_PROFILE required action if the user was created.");
    UPDATE_PROFILE_PROPERTY.setDefaultValue(false);

    UPDATE_PASSWORD_PROPERTY = new ProviderConfigProperty();
    UPDATE_PASSWORD_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    UPDATE_PASSWORD_PROPERTY.setName(UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY);
    UPDATE_PASSWORD_PROPERTY.setLabel("Update password on create");
    UPDATE_PASSWORD_PROPERTY.setHelpText("Add an UPDATE_PASSWORD required action if the user was created.");
    UPDATE_PASSWORD_PROPERTY.setDefaultValue(false);

    TOKEN_PERSISTENT_PROPERTY = new ProviderConfigProperty();
    TOKEN_PERSISTENT_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    TOKEN_PERSISTENT_PROPERTY.setName(ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY);
    TOKEN_PERSISTENT_PROPERTY.setLabel("Allow magic link to be reusable");
    TOKEN_PERSISTENT_PROPERTY.setHelpText("Toggle whether magic link should be persistent until expired.");
    TOKEN_PERSISTENT_PROPERTY.setDefaultValue(true);

    TOKEN_LIFESPAN_PROPERTY = new ProviderConfigProperty();
    TOKEN_LIFESPAN_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    TOKEN_LIFESPAN_PROPERTY.setName(ACTION_TOKEN_LIFE_SPAN);
    TOKEN_LIFESPAN_PROPERTY.setLabel("Token lifespan");
    TOKEN_LIFESPAN_PROPERTY.setHelpText(
        "Amount of time the magic link is valid, in seconds. Defaults to 86400 s (1 day) if not set.");
  }

  /** Ordered base config properties shared by all standard magic link authenticator variants. */
  static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(
      FORCE_CREATE_PROPERTY,
      UPDATE_PROFILE_PROPERTY,
      UPDATE_PASSWORD_PROPERTY,
      TOKEN_PERSISTENT_PROPERTY,
      TOKEN_LIFESPAN_PROPERTY);

  private final Map<String, String> config;

  public MagicLinkConfig(AuthenticatorConfigModel configModel) {
    this.config = (configModel != null && configModel.getConfig() != null)
        ? configModel.getConfig()
        : Map.of();
  }

  /** Whether to create a new realm user when the submitted email has no match. */
  public boolean isForceCreate() {
    return getBoolean(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, true);
  }

  /** Whether to add {@code UPDATE_PROFILE} as a required action on newly created users. */
  public boolean isUpdateProfile() {
    return getBoolean(UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, false);
  }

  /** Whether to add {@code UPDATE_PASSWORD} as a required action on newly created users. */
  public boolean isUpdatePassword() {
    return getBoolean(UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY, false);
  }

  /** Whether the action token may be redeemed more than once within its validity window. */
  public boolean isTokenPersistent() {
    return getBoolean(ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY, true);
  }

  /** Token validity in seconds, empty if not configured (caller uses default). */
  public OptionalInt getTokenLifespan() {
    String val = config.get(ACTION_TOKEN_LIFE_SPAN);
    if (Strings.isNullOrEmpty(val)) return OptionalInt.empty();
    try {
      return OptionalInt.of(Integer.parseInt(val.trim()));
    } catch (NumberFormatException e) {
      return OptionalInt.empty();
    }
  }

  /** Raw config map, for passing to customization providers. */
  public Map<String, String> raw() {
    return config;
  }

  private boolean getBoolean(String key, boolean defaultValue) {
    String val = config.get(key);
    return Strings.isNullOrEmpty(val) ? defaultValue : Boolean.parseBoolean(val.trim());
  }
}
