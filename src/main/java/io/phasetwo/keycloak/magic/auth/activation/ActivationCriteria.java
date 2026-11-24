package io.phasetwo.keycloak.magic.auth.activation;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Typed wrapper around the per-execution config map shared by the activation authenticators
 * ({@link ActivationGateAuthenticator} and {@link ActivationOrResetEmailAuthenticator}). Also owns
 * the static {@link ProviderConfigProperty} definitions their factories expose in the admin
 * console.
 *
 * <p>An account is <em>pending activation</em> when any enabled criterion matches (OR semantics):
 *
 * <ul>
 *   <li>the user's email address is not verified,
 *   <li>the user has no password credential (e.g. accounts created by a migration that sets
 *       credentials through an execute-actions email),
 *   <li>the user has one of the configured required actions outstanding.
 * </ul>
 */
public final class ActivationCriteria {

  static final String PENDING_UNVERIFIED_EMAIL_CONFIG_PROPERTY =
      "ext-activation-pending-unverified-email";
  static final String PENDING_NO_PASSWORD_CONFIG_PROPERTY = "ext-activation-pending-no-password";
  static final String PENDING_REQUIRED_ACTIONS_CONFIG_PROPERTY =
      "ext-activation-pending-required-actions";
  static final String EMAIL_ACTIONS_CONFIG_PROPERTY = "ext-activation-email-actions";
  static final String EXPLICIT_ACTIONS_CONFIG_PROPERTY = "ext-activation-explicit-actions";
  static final String TOKEN_LIFESPAN_CONFIG_PROPERTY = "ext-activation-token-lifespan";
  static final String RESEND_COOLDOWN_CONFIG_PROPERTY = "ext-activation-resend-cooldown";

  static final String EMAIL_ACTIONS_DERIVE = "derive";
  static final String EMAIL_ACTIONS_EXPLICIT = "explicit";

  static final int DEFAULT_RESEND_COOLDOWN_SECONDS = 30;

  private static final ProviderConfigProperty PENDING_UNVERIFIED_EMAIL_PROPERTY;
  private static final ProviderConfigProperty PENDING_NO_PASSWORD_PROPERTY;
  private static final ProviderConfigProperty PENDING_REQUIRED_ACTIONS_PROPERTY;
  private static final ProviderConfigProperty EMAIL_ACTIONS_PROPERTY;
  private static final ProviderConfigProperty EXPLICIT_ACTIONS_PROPERTY;
  private static final ProviderConfigProperty TOKEN_LIFESPAN_PROPERTY;
  private static final ProviderConfigProperty RESEND_COOLDOWN_PROPERTY;

  static {
    PENDING_UNVERIFIED_EMAIL_PROPERTY = new ProviderConfigProperty();
    PENDING_UNVERIFIED_EMAIL_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    PENDING_UNVERIFIED_EMAIL_PROPERTY.setName(PENDING_UNVERIFIED_EMAIL_CONFIG_PROPERTY);
    PENDING_UNVERIFIED_EMAIL_PROPERTY.setLabel("Pending when email unverified");
    PENDING_UNVERIFIED_EMAIL_PROPERTY.setHelpText(
        "Treat a user whose email address is not verified as pending activation.");
    PENDING_UNVERIFIED_EMAIL_PROPERTY.setDefaultValue(true);

    PENDING_NO_PASSWORD_PROPERTY = new ProviderConfigProperty();
    PENDING_NO_PASSWORD_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    PENDING_NO_PASSWORD_PROPERTY.setName(PENDING_NO_PASSWORD_CONFIG_PROPERTY);
    PENDING_NO_PASSWORD_PROPERTY.setLabel("Pending when no password");
    PENDING_NO_PASSWORD_PROPERTY.setHelpText(
        "Treat a user without a password credential as pending activation. Covers migrated"
            + " accounts that set their first password through the activation email.");
    PENDING_NO_PASSWORD_PROPERTY.setDefaultValue(true);

    PENDING_REQUIRED_ACTIONS_PROPERTY = new ProviderConfigProperty();
    PENDING_REQUIRED_ACTIONS_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    PENDING_REQUIRED_ACTIONS_PROPERTY.setName(PENDING_REQUIRED_ACTIONS_CONFIG_PROPERTY);
    PENDING_REQUIRED_ACTIONS_PROPERTY.setLabel("Pending required actions");
    PENDING_REQUIRED_ACTIONS_PROPERTY.setHelpText(
        "Comma-separated required action aliases (e.g. VERIFY_EMAIL,UPDATE_PASSWORD). A user with"
            + " any of these outstanding is treated as pending activation. Leave empty to rely on"
            + " the two toggles above.");

    EMAIL_ACTIONS_PROPERTY = new ProviderConfigProperty();
    EMAIL_ACTIONS_PROPERTY.setType(ProviderConfigProperty.LIST_TYPE);
    EMAIL_ACTIONS_PROPERTY.setName(EMAIL_ACTIONS_CONFIG_PROPERTY);
    EMAIL_ACTIONS_PROPERTY.setLabel("Activation email actions");
    EMAIL_ACTIONS_PROPERTY.setHelpText(
        "Which required actions the emailed activation link performs. 'derive' sends the user's"
            + " own outstanding actions (plus VERIFY_EMAIL if unverified and UPDATE_PASSWORD if no"
            + " password is set); 'explicit' sends the configured list below.");
    EMAIL_ACTIONS_PROPERTY.setOptions(List.of(EMAIL_ACTIONS_DERIVE, EMAIL_ACTIONS_EXPLICIT));
    EMAIL_ACTIONS_PROPERTY.setDefaultValue(EMAIL_ACTIONS_DERIVE);

    EXPLICIT_ACTIONS_PROPERTY = new ProviderConfigProperty();
    EXPLICIT_ACTIONS_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    EXPLICIT_ACTIONS_PROPERTY.setName(EXPLICIT_ACTIONS_CONFIG_PROPERTY);
    EXPLICIT_ACTIONS_PROPERTY.setLabel("Explicit email actions");
    EXPLICIT_ACTIONS_PROPERTY.setHelpText(
        "Comma-separated required action aliases the activation link performs when 'Activation"
            + " email actions' is set to 'explicit'.");

    TOKEN_LIFESPAN_PROPERTY = new ProviderConfigProperty();
    TOKEN_LIFESPAN_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    TOKEN_LIFESPAN_PROPERTY.setName(TOKEN_LIFESPAN_CONFIG_PROPERTY);
    TOKEN_LIFESPAN_PROPERTY.setLabel("Activation link lifespan");
    TOKEN_LIFESPAN_PROPERTY.setHelpText(
        "Amount of time the activation link is valid, in seconds. Defaults to the realm's"
            + " admin-generated action token lifespan if not set.");

    RESEND_COOLDOWN_PROPERTY = new ProviderConfigProperty();
    RESEND_COOLDOWN_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    RESEND_COOLDOWN_PROPERTY.setName(RESEND_COOLDOWN_CONFIG_PROPERTY);
    RESEND_COOLDOWN_PROPERTY.setLabel("Resend cooldown");
    RESEND_COOLDOWN_PROPERTY.setHelpText(
        "Minimum time in seconds between activation emails for the same authentication session."
            + " Defaults to "
            + DEFAULT_RESEND_COOLDOWN_SECONDS
            + " s if not set.");
  }

  /** Config properties shared by both activation authenticators. */
  public static final List<ProviderConfigProperty> CRITERIA_CONFIG_PROPERTIES =
      List.of(
          PENDING_UNVERIFIED_EMAIL_PROPERTY,
          PENDING_NO_PASSWORD_PROPERTY,
          PENDING_REQUIRED_ACTIONS_PROPERTY,
          EMAIL_ACTIONS_PROPERTY,
          EXPLICIT_ACTIONS_PROPERTY,
          TOKEN_LIFESPAN_PROPERTY);

  /** Config properties for the browser-flow activation gate (adds the resend cooldown). */
  public static final List<ProviderConfigProperty> GATE_CONFIG_PROPERTIES =
      List.of(
          PENDING_UNVERIFIED_EMAIL_PROPERTY,
          PENDING_NO_PASSWORD_PROPERTY,
          PENDING_REQUIRED_ACTIONS_PROPERTY,
          EMAIL_ACTIONS_PROPERTY,
          EXPLICIT_ACTIONS_PROPERTY,
          TOKEN_LIFESPAN_PROPERTY,
          RESEND_COOLDOWN_PROPERTY);

  private final Map<String, String> config;

  public ActivationCriteria(AuthenticatorConfigModel configModel) {
    this.config =
        (configModel != null && configModel.getConfig() != null)
            ? configModel.getConfig()
            : Map.of();
  }

  /** Whether the user still needs activation before password authentication makes sense. */
  public boolean isPending(UserModel user) {
    if (getBoolean(PENDING_UNVERIFIED_EMAIL_CONFIG_PROPERTY, true) && !user.isEmailVerified()) {
      return true;
    }
    if (getBoolean(PENDING_NO_PASSWORD_CONFIG_PROPERTY, true) && !hasPassword(user)) {
      return true;
    }
    Set<String> watched = getCommaSeparated(PENDING_REQUIRED_ACTIONS_CONFIG_PROPERTY);
    return !watched.isEmpty() && user.getRequiredActionsStream().anyMatch(watched::contains);
  }

  /**
   * Required actions the activation link performs for this user. In 'derive' mode (the default)
   * these are the user's own outstanding actions plus whatever their account state implies, so a
   * self-registered user gets VERIFY_EMAIL and a migrated user without a password gets
   * VERIFY_EMAIL and UPDATE_PASSWORD from the same configuration.
   */
  public List<String> emailActions(UserModel user) {
    if (EMAIL_ACTIONS_EXPLICIT.equals(config.get(EMAIL_ACTIONS_CONFIG_PROPERTY))) {
      return List.copyOf(getCommaSeparated(EXPLICIT_ACTIONS_CONFIG_PROPERTY));
    }
    Set<String> actions = new LinkedHashSet<>();
    user.getRequiredActionsStream().forEach(actions::add);
    if (!user.isEmailVerified()) {
      actions.add(UserModel.RequiredAction.VERIFY_EMAIL.name());
    }
    if (!hasPassword(user)) {
      actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());
    }
    return List.copyOf(actions);
  }

  /** Activation link validity in seconds, falling back to the realm's admin action token lifespan. */
  public int getTokenLifespan(RealmModel realm) {
    return getInt(TOKEN_LIFESPAN_CONFIG_PROPERTY, realm.getActionTokenGeneratedByAdminLifespan());
  }

  /** Minimum seconds between activation emails within one authentication session. */
  public int getResendCooldownSeconds() {
    return getInt(RESEND_COOLDOWN_CONFIG_PROPERTY, DEFAULT_RESEND_COOLDOWN_SECONDS);
  }

  private static boolean hasPassword(UserModel user) {
    return user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
  }

  private Set<String> getCommaSeparated(String key) {
    String val = config.get(key);
    if (Strings.isNullOrEmpty(val)) return Set.of();
    return new LinkedHashSet<>(Splitter.on(',').trimResults().omitEmptyStrings().splitToList(val));
  }

  private boolean getBoolean(String key, boolean defaultValue) {
    String val = config.get(key);
    return Strings.isNullOrEmpty(val) ? defaultValue : Boolean.parseBoolean(val.trim());
  }

  private int getInt(String key, int defaultValue) {
    String val = config.get(key);
    if (Strings.isNullOrEmpty(val)) return defaultValue;
    try {
      return Integer.parseInt(val.trim());
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }
}
