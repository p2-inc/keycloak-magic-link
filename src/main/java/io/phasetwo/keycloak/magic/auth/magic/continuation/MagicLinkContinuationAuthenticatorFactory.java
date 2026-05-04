package io.phasetwo.keycloak.magic.auth.magic.continuation;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.magic.AbstractMagicLinkAuthenticatorFactory;
import io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for {@link MagicLinkContinuationAuthenticator} (provider ID:
 * {@code magic-link-continuation-form}).
 *
 * <p>The continuation flow uses a long-polling mechanism so the browser tab waits while the user
 * clicks the link in a different browser or device. It does not participate in the
 * {@link io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationSpi}.
 */
@JBossLog
@AutoService(AuthenticatorFactory.class)
public final class MagicLinkContinuationAuthenticatorFactory
    extends AbstractMagicLinkAuthenticatorFactory {

  public static final String PROVIDER_ID = "magic-link-continuation-form";

  private static final ProviderConfigProperty CREATE_USER_PROPERTY;
  private static final ProviderConfigProperty TIMEOUT_PROPERTY;

  static {
    CREATE_USER_PROPERTY = new ProviderConfigProperty();
    CREATE_USER_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    CREATE_USER_PROPERTY.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    CREATE_USER_PROPERTY.setLabel("Force create user");
    CREATE_USER_PROPERTY.setHelpText(
        "Creates a new user when an email is provided that does not match an existing user.");
    CREATE_USER_PROPERTY.setDefaultValue(true);

    TIMEOUT_PROPERTY = new ProviderConfigProperty();
    TIMEOUT_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
    TIMEOUT_PROPERTY.setName(MagicLinkConstants.TIMEOUT);
    TIMEOUT_PROPERTY.setLabel("Expiration time");
    TIMEOUT_PROPERTY.setHelpText(
        "Magic link authenticator expiration time in minutes. Default expiration period 10 minutes.");
    TIMEOUT_PROPERTY.setDefaultValue("10");
  }

  public MagicLinkContinuationAuthenticatorFactory() {
    super();
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkContinuationAuthenticator();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Magic Link continuation";
  }

  @Override
  public String getHelpText() {
    return "Sign in with a magic link that will be sent to your email.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(CREATE_USER_PROPERTY, TIMEOUT_PROPERTY);
  }
}
