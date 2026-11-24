package io.phasetwo.keycloak.magic.auth.activation;

import com.google.auto.service.AutoService;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Factory for {@link ActivationOrResetEmailAuthenticator}. */
@AutoService(AuthenticatorFactory.class)
public final class ActivationOrResetEmailAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-auth-activation-reset-email";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED
  };

  /** Criteria properties first, then the stock Send Reset Email properties (passed through). */
  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES =
      Stream.concat(
              ActivationCriteria.CRITERIA_CONFIG_PROPERTIES.stream(),
              new ResetCredentialEmail().getConfigProperties().stream())
          .collect(Collectors.toList());

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Send Activation or Reset Email";
  }

  @Override
  public String getHelpText() {
    return "Send Reset Email replacement that emails activation instructions to accounts still"
        + " pending activation, and the standard password reset email to activated accounts.";
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new ActivationOrResetEmailAuthenticator();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
