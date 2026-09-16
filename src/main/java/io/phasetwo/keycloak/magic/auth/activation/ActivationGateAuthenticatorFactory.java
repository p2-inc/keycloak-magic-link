package io.phasetwo.keycloak.magic.auth.activation;

import com.google.auto.service.AutoService;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Factory for {@link ActivationGateAuthenticator}. */
@AutoService(AuthenticatorFactory.class)
public final class ActivationGateAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-auth-activation-gate";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Activation Gate";
  }

  @Override
  public String getHelpText() {
    return "Email-first login router. Pending accounts are emailed activation instructions before"
        + " any password prompt; activated accounts continue to the next authenticator (e.g."
        + " Password Form). Unknown emails receive the same response as pending accounts to avoid"
        + " account enumeration.";
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new ActivationGateAuthenticator();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ActivationCriteria.GATE_CONFIG_PROPERTIES;
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
