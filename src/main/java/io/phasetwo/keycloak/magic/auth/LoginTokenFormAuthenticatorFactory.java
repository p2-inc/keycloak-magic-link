package io.phasetwo.keycloak.magic.auth;

import com.google.auto.service.AutoService;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Factory for {@link LoginTokenFormAuthenticator}. */
@AutoService(AuthenticatorFactory.class)
public class LoginTokenFormAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "login-token-form";

  private static final LoginTokenFormAuthenticator SINGLETON = new LoginTokenFormAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Login Token";
  }

  @Override
  public String getHelpText() {
    return "Shows a form for manual Login Token entry. Accepts tokens with or without the lt: prefix.";
  }

  @Override
  public String getReferenceCategory() {
    return "magic-link";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.ALTERNATIVE,
      AuthenticationExecutionModel.Requirement.DISABLED,
    };
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
