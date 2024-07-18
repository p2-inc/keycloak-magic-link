package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class MagicLinkContinuationAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "magic-link-continuation-form";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkContinuationAuthenticator();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "alternate-auth";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
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
    // Force create user property configuration
    ProviderConfigProperty createUser = new ProviderConfigProperty();
    createUser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    createUser.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    createUser.setLabel("Force create user");
    createUser.setHelpText(
        "Creates a new user when an email is provided that does not match an existing user.");
    createUser.setDefaultValue(true);

    // Expiration time property configuration
    ProviderConfigProperty timeout = new ProviderConfigProperty();
    timeout.setType(ProviderConfigProperty.STRING_TYPE);
    timeout.setName(MagicLinkConstants.TIMEOUT);
    timeout.setLabel("Expiration time");
    timeout.setHelpText(
        "Magic link authenticator expiration time in minutes. Default expiration period 10 minutes.");
    timeout.setDefaultValue("10");

    return List.of(createUser, timeout);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
