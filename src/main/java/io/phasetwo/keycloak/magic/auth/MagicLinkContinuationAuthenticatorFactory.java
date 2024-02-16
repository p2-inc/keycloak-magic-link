package io.phasetwo.keycloak.magic.auth;

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
  public String getDisplayType() {
    return "Magic Link continuation";
  }

  @Override
  public String getHelpText() {
    return "Sign in with a magic link that will be sent to your email.";
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
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty timeout = new ProviderConfigProperty();
    timeout.setType(ProviderConfigProperty.STRING_TYPE);
    timeout.setName(MagicLinkConstants.TIMEOUT);
    timeout.setLabel("Expiration time");
    timeout.setHelpText(
        "Magic link authenticator expiration time in minutes. Default expiration period 10 minutes.");
    timeout.setDefaultValue("10");

    return List.of(timeout);
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkContinuationAuthenticator();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
