package io.phasetwo.keycloak.magic.auth;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import lombok.extern.jbosslog.JBossLog;
import java.util.List;
import com.google.auto.service.AutoService;

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class CloudflareTurnstileAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-auth-cloudflare-turnstile";

  @Override
  public Authenticator create(KeycloakSession session) {
    return new CloudflareTurnstileAuthenticator();
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

  @Override
  public String getHelpText() {
    return "Shows Cloudflare Turnstile button.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CloudflareTurnstile.configProperties;
  }

  @Override
  public String getDisplayType() {
    return "Cloudflare Turnstile validation";
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
    return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};
  }
  
  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }
}
