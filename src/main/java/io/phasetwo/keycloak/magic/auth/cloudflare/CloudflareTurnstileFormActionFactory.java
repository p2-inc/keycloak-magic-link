package io.phasetwo.keycloak.magic.auth.cloudflare;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(FormActionFactory.class)
public class CloudflareTurnstileFormActionFactory implements FormActionFactory {

  public static final String PROVIDER_ID = "ext-turnstile-form-action";

  @Override
  public String getDisplayType() {
    return "Cloudflare Turnstile validation";
  }

  @Override
  public String getReferenceCategory() {
    return "alterante-verification";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED
    };
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Cloudflare Turnstile CAPTCHA verification for REGISTRATION flows.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CloudflareTurnstile.configProperties;
  }

  @Override
  public FormAction create(KeycloakSession session) {
    return new CloudflareTurnstileFormAction();
  }

  @Override
  public void init(Config.Scope config) {
    // No initialization needed
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // No post-initialization needed
  }

  @Override
  public void close() {
    // No resources to close
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
