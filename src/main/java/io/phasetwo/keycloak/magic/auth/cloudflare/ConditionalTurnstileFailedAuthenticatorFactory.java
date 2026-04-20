package io.phasetwo.keycloak.magic.auth.cloudflare;

import com.google.auto.service.AutoService;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class ConditionalTurnstileFailedAuthenticatorFactory
    implements ConditionalAuthenticatorFactory {

  public static final String PROVIDER_ID = "conditional-turnstile-failed";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    ProviderConfigProperty negate = new ProviderConfigProperty();
    negate.setName(ConditionalTurnstileFailedAuthenticator.CONF_NEGATE);
    negate.setLabel("Negate");
    negate.setHelpText(
        "When enabled, the condition is inverted: the subflow executes when Turnstile did NOT fail.");
    negate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    negate.setDefaultValue("false");
    CONFIG_PROPERTIES = List.of(negate);
  }

  @Override
  public String getDisplayType() {
    return "Condition - Turnstile Failed";
  }

  @Override
  public String getReferenceCategory() {
    return "condition";
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
    return false;
  }

  @Override
  public String getHelpText() {
    return "Matches when the Cloudflare Turnstile CAPTCHA check failed during the current authentication session. Use inside a conditional subflow to enforce a 2FA step for suspected bots or automated submissions.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public ConditionalAuthenticator getSingleton() {
    return ConditionalTurnstileFailedAuthenticator.SINGLETON;
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
