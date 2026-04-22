package io.phasetwo.keycloak.magic.auth.cloudflare;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class CloudflareTurnstileUsernamePasswordAuthenticatorFactory
    implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-auth-turnstile-username-password";

  @Override
  public Authenticator create(KeycloakSession session) {
    return new CloudflareTurnstileUsernamePasswordAuthenticator();
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
  public String getDisplayType() {
    return "Cloudflare Turnstile Username Password Form";
  }

  @Override
  public String getHelpText() {
    return "Validates username/password with Cloudflare Turnstile captcha.";
  }

  @Override
  public String getReferenceCategory() {
    return "password";
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
  public List<ProviderConfigProperty> getConfigProperties() {
    List<ProviderConfigProperty> props = new ArrayList<>(CloudflareTurnstile.configProperties);
    ProviderConfigProperty prop = new ProviderConfigProperty();
    prop.setName(CloudflareTurnstileUsernamePasswordAuthenticator.CF_VERIFY_EMAIL_ON_FAIL);
    prop.setLabel("Verify email on CAPTCHA failure");
    prop.setHelpText(
        "When enabled, marks the user's email as unverified and triggers email verification if"
            + " valid credentials are submitted but the Turnstile CAPTCHA check fails."
            + " Disabled by default.");
    prop.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    prop.setDefaultValue("false");
    props.add(prop);
    return props;
  }
}
