package io.phasetwo.keycloak.magic.auth;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for {@link MagicLinkBFAuthenticator}.
 *
 * <p>Configure a default {@code loa.level} in the browser flow if you want the magic-link
 * authenticator to set a LOA even when the API caller does not provide one. The API's {@code loa}
 * field always takes precedence over this setting when present.
 */
@AutoService(AuthenticatorFactory.class)
public class MagicLinkBFAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-magic-link-browser-flow";

  private static final MagicLinkBFAuthenticator SINGLETON = new MagicLinkBFAuthenticator();

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
    return "Magic Link (v2) Verifier";
  }

  @Override
  public String getHelpText() {
    return "Verifies a Magic Link (v2) if a Magic Link UUID is provided via login_hint.";
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
    return new AuthenticationExecutionModel.Requirement[]{
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
