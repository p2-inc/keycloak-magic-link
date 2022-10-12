package io.phasetwo.keycloak.magic.auth;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.MagicLink;
import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderEvent;
import lombok.extern.jbosslog.JBossLog;

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class MagicLinkAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-magic-form";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkAuthenticator();
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
    return "Magic Link";
  }

  @Override
  public String getHelpText() {
    return "Sign in with a magic link that will be sent to your email.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty createUser = new ProviderConfigProperty();
    createUser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    createUser.setName(MagicLinkAuthenticator.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    createUser.setLabel("Force create user");
    createUser.setHelpText(
        "Creates a new user when an email is provided that does not match an existing user.");
    createUser.setDefaultValue(true);

    ProviderConfigProperty updateProfile = new ProviderConfigProperty();
    updateProfile.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    updateProfile.setName(MagicLinkAuthenticator.UPDATE_PROFILE_ACTION_CONFIG_PROPERTY);
    updateProfile.setLabel("Update profile on create");
    updateProfile.setHelpText("Add an UPDATE_PROFILE required action if the user was created.");
    updateProfile.setDefaultValue(false);

    return Arrays.asList(createUser, updateProfile);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
        (ProviderEvent ev) -> {
          if (ev instanceof RealmModel.RealmPostCreateEvent) {
            try {
              MagicLink.realmPostCreate((RealmModel.RealmPostCreateEvent) ev);
            } catch (Exception e) {
              log.warn("Error creating magic link auth flow.", e);
            }
          }
        });
  }

  @Override
  public void close() {}
}
