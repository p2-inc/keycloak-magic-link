package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.MagicLink;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderEvent;

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
    createUser.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
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

    ProviderConfigProperty updatePassword = new ProviderConfigProperty();
    updatePassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    updatePassword.setName(MagicLinkAuthenticator.UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY);
    updatePassword.setLabel("Update password on create");
    updatePassword.setHelpText("Add an UPDATE_PASSWORD required action if the user was created.");
    updatePassword.setDefaultValue(false);

    ProviderConfigProperty actionTokenPersistent = new ProviderConfigProperty();
    actionTokenPersistent.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    actionTokenPersistent.setName(MagicLinkAuthenticator.ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY);
    actionTokenPersistent.setLabel("Allow magic link to be reusable");
    actionTokenPersistent.setHelpText(
        "Toggle whether magic link should be persistent until expired.");
    actionTokenPersistent.setDefaultValue(true);

    ProviderConfigProperty actionTokenLifeSpan = new ProviderConfigProperty();
    actionTokenLifeSpan.setType(ProviderConfigProperty.STRING_TYPE);
    actionTokenLifeSpan.setName(MagicLinkAuthenticator.ACTION_TOKEN_LIFE_SPAN);
    actionTokenLifeSpan.setLabel("Token lifespan");
    actionTokenLifeSpan.setHelpText(
        "Amount of time the magic link is valid, in seconds. If this value is not specific, it will use the default 86400s (1 day)");

    return List.of(
        createUser, updateProfile, updatePassword, actionTokenPersistent, actionTokenLifeSpan);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
        (ProviderEvent ev) -> {
          if (ev instanceof RealmModel.RealmPostCreateEvent) {
            MagicLink.realmPostCreate(factory, (RealmModel.RealmPostCreateEvent) ev);
          }
        });
  }

  @Override
  public void close() {}
}
