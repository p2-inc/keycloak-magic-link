package io.phasetwo.keycloak.magic.auth.magic;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.magic.spi.DefaultMagicLinkCustomizationProviderFactory;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.provider.ProviderEvent;

/**
 * Default magic link authenticator factory (provider ID: {@code ext-magic-form}).
 *
 * <p>Uses {@link DefaultMagicLinkCustomizationProviderFactory}: all users are allowed and the
 * standard {@code magic-link-email.ftl} template is used. This is a drop-in replacement for the
 * original factory.
 *
 * <p>To apply custom business logic (e.g. org membership checks), create a subclass of
 * {@link AbstractMagicLinkAuthenticatorFactory} with a different provider ID and pass a custom
 * {@link io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProviderFactory}.
 */
@JBossLog
@AutoService(AuthenticatorFactory.class)
public final class MagicLinkAuthenticatorFactory extends AbstractMagicLinkAuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-magic-form";

  /**
   * Provider option. When {@code false}, realms created afterwards do not get the built-in {@value
   * MagicLink#MAGIC_LINK_AUTH_FLOW_ALIAS} flow. Defaults to {@code true}.
   */
  public static final String CREATE_DEFAULT_FLOW_OPTION = "create-default-flow";

  private boolean createDefaultFlow = true;

  public MagicLinkAuthenticatorFactory() {
    super(new DefaultMagicLinkCustomizationProviderFactory());
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Magic Link";
  }

  @Override
  public String getHelpText() {
    return "Sign in with a magic link that will be sent to your email.";
  }

  /**
   * Reads {@value #CREATE_DEFAULT_FLOW_OPTION}, set with {@code
   * --spi-authenticator--ext-magic-form--create-default-flow=false}.
   */
  @Override
  public void init(Config.Scope config) {
    createDefaultFlow = config.getBoolean(CREATE_DEFAULT_FLOW_OPTION, true);
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name(CREATE_DEFAULT_FLOW_OPTION)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText(
            "Create the built-in \""
                + MagicLink.MAGIC_LINK_AUTH_FLOW_ALIAS
                + "\" authentication flow in every new realm.")
        .defaultValue(true)
        .add()
        .build();
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    if (!createDefaultFlow) {
      log.infof(
          "%s=false: new realms will not get the \"%s\" flow",
          CREATE_DEFAULT_FLOW_OPTION, MagicLink.MAGIC_LINK_AUTH_FLOW_ALIAS);
      return;
    }
    factory.register(
        (ProviderEvent ev) -> {
          if (ev instanceof RealmModel.RealmPostCreateEvent) {
            MagicLink.realmPostCreate(factory, (RealmModel.RealmPostCreateEvent) ev);
          }
        });
  }
}
