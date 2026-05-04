package io.phasetwo.keycloak.magic.auth.magic;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.magic.spi.DefaultMagicLinkCustomizationProviderFactory;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
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

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
        (ProviderEvent ev) -> {
          if (ev instanceof RealmModel.RealmPostCreateEvent) {
            MagicLink.realmPostCreate(factory, (RealmModel.RealmPostCreateEvent) ev);
          }
        });
  }
}
