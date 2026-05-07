package io.phasetwo.keycloak.magic.auth.magic.spi;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.magic.MagicLinkConfig;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * Default {@link MagicLinkCustomizationProvider} that replicates the original magic link behavior:
 * all authenticated users are allowed and the standard {@code magic-link-email.ftl} template is used.
 */
public final class DefaultMagicLinkCustomizationProvider implements MagicLinkCustomizationProvider {

  @Override
  public boolean canAuthenticate(
      AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
    return true;
  }

  @Override
  public boolean sendMagicLinkEmail(
      KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
    return MagicLink.sendMagicLinkEmail(session, user, link);
  }

  @Override
  public void close() {}
}
