package io.phasetwo.keycloak.magic.auth.magic.spi;

import io.phasetwo.keycloak.magic.auth.magic.MagicLinkConfig;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

/**
 * Extension point for customizing the standard magic link authentication flow.
 *
 * <p>Register a custom implementation via {@link MagicLinkCustomizationProviderFactory} and wire
 * it into a concrete {@link io.phasetwo.keycloak.magic.auth.magic.AbstractMagicLinkAuthenticatorFactory}
 * subclass to change user-validation or email-sending behavior without forking the authenticator.
 */
public interface MagicLinkCustomizationProvider extends Provider {

  /**
   * Called after the user has been resolved but before the magic link token is created.
   *
   * <p>Return {@code false} to abort the flow (e.g. user is not a member of the required
   * organization). The implementation is responsible for setting an appropriate challenge on the
   * {@code context} before returning {@code false}.
   *
   * @param context the active authentication flow context
   * @param user the resolved user (never {@code null})
   * @param config the typed authenticator config
   * @return {@code true} to continue, {@code false} to abort
   */
  boolean canAuthenticate(AuthenticationFlowContext context, UserModel user, MagicLinkConfig config);

  /**
   * Send the magic link to the user.
   *
   * @param session the active Keycloak session
   * @param user the recipient
   * @param link the fully qualified magic link URL
   * @param config the typed authenticator config
   * @return {@code true} if the email was dispatched successfully
   */
  boolean sendMagicLinkEmail(
      KeycloakSession session, UserModel user, String link, MagicLinkConfig config);
}
