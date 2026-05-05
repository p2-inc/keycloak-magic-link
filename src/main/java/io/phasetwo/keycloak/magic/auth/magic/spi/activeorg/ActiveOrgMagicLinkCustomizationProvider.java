package io.phasetwo.keycloak.magic.auth.magic.spi.activeorg;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.magic.MagicLinkConfig;
import io.phasetwo.keycloak.magic.auth.magic.spi.MagicLinkCustomizationProvider;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * Active-org–scoped magic link customization.
 *
 * <p>Denies authentication when {@code ext-magic-org-require-membership=true} and the resolved
 * user does not carry the attribute {@code org.ro.active} matching the configured org ID.
 */
@JBossLog
public final class ActiveOrgMagicLinkCustomizationProvider implements MagicLinkCustomizationProvider {

  private final KeycloakSession session;
  private final ActiveOrgMagicLinkCustomizationConfig orgConfig;

  ActiveOrgMagicLinkCustomizationProvider(
      KeycloakSession session, ActiveOrgMagicLinkCustomizationConfig orgConfig) {
    this.session = session;
    this.orgConfig = orgConfig;
  }

  @Override
  public boolean canAuthenticate(
      AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
    if (!orgConfig.isRequireMembership()) {
      return true;
    }
    String orgId = orgConfig.getOrganizationId();
    if (orgId == null || orgId.isEmpty()) {
      return true;
    }
    boolean isMember = user.getAttributeStream("org.ro.active")
        .anyMatch(org -> org.equalsIgnoreCase(orgId));
    if (!isMember) {
      log.debugf("User %s active organization is not %s — denying magic link", user.getEmail(), orgId);
      Response deny = context.form()
          .setError("magicLinkOrgDenied")
          .createErrorPage(Response.Status.FORBIDDEN);
      context.failure(AuthenticationFlowError.ACCESS_DENIED, deny);
    }
    return isMember;
  }

  @Override
  public boolean sendMagicLinkEmail(
      KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
    return MagicLink.sendMagicLinkEmail(session, user, link);
  }

  @Override
  public void close() {}
}
