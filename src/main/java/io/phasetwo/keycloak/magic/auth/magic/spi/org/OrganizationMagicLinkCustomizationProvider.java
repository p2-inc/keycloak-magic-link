package io.phasetwo.keycloak.magic.auth.magic.spi.org;

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
 * Organization-scoped magic link customization.
 *
 * <p>Denies authentication when {@code ext-magic-org-require-membership=true} and the resolved
 * user does not carry the attribute {@code org.{orgId}=true}. In a real deployment this attribute
 * would be set (or derived) by the keycloak-orgs extension or a custom user-storage provider; for
 * a pure-Keycloak setup a mapper or script can set it at login time.
 *
 * <p>Email sending delegates to the standard {@code magic-link-email.ftl} template. Override
 * {@link #sendMagicLinkEmail} to use an organisation-specific template.
 */
@JBossLog
public final class OrganizationMagicLinkCustomizationProvider implements MagicLinkCustomizationProvider {

  private final KeycloakSession session;
  private final OrganizationMagicLinkCustomizationConfig orgConfig;

  OrganizationMagicLinkCustomizationProvider(
      KeycloakSession session, OrganizationMagicLinkCustomizationConfig orgConfig) {
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
    boolean isMember = user.getAttributeStream("org." + orgId)
        .anyMatch("true"::equalsIgnoreCase);
    if (!isMember) {
      log.debugf("User %s is not a member of org %s — denying magic link", user.getEmail(), orgId);
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
