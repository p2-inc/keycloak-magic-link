package io.phasetwo.keycloak.magic.resources;

import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.SESSION_CONFIRMED;

import io.phasetwo.keycloak.magic.representation.MagicLinkContinuationRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

@JBossLog
public class MagicLinkPublicResource {

  private final KeycloakSession session;

  public MagicLinkPublicResource(KeycloakSession session) {
    this.session = session;
  }

  @POST
  @Path("/magic-link-continuation/verify")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public boolean verifyMagicLink(final MagicLinkContinuationRequest rep) {
    SingleUseObjectProvider singleUseObjects = session.singleUseObjects();
    var sessionConfirmationMap = singleUseObjects.get(rep.getSessionId());

    if (sessionConfirmationMap != null) {
      return Boolean.parseBoolean(sessionConfirmationMap.get(SESSION_CONFIRMED));
    }

    return false;
  }
}
