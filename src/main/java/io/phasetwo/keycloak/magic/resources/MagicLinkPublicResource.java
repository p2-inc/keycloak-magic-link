package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.representation.MagicLinkContinuationRequest;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.SESSION_CONFIRMED;

@JBossLog
public class MagicLinkPublicResource extends AbstractAdminResource {

    public MagicLinkPublicResource(KeycloakSession session) {
        super(session);
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
