package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.TinyUrlHelper;
import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.net.URI;
import java.util.Optional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

@JBossLog
public class TinyUrlResource extends AbstractAdminResource {
  public TinyUrlResource(KeycloakSession session) {
    super(session);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{url_key}")
  public Response getMagicLinkUrl(@PathParam("url_key") String urlKey) {
    Optional<TinyUrl> tinyUrl = session.getProvider(TinyUrlService.class).findByUrlKey(urlKey);

    if (tinyUrl.isEmpty()) {
      ClientModel client =
          session.getContext().getRealm().getClientByClientId(TinyUrlConstants.ESD_UI);
      session.getContext().setClient(client);
      return ErrorPage.error(
          session, null, Response.Status.BAD_REQUEST, Messages.EXPIRED_ACTION_TOKEN_NO_SESSION);
    }

    String redirectUrl =
        TinyUrlHelper.actionTokenBuilder(session.getContext().getUri().getBaseUri(), tinyUrl.get())
            .build()
            .toString();
    log.debugf("Tiny Url Redirecting to %s", redirectUrl);
    return Response.temporaryRedirect(URI.create(redirectUrl)).build();
  }
}
