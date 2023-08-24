package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.TinyUrlHelper;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.representation.MagicLinkInfo;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
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
    ClientModel client =
        session.getContext().getRealm().getClientByClientId(TinyUrlConstants.ESD_UI);
    session.getContext().setClient(client);
    session.getContext().setRealm(realm);
    if (tinyUrl.isEmpty()) {
      return ErrorPage.error(
          session, null, Response.Status.BAD_REQUEST, Messages.EXPIRED_ACTION_TOKEN_NO_SESSION);
    } else if (tinyUrl.get().isDeleted()) {
      UserModel user = session.users().getUserByEmail(realm, tinyUrl.get().getEmail());
      if (user != null && user.isEnabled()) {
        MagicLinkActionToken token =
            MagicLink.createActionToken(
                user,
                tinyUrl.get().getClientId(),
                client.getRootUrl(),
                OptionalInt.empty(),
                null,
                null,
                null,
                false);

        MagicLinkInfo linkInfo = MagicLink.linkFromActionToken(session, realm, token);
        MagicLink.sendMagicLinkEmail(session, user, linkInfo);
        log.infof(
            "resent magic link email for expired tiny url to %s? Link? %s",
            user.getEmail(), linkInfo.getLink());
        return ErrorPage.error(
            session, null, Response.Status.CREATED, Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS);
      } else {
        return ErrorPage.error(
            session, null, Response.Status.BAD_REQUEST, Messages.EXPIRED_ACTION_TOKEN_NO_SESSION);
      }
    }

    String redirectUrl =
        TinyUrlHelper.getActionTokenUri(session.getContext().getUri().getBaseUri(), tinyUrl.get());

    // hard deleting the magic link after one use
    session.getProvider(TinyUrlService.class).hardDeleteTinyUrl(tinyUrl.get());

    log.debugf("Tiny Url Redirecting to %s", redirectUrl);
    return Response.temporaryRedirect(URI.create(redirectUrl)).build();
  }

  @POST
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{url_key}/validate")
  public Response validateMagicLinkCode(@PathParam("url_key") String urlKey) {
    Optional<TinyUrl> tinyUrl = session.getProvider(TinyUrlService.class).findByUrlKey(urlKey);
    Map<String, Boolean> jsonResponse = Map.of("isLoginCodeValid", tinyUrl.isPresent());
    if (tinyUrl.isPresent()) {
      return Response.ok().entity(jsonResponse).build();
    } else {
      return Response.status(Response.Status.NOT_FOUND).entity(jsonResponse).build();
    }
  }
}
