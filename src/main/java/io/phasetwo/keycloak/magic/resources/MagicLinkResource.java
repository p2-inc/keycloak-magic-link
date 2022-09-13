package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import java.util.OptionalInt;
import javax.validation.constraints.*;
import javax.ws.rs.*;
import javax.ws.rs.Consumes;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class MagicLinkResource extends AbstractAdminResource {

  public MagicLinkResource(RealmModel realm) {
    super(realm);
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public MagicLinkResponse createMagicLink(final MagicLinkRequest rep) {
    if (!permissions.users().canManage())
      throw new ForbiddenException("magic link requires manage-users");

    ClientModel client = session.clients().getClientByClientId(realm, rep.getClientId());
    if (client == null)
      throw new NotFoundException(String.format("Client with ID %s not found.", rep.getClientId()));
    if (!MagicLink.validateRedirectUri(session, rep.getRedirectUri(), client))
      throw new BadRequestException(
          String.format("redirectUri %s disallowed by client.", rep.getRedirectUri()));

    String emailOrUsername = rep.getEmail();
    boolean forceCreate = rep.isForceCreate();
    boolean updateProfile = rep.isUpdateProfile();
    boolean sendEmail = rep.isSendEmail();

    if (rep.getUsername() != null) {
      emailOrUsername = rep.getUsername();
      forceCreate = false;
      updateProfile = false;
      sendEmail = false;
    }

    UserModel user =
        MagicLink.getOrCreate(
            session,
            realm,
            emailOrUsername,
            forceCreate,
            updateProfile,
            MagicLink.registerEvent(event));
    if (user == null)
      throw new NotFoundException(
          String.format("User with email %s not found, and forceCreate is off.", rep.getEmail()));

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            rep.getClientId(),
            rep.getRedirectUri(),
            OptionalInt.of(rep.getExpirationSeconds()));
    String link = MagicLink.linkFromActionToken(session, realm, token);
    boolean sent = false;
    if (sendEmail) {
      sent = MagicLink.sendMagicLinkEmail(session, user, link);
      log.infof("sent email to %s? %b. Link? %s", rep.getEmail(), sent, link);
    }

    MagicLinkResponse resp = new MagicLinkResponse();
    resp.setUserId(user.getId());
    resp.setLink(link);
    resp.setSent(sent);

    return resp;
  }
}
