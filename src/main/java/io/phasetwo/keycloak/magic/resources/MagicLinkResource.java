package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import io.phasetwo.keycloak.magic.representation.MagicLinkInfo;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import jakarta.ws.rs.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.OptionalInt;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

@JBossLog
public class MagicLinkResource extends AbstractAdminResource {

  public MagicLinkResource(KeycloakSession session) {
    super(session);
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

    session.getContext().setClient(client);
    session.getContext().setRealm(realm);
    String emailOrUsername = rep.getEmail();
    boolean forceCreate = rep.isForceCreate();
    boolean updateProfile = rep.isUpdateProfile();
    boolean updatePassword = rep.isUpdatePassword();
    boolean sendEmail = rep.isSendEmail();
    boolean sendEmailWithCode = rep.isSendEmailWithCode();

    if (rep.getUsername() != null) {
      emailOrUsername = rep.getUsername();
      forceCreate = false;
      sendEmail = false;
    }

    UserModel user =
        MagicLink.getOrCreate(
            session,
            realm,
            emailOrUsername,
            forceCreate,
            updateProfile,
            updatePassword,
            MagicLink.registerEvent(event));
    if (user == null)
      throw new NotFoundException(
          String.format(
              "User with email/username %s not found, and forceCreate is off.", emailOrUsername));

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            rep.getClientId(),
            rep.getRedirectUri(),
            OptionalInt.of(rep.getExpirationSeconds()),
            rep.getScope(),
            rep.getNonce(),
            rep.getState(),
            rep.getRememberMe(),
            rep.getActionTokenPersistent());
    MagicLinkInfo linkInfo = MagicLink.linkFromActionToken(session, realm, token);
    linkInfo.setShouldSendCode(sendEmailWithCode);
    boolean sent = false;
    if (sendEmail) {
      sent = MagicLink.sendMagicLinkEmail(session, user, linkInfo);
    }

    MagicLinkResponse resp = new MagicLinkResponse();
    resp.setUserId(user.getId());
    resp.setLink(linkInfo.getLink());
    resp.setSent(sent);

    return resp;
  }
}
