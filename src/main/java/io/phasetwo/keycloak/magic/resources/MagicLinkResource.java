package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import java.util.OptionalInt;

import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;

@JBossLog
public class MagicLinkResource extends AbstractAdminResource {

  public MagicLinkResource(KeycloakSession session) {
    super(session);
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public MagicLinkResponse createMagicLink(final MagicLinkRequest request) {
    if (!permissions.users().canManage()) throw new ForbiddenException("magic link requires manage-users");

    ClientModel client = session.clients().getClientByClientId(realm, request.getClientId());
    if (client == null) throw new NotFoundException(String.format("Client with ID %s not found.", request.getClientId()));
    if (!MagicLink.validateRedirectUri(session, request.getRedirectUri(), client))
      throw new BadRequestException(String.format("redirectUri %s disallowed by client.", request.getRedirectUri()));

    String emailOrUsername = request.getEmail();
    boolean forceCreate = request.isForceCreate();
    boolean updateProfile = request.isUpdateProfile();
    boolean updatePassword = request.isUpdatePassword();
    boolean sendEmail = request.isSendEmail();

    if (request.getUsername() != null) {
      emailOrUsername = request.getUsername();
      forceCreate = false;
      sendEmail = false;
    }

    UserModel user = MagicLink.getOrCreate(
        session,
        realm,
        emailOrUsername,
        forceCreate,
        updateProfile,
        updatePassword,
        MagicLink.registerEvent(event, MAGIC_LINK)
    );
    if (user == null) throw new NotFoundException(String.format("User with email/username %s not found, and forceCreate is off.", emailOrUsername));

    MagicLinkActionToken token = MagicLink.createActionToken(
        user,
        request.getClientId(),
        request.getRedirectUri(),
        OptionalInt.of(request.getExpirationSeconds()),
        request.getScope(),
        request.getNonce(),
        request.getState(),
        request.getCodeChallenge(),
        request.getCodeChallengeMethod(),
        request.getRememberMe(),
        request.getActionTokenPersistent(),
        request.getOrg(),
        request.getModule(),
        request.getLevel(),
        request.getCompanyId(),
        request.getExtraPermissions()
    );
    String link = MagicLink.linkFromActionToken(session, realm, token);
    boolean sent = false;
    if (sendEmail) {
      sent = MagicLink.sendMagicLinkEmail(session, user, link);
      log.debugf("sent email to %s? %b. Link? %s", request.getEmail(), sent, link);
    }

    MagicLinkResponse response = new MagicLinkResponse();
    response.setUserId(user.getId());
    response.setLink(link);
    response.setSent(sent);
    return response;
  }
}
