package io.phasetwo.keycloak.magic;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.function.Consumer;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;

/** common utilities for Magic Link authentication, used by the authenticator and resource */
@JBossLog
public class MagicLink {

  public static Consumer<UserModel> registerEvent(final EventBuilder event) {
    return new Consumer<UserModel>() {
      @Override
      public void accept(UserModel user) {
        event
            .event(EventType.REGISTER)
            .detail(Details.REGISTER_METHOD, "magic")
            .detail(Details.USERNAME, user.getUsername())
            .detail(Details.EMAIL, user.getEmail())
            .user(user)
            .success();
      }
    };
  }

  public static UserModel getOrCreate(KeycloakSession session, String email, boolean forceCreate) {
    return getOrCreate(session, email, forceCreate, null);
  }

  public static UserModel getOrCreate(
      KeycloakSession session, String email, boolean forceCreate, Consumer<UserModel> onNew) {
    UserModel user =
        KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), email);
    // UserModel user = session.users().getUserByEmail(email, session.getContext().getRealm());
    if (user == null && forceCreate) {
      user = session.users().addUser(session.getContext().getRealm(), email);
      user.setEnabled(true);
      user.setEmail(email);
      user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
      if (onNew != null) {
        onNew.accept(user);
      }
    }
    return user;
  }

  public static MagicLinkActionToken createActionToken(
      UserModel user, String clientId, String redirectUri, OptionalInt validity) {
    // build the action token
    int validityInSecs = validity.orElse(60 * 60 * 24); // 1 day
    int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
    MagicLinkActionToken token =
        new MagicLinkActionToken(user.getId(), absoluteExpirationInSecs, clientId, redirectUri);
    return token;
  }

  public static String linkFromActionToken(KeycloakSession session, MagicLinkActionToken token) {
    UriInfo uriInfo = session.getContext().getUri();
    RealmModel realm = session.getContext().getRealm();
    UriBuilder builder =
        actionTokenBuilder(
            uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo), token.getIssuedFor());
    return builder.build(realm.getName()).toString();
  }

  public static boolean validateRedirectUri(
      KeycloakSession session, String redirectUri, ClientModel client) {
    String redirect = RedirectUtils.verifyRedirectUri(session, redirectUri, client);
    log.infof("Redirect after verify %s -> %s", redirectUri, redirect);
    return (redirectUri.equals(redirect));
  }

  private static UriBuilder actionTokenBuilder(URI baseUri, String tokenString, String clientId) {
    log.infof("baseUri: %s, tokenString: %s, clientId: %s", baseUri, tokenString, clientId);
    return Urls.realmBase(baseUri)
        .path(RealmsResource.class, "getLoginActionsService")
        .path(LoginActionsService.class, "executeActionToken")
        .queryParam(Constants.KEY, tokenString)
        .queryParam(Constants.CLIENT_ID, clientId);
  }

  public static boolean sendMagicLinkEmail(KeycloakSession session, UserModel user, String link) {
    RealmModel realm = session.getContext().getRealm();
    try {
      EmailTemplateProvider emailTemplateProvider =
          session.getProvider(EmailTemplateProvider.class);
      List<Object> subjAttr = ImmutableList.of();
      Map<String, Object> bodyAttr = Maps.newHashMap();
      bodyAttr.put("realmName", realm.getName());
      bodyAttr.put("magicLink", link);
      emailTemplateProvider
          .setRealm(realm)
          .setUser(user)
          .setAttribute("realmName", realm.getName())
          .send("magicLinkSubject", subjAttr, "magic-link-email.ftl", bodyAttr);
      return true;
    } catch (EmailException e) {
      log.error("Failed to send welcome mail", e);
    }
    return false;
  }
}
