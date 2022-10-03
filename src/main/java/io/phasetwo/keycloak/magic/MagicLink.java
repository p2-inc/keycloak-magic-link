package io.phasetwo.keycloak.magic;

import com.google.common.base.Strings;
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
import org.keycloak.Config;
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

  public static UserModel getOrCreate(
      KeycloakSession session,
      RealmModel realm,
      String email,
      boolean forceCreate,
      boolean updateProfile) {
    return getOrCreate(session, realm, email, forceCreate, updateProfile, null);
  }

  public static UserModel getOrCreate(
      KeycloakSession session,
      RealmModel realm,
      String email,
      boolean forceCreate,
      boolean updateProfile,
      Consumer<UserModel> onNew) {
    UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, email);
    if (user == null && forceCreate) {
      user = session.users().addUser(realm, email);
      user.setEnabled(true);
      user.setEmail(email);
      if (updateProfile) user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
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

  public static String linkFromActionToken(
      KeycloakSession session, RealmModel realm, MagicLinkActionToken token) {
    UriInfo uriInfo = session.getContext().getUri();

    //This is a workaround for situations where the realm you are using to call this (e.g. master)
    //is different than the one you are generating the action token for. Because the SignatureProvider
    //assumes the value that is set in session.getContext().getRealm() has the keys it should use, we
    //need to temporarily reset it
    RealmModel r = session.getContext().getRealm();
    log.infof("realm %s session.context.realm %s", realm.getName(), r.getName());
    //Because of the risk, throw an exception for master realm
    if (Config.getAdminRealm().equals(realm.getName())) {
      throw new IllegalStateException(String.format("Magic links not allowed for %s realm", Config.getAdminRealm()));
    }
    session.getContext().setRealm(realm);
    
    UriBuilder builder =
        actionTokenBuilder(
            uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo), token.getIssuedFor());

    //and then set it back
    session.getContext().setRealm(r);
    return builder.build(realm.getName()).toString();
  }

  public static boolean validateRedirectUri(
      KeycloakSession session, String redirectUri, ClientModel client) {
    String redirect = RedirectUtils.verifyRedirectUri(session, redirectUri, client);
    log.debugf("Redirect after verify %s -> %s", redirectUri, redirect);
    return (redirectUri.equals(redirect));
  }

  private static UriBuilder actionTokenBuilder(URI baseUri, String tokenString, String clientId) {
    log.debugf("baseUri: %s, tokenString: %s, clientId: %s", baseUri, tokenString, clientId);
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
      String realmName =
          Strings.isNullOrEmpty(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();
      List<Object> subjAttr = ImmutableList.of(realmName);
      Map<String, Object> bodyAttr = Maps.newHashMap();
      bodyAttr.put("realmName", realmName);
      bodyAttr.put("magicLink", link);
      emailTemplateProvider
          .setRealm(realm)
          .setUser(user)
          .setAttribute("realmName", realmName)
          .send("magicLinkSubject", subjAttr, "magic-link-email.ftl", bodyAttr);
      return true;
    } catch (EmailException e) {
      log.error("Failed to send welcome mail", e);
    }
    return false;
  }
}
