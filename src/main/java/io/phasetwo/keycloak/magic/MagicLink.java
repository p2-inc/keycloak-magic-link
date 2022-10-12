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
import java.util.stream.Collectors;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.provider.ProviderFactory;
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

    // This is a workaround for situations where the realm you are using to call this (e.g. master)
    // is different than the one you are generating the action token for. Because the
    // SignatureProvider
    // assumes the value that is set in session.getContext().getRealm() has the keys it should use,
    // we
    // need to temporarily reset it
    RealmModel r = session.getContext().getRealm();
    log.infof("realm %s session.context.realm %s", realm.getName(), r.getName());
    // Because of the risk, throw an exception for master realm
    if (Config.getAdminRealm().equals(realm.getName())) {
      throw new IllegalStateException(
          String.format("Magic links not allowed for %s realm", Config.getAdminRealm()));
    }
    session.getContext().setRealm(realm);

    UriBuilder builder =
        actionTokenBuilder(
            uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo), token.getIssuedFor());

    // and then set it back
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

  public static final String MAGIC_LINK_AUTH_FLOW_ALIAS = "magic link";
  public static final String COOKIE_PROVIDER_ID =
      org.keycloak.authentication.authenticators.browser.CookieAuthenticatorFactory.PROVIDER_ID;
  public static final String IDP_REDIRECTOR_PROVIDER_ID =
      org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticatorFactory
          .PROVIDER_ID;
  public static final String MAGIC_LINK_PROVIDER_ID =
      io.phasetwo.keycloak.magic.auth.MagicLinkAuthenticatorFactory.PROVIDER_ID;

  public static void realmPostCreate(RealmModel.RealmPostCreateEvent event) {
    KeycloakSession session = event.getKeycloakSession();
    RealmModel realm = event.getCreatedRealm();
    AuthenticationFlowModel flow = realm.getFlowByAlias(MAGIC_LINK_AUTH_FLOW_ALIAS);
    if (flow != null) {
      log.infof("%s flow exists. Skipping.", MAGIC_LINK_AUTH_FLOW_ALIAS);
      return;
    }

    log.infof("creating built-in auth flow for %s", MAGIC_LINK_AUTH_FLOW_ALIAS);
    flow = new AuthenticationFlowModel();
    flow.setAlias(MAGIC_LINK_AUTH_FLOW_ALIAS);
    flow.setBuiltIn(true);
    flow.setProviderId("basic-flow");
    flow.setDescription("Simple magic link authentication flow.");
    flow.setTopLevel(true);
    flow = realm.addAuthenticationFlow(flow);

    // cookie
    addExecutionToFlow(
        session,
        realm,
        flow,
        COOKIE_PROVIDER_ID,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE);
    // kerberos?
    // identity provider redirector
    addExecutionToFlow(
        session,
        realm,
        flow,
        IDP_REDIRECTOR_PROVIDER_ID,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE);

    // forms
    AuthenticationFlowModel forms = new AuthenticationFlowModel();
    forms.setAlias(String.format("%s %s", MAGIC_LINK_AUTH_FLOW_ALIAS, "forms"));
    forms.setProviderId("basic-flow");
    forms.setDescription("Forms for simple magic link authentication flow.");
    forms.setTopLevel(false);
    forms = realm.addAuthenticationFlow(forms);

    AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
    execution.setParentFlow(flow.getId());
    execution.setFlowId(forms.getId());
    execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
    execution.setAuthenticatorFlow(true);
    execution.setPriority(getNextPriority(realm, flow));
    execution = realm.addAuthenticatorExecution(execution);

    addExecutionToFlow(
        session,
        realm,
        forms,
        MAGIC_LINK_PROVIDER_ID,
        AuthenticationExecutionModel.Requirement.REQUIRED);
  }

  private static int getNextPriority(RealmModel realm, AuthenticationFlowModel parentFlow) {
    List<AuthenticationExecutionModel> executions =
        realm.getAuthenticationExecutionsStream(parentFlow.getId()).collect(Collectors.toList());
    return executions.isEmpty() ? 0 : executions.get(executions.size() - 1).getPriority() + 1;
  }

  private static void addExecutionToFlow(
      KeycloakSession session,
      RealmModel realm,
      AuthenticationFlowModel flow,
      String providerId,
      AuthenticationExecutionModel.Requirement requirement) {
    List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutions(flow.getId());
    boolean hasExecution =
        executions.stream().filter(e -> providerId.equals(e.getAuthenticator())).count() > 0;

    if (!hasExecution) {
      log.infof("adding execution %s for auth flow for %s", providerId, flow.getAlias());
      ProviderFactory f =
          session.getKeycloakSessionFactory().getProviderFactory(Authenticator.class, providerId);
      AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
      execution.setParentFlow(flow.getId());
      execution.setRequirement(requirement);
      execution.setAuthenticatorFlow(false);
      execution.setAuthenticator(providerId);
      execution = realm.addAuthenticatorExecution(execution);
    }
  }
}
