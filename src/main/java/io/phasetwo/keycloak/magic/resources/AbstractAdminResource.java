package io.phasetwo.keycloak.magic.resources;

import javax.validation.constraints.*;
import javax.ws.rs.*;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

@JBossLog
public abstract class AbstractAdminResource {

  @Context protected ClientConnection clientConnection;
  @Context protected HttpHeaders headers;
  @Context protected KeycloakSession session;
  protected AdminAuth auth;
  protected AdminEventBuilder adminEvent;
  protected AdminPermissionEvaluator permissions;
  protected EventBuilder event;
  protected final RealmModel realm;

  protected AbstractAdminResource(RealmModel realm) {
    this.realm = realm;
  }

  public void setup() {
    setupAuth();
    setupEvents();
    setupPermissions();
    setupCors();
    init();
  }

  void init() {
    // override if your extending class needs additional setup;
  }

  private void setupCors() {
    CorsResource.setupCors(session, auth);
  }

  private void setupAuth() {
    auth = authenticateRealmAdminRequest(headers);
  }

  private void setupEvents() {
    adminEvent =
        new AdminEventBuilder(this.realm, auth, session, session.getContext().getConnection())
            .realm(realm);
    event =
        new EventBuilder​(this.realm, session, clientConnection).realm(realm);
  }

  private void setupPermissions() {
    permissions = AdminPermissions.evaluator(session, realm, auth);
  }

  private AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
    String tokenString = AppAuthManager.extractAuthorizationHeaderToken(headers);
    if (tokenString == null) throw new NotAuthorizedException("Bearer");
    AccessToken token;
    try {
      JWSInput input = new JWSInput(tokenString);
      token = input.readJsonContent(AccessToken.class);
    } catch (JWSInputException e) {
      throw new NotAuthorizedException("Bearer token format error");
    }
    String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
    RealmManager realmManager = new RealmManager(session);
    RealmModel realm = realmManager.getRealmByName(realmName);
    if (realm == null) {
      throw new NotAuthorizedException("Unknown realm in token");
    }
    session.getContext().setRealm(realm);

    AuthenticationManager.AuthResult authResult =
        new AppAuthManager.BearerTokenAuthenticator(session)
            .setRealm(realm)
            .setConnection(clientConnection)
            .setHeaders(headers)
            .authenticate();

    if (authResult == null) {
      log.debug("Token not valid");
      throw new NotAuthorizedException("Bearer");
    }

    ClientModel client = realm.getClientByClientId(token.getIssuedFor());
    if (client == null) {
      throw new NotFoundException("Could not find client for authorization");
    }

    return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
  }
}
