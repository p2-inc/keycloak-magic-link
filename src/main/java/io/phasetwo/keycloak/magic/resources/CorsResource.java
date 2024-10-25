package io.phasetwo.keycloak.magic.resources;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.resources.admin.AdminAuth;

@JBossLog
public class CorsResource {

  private final KeycloakSession session;
  private final HttpRequest request;

  public CorsResource(KeycloakSession session, HttpRequest request) {
    this.session = session;
    this.request = request;
  }

  public static final String[] METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
  };

  @OPTIONS
  @Path("{any:.*}")
  public Response preflight() {
    log.debug("CORS OPTIONS preflight request");
    return Cors.builder().auth().allowedMethods(METHODS).preflight().add(Response.ok());
  }

  public static void setupCors(KeycloakSession session, AdminAuth auth) {
    Cors.builder()
        .allowedOrigins(auth.getToken())
        .allowedMethods(METHODS)
        .exposedHeaders("Location")
        .auth()
        .add();
  }
}
