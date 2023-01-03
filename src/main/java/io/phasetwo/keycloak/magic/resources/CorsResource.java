package io.phasetwo.keycloak.magic.resources;

import javax.ws.rs.*;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.Cors;
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
    return Cors.add(request, Response.ok()).auth().allowedMethods(METHODS).preflight().build();
  }

  public static void setupCors(KeycloakSession session, AdminAuth auth) {
    HttpRequest request = session.getContext().getContextObject(HttpRequest.class);
    HttpResponse response = session.getContext().getContextObject(HttpResponse.class);
    if (hasCors(response)) return;
    Cors.add(request)
        .allowedOrigins(auth.getToken())
        .allowedMethods(METHODS)
        .exposedHeaders("Location")
        .auth()
        .build(response);
  }

  public static boolean hasCors(HttpResponse response) {
    MultivaluedMap<String, Object> headers = response.getOutputHeaders();
    if (headers == null) return false;
    return (headers.get("Access-Control-Allow-Credentials") != null
        || headers.get("Access-Control-Allow-Origin") != null
        || headers.get("Access-Control-Expose-Headers") != null);
  }
}
