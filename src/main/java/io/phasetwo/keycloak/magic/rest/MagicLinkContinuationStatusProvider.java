package io.phasetwo.keycloak.magic.rest;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Provides REST endpoint to poll magic link continuation status
 *
 * <p>This endpoint is used during the authentication flow and must be accessible without
 * authentication.
 */
@JBossLog
@Path("")
public class MagicLinkContinuationStatusProvider implements RealmResourceProvider {
  public static final String AUTH_NOTE_STATE = "MLC_STATE";
  public static final String STATE_PENDING = "pending";
  public static final String STATE_CONFIRMED = "confirmed";
  public static final String STATE_EXPIRED = "expired";

  private final KeycloakSession session;

  public MagicLinkContinuationStatusProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    // Return this provider directly - no authentication required
    // Security is provided by the authentication session cookie
    return this;
  }

  @Override
  public void close() {}

  @GET
  @Path("{sessionId}/{tabId}/status")
  @Produces(MediaType.APPLICATION_JSON)
  public Response status(
      @PathParam("sessionId") String sessionId, @PathParam("tabId") String tabId) {
    log.debugf("[MLC] Polling status for sessionId: %s, tabId: %s", sessionId, tabId);
    
    // This endpoint must be accessible during the authentication flow
    // We use sessionId from URL because the magic link is clicked from a different device
    RealmModel realm = session.getContext().getRealm();
    AuthenticationSessionModel authSession = findAuthSessionByIds(realm, sessionId, tabId);

    if (authSession == null) {
      log.debugf("[MLC] Auth session not found (likely consumed), returning 404 for tabId: %s", tabId);
      return Response.status(Response.Status.NOT_FOUND)
          .entity(Map.of("error", "Session not found or already consumed"))
          .build();
    }

    String note = authSession.getAuthNote(AUTH_NOTE_STATE);
    String sessionConfirmed = authSession.getAuthNote("SESSION_CONFIRMED");
    String state = (note == null) ? STATE_PENDING : note;

    long now = Instant.now().getEpochSecond();
    String expStr = authSession.getClientNote("auth_session_exp");
    long exp = (expStr != null) ? parseLongSafe(expStr, now) : now;
    long expiresIn = Math.max(0, exp - now);

    log.debugf(
        "[MLC] Auth session found - tabId: %s, MLC_STATE: %s, SESSION_CONFIRMED: %s, state: %s, expiresIn: %d",
        tabId, note, sessionConfirmed, state, expiresIn);

    Map<String, Object> response = Map.of("state", state, "expires_in", expiresIn);
    log.debugf("[MLC] Returning response: %s", response);
    return Response.ok(response).build();
  }

  private AuthenticationSessionModel findAuthSessionByIds(
      RealmModel realm, String sessionId, String tabId) {
    // Find the auth session by sessionId (not by cookie, since magic link can be clicked from
    // different device)
    RootAuthenticationSessionModel root =
        session.authenticationSessions().getRootAuthenticationSession(realm, sessionId);
    if (root == null) {
      log.warnf("[MLC] No root authentication session found for sessionId: %s", sessionId);
      return null;
    }

    log.debugf(
        "[MLC] Found root session, searching for tabId %s in %d auth sessions",
        tabId, root.getAuthenticationSessions().size());

    for (String key : root.getAuthenticationSessions().keySet()) {
      AuthenticationSessionModel s = root.getAuthenticationSessions().get(key);
      log.debugf("[MLC] Checking auth session with tabId: %s", s.getTabId());
      if (tabId.equals(s.getTabId())) {
        log.debugf("[MLC] Found matching auth session for tabId: %s", tabId);
        return s;
      }
    }
    log.warnf("[MLC] No auth session found with tabId: %s in sessionId: %s", tabId, sessionId);
    return null;
  }

  private long parseLongSafe(String s, long fallback) {
    try {
      return Long.parseLong(s);
    } catch (Exception e) {
      return fallback;
    }
  }
}

