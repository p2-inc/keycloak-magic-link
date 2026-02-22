package io.phasetwo.keycloak.magic.auth.token;

import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.authentication.authenticators.util.LoAUtil;
import org.keycloak.events.*;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Handles the magic link action token by logging the user in and forwarding to the redirect uri.
 */
public class MagicLinkActionTokenHandler extends AbstractActionTokenHandler<MagicLinkActionToken> {

  private static final Logger log = Logger.getLogger(MagicLinkActionTokenHandler.class);

  public static final String LOGIN_METHOD = "login_method";

  public MagicLinkActionTokenHandler() {
    super(
        MagicLinkActionToken.TOKEN_TYPE,
        MagicLinkActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  /*
  @Override
  public Predicate<? super MagicLinkActionToken>[] getVerifiers(
      ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return TokenUtils.predicates(
        TokenUtils.checkThat(
            t ->
                Objects.equals(
                    t.getEmail(),
                    tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
            Errors.INVALID_EMAIL,
            getDefaultErrorMessage()));
  }
  */

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
  }

  @Override
  public boolean canUseTokenRepeatedly(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return token
        .getActionTokenPersistent(); // Invalidate action token after one use if configured to do so
  }

  @Override
  public Response handleToken(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    log.debugf("handleToken for iss:%s, user:%s", token.getIssuedFor(), token.getUserId());
    UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();

    final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    final ClientModel client = authSession.getClient();
    final String redirectUri =
        token.getRedirectUri() != null
            ? token.getRedirectUri()
            : ResolveRelative.resolveRelativeUri(
                tokenContext.getSession(), client.getRootUrl(), client.getBaseUrl());
    log.debugf("Using redirect_uri %s", redirectUri);

    String redirect =
        RedirectUtils.verifyRedirectUri(
            tokenContext.getSession(), redirectUri, authSession.getClient());
    if (redirect != null) {
      authSession.setAuthNote(
          AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
      authSession.setRedirectUri(redirect);
      authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
      if (token.getState() != null) {
        authSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, token.getState());
      }
      if (token.getNonce() != null) {
        authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
        authSession.setUserSessionNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
      }

      if (token.getCodeChallenge() != null) {
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, token.getCodeChallenge());
      }

      if (token.getCodeChallengeMethod() != null) {
        authSession.setClientNote(
            OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, token.getCodeChallengeMethod());
      }
    }

    if (token.getScope() != null) {
      authSession.setClientNote(OAuth2Constants.SCOPE, token.getScope());
      AuthenticationManager.setClientScopesInSession(tokenContext.getSession(), authSession);
    }

    if (token.getRememberMe() != null && token.getRememberMe()) {
      authSession.setAuthNote(Details.REMEMBER_ME, "true");
      tokenContext.getEvent().detail(Details.REMEMBER_ME, "true");
    } else {
      authSession.removeAuthNote(Details.REMEMBER_ME);
    }

    if (OIDCResponseMode.FRAGMENT.value().equals(token.getResponseMode())) {
      authSession.setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, OIDCResponseMode.FRAGMENT.value());
    }

    // Default to switching the email verified toggle to true since they clicked on this link in an
    // email.
    // Although, since a magic link can be created by API, we should revisit whether this should be
    // the
    // default.
    user.setEmailVerified(true);

    // Create a user session note to indicate that a magic link was used for login.
    authSession.setUserSessionNote(LOGIN_METHOD, MagicLinkActionTokenHandlerFactory.PROVIDER_ID);

    // Set AMR + LOA via the standard Keycloak mechanism.
    // The ActionToken flow bypasses normal authenticator execution, so authenticators-completed
    // is never populated and ConditionalLoaAuthenticator.onTopFlowSuccess() never runs.
    // We replicate both by using the execution ID stored in the token:
    //   - AMR: updateCompletedExecutions() registers the execution; AmrProtocolMapper reads
    //          Authenticator Reference + Authenticator Reference Max Age from its AuthenticatorConfig.
    //   - LOA: we read the level from the sibling ConditionalLoaAuthenticator in the same parent flow,
    //          so the LOA value is defined in exactly one place (the Condition config) and not duplicated
    //          in the Magic Link execution config.
    //   - API fallback: if no executionId is in the token, token.getLoa() is used directly (set by
    //          MagicLinkResource when flow_alias is not provided or ConditionalLoaAuthenticator is absent).
    //
    // Session preservation (Option A):
    //   If the browser already has a valid session with a LOA >= the magic link's LOA,
    //   we keep the existing session as-is and do not downgrade it.
    String executionId = token.getExecutionId();
    Integer loaLevel = token.getLoa(); // fallback for API path without flow context

    if (executionId != null) {
      // AMR
      AuthenticatorUtils.updateCompletedExecutions(authSession, null, executionId);
      log.debugf("[MagicLink] Registered execution %s in authenticators-completed for AMR", executionId);

      // LOA: read from sibling ConditionalLoaAuthenticator in the same parent flow
      AuthenticationExecutionModel magicExecution = tokenContext.getRealm().getAuthenticationExecutionById(executionId);
      if (magicExecution != null) {
        List<AuthenticationExecutionModel> loaConditions = AuthenticatorUtil.getExecutionsByType(
            tokenContext.getRealm(),
            magicExecution.getParentFlow(),
            ConditionalLoaAuthenticatorFactory.PROVIDER_ID);
        if (!loaConditions.isEmpty()) {
          Integer levelFromFlow = LoAUtil.getLevelFromLoaConditionConfiguration(
              tokenContext.getRealm().getAuthenticatorConfigById(loaConditions.get(0).getAuthenticatorConfig()));
          if (levelFromFlow != null) {
            loaLevel = levelFromFlow;
            log.debugf("[MagicLink] LOA level %d read from ConditionalLoaAuthenticator in parent flow", loaLevel);
          }
        }
      }
    } else {
      log.debugf("[MagicLink] No execution ID in token — AMR will not be set");
    }

    // Session preservation (Option A):
    // Keycloak always creates a new UserSession when an ActionToken is redeemed — the existing
    // browser session (identity cookie) is removed in redirectAfterSuccessfulFlow(). We cannot
    // prevent that. Instead, we carry over the existing session's LOA_MAP and
    // authenticators-completed into the new AuthSession so the new UserSession inherits the
    // combined state (higher LOA + all previous AMR values).
    UserSessionModel existingUserSession = getExistingUserSession(tokenContext);
    if (existingUserSession != null) {
      mergeExistingSessionIntoAuthSession(
          existingUserSession, authSession, loaLevel, tokenContext.getSession());
    } else if (loaLevel != null) {
      AcrStore acrStore = new AcrStore(tokenContext.getSession(), authSession);
      acrStore.setLevelAuthenticated(loaLevel);
      authSession.setUserSessionNote(Constants.LOA_MAP, authSession.getAuthNote(Constants.LOA_MAP));
    }

    String nextAction =
        AuthenticationManager.nextRequiredAction(
            tokenContext.getSession(),
            authSession,
            tokenContext.getRequest(),
            tokenContext.getEvent());
    return AuthenticationManager.redirectToRequiredActions(
        tokenContext.getSession(),
        tokenContext.getRealm(),
        authSession,
        tokenContext.getUriInfo(),
        nextAction);
  }

  /**
   * Returns the existing UserSession from the browser's identity cookie, or {@code null} if none.
   */
  private UserSessionModel getExistingUserSession(
      ActionTokenContext<MagicLinkActionToken> tokenContext) {
    try {
      AuthenticationManager.AuthResult authResult =
          AuthenticationManager.authenticateIdentityCookie(
              tokenContext.getSession(), tokenContext.getRealm(), true);
      if (authResult == null) return null;
      return authResult.getSession();
    } catch (Exception e) {
      log.debugf("[MagicLink] Could not read existing user session: %s", e.getMessage());
      return null;
    }
  }

  /**
   * Merges the existing UserSession's LOA_MAP and authenticators-completed into the new
   * AuthSession so the new UserSession inherits the combined state.
   *
   * <p>This preserves higher LOA levels and all previous AMR values from the existing session.
   * If the magic link's LOA is higher than the existing session's LOA, the magic link LOA wins.
   */
  private void mergeExistingSessionIntoAuthSession(
      UserSessionModel existingSession,
      AuthenticationSessionModel authSession,
      Integer magicLinkLoa,
      org.keycloak.models.KeycloakSession keycloakSession) {

    // --- LOA: carry over the existing LOA_MAP note, then apply magic link LOA on top ---
    String existingLoaMap = existingSession.getNote(Constants.LOA_MAP);
    if (existingLoaMap != null && !existingLoaMap.isEmpty()) {
      // Write the existing LOA_MAP into the auth note so AcrStore can read/merge it
      authSession.setAuthNote(Constants.LOA_MAP, existingLoaMap);
      log.debugf("[MagicLink] Carried over existing LOA_MAP into new auth session: %s", existingLoaMap);
    }

    // Determine the effective LOA level: max(existing, magicLink)
    int existingLoa = getHighestLevelFromLoaMap(existingLoaMap);
    int effectiveLoa = magicLinkLoa != null ? magicLinkLoa : Constants.NO_LOA;
    if (existingLoa != Constants.NO_LOA && existingLoa > effectiveLoa) {
      effectiveLoa = existingLoa;
      log.debugf(
          "[MagicLink] Existing session LOA %d > magic link LOA %s — using existing LOA",
          existingLoa, magicLinkLoa);
    } else {
      log.debugf(
          "[MagicLink] Using magic link LOA %d (existing session LOA: %d)",
          effectiveLoa, existingLoa);
    }

    if (effectiveLoa != Constants.NO_LOA) {
      AcrStore acrStore = new AcrStore(keycloakSession, authSession);
      acrStore.setLevelAuthenticated(effectiveLoa);
      authSession.setUserSessionNote(Constants.LOA_MAP, authSession.getAuthNote(Constants.LOA_MAP));
    }

    // --- AMR: merge existing authenticators-completed with the new auth session ---
    String existingCompleted = existingSession.getNote("authenticators-completed");
    if (existingCompleted != null && !existingCompleted.isEmpty()) {
      // The existing authenticators-completed is already set as a user session note.
      // Copy it into the new auth session's user session notes so it survives into the new session.
      authSession.setUserSessionNote("authenticators-completed", existingCompleted);
      log.debugf("[MagicLink] Carried over existing authenticators-completed: %s", existingCompleted);
    }

    // --- Remember Me: inherit from existing session if not explicitly set in the magic link token ---
    // The token's remember_me flag (set in handleToken above) takes precedence if explicitly true.
    // If the token did not set remember_me but the existing session had it, preserve it.
    if (existingSession.isRememberMe()
        && authSession.getAuthNote(Details.REMEMBER_ME) == null) {
      authSession.setAuthNote(Details.REMEMBER_ME, "true");
      log.debugf("[MagicLink] Carried over remember_me from existing session");
    }
  }

  /**
   * Parses the LOA_MAP JSON and returns the highest level, or {@code Constants.NO_LOA} if empty.
   * The LOA_MAP format is a JSON object: {"1": <timestamp>, "2": <timestamp>, ...}
   */
  private int getHighestLevelFromLoaMap(String loaMap) {
    if (loaMap == null || loaMap.isEmpty()) return Constants.NO_LOA;
    int highest = Constants.NO_LOA;
    for (String entry : loaMap.replaceAll("[{} \"]", "").split(",")) {
      String[] kv = entry.split(":");
      if (kv.length == 2) {
        try {
          int level = Integer.parseInt(kv[0].trim());
          if (level > highest) highest = level;
        } catch (NumberFormatException ignored) {}
      }
    }
    return highest;
  }
}
