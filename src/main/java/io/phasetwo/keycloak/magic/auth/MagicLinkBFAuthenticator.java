package io.phasetwo.keycloak.magic.auth;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.authentication.authenticators.util.LoAUtil;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import java.util.List;
import java.util.Map;

/**
 * Authenticator that completes magic-link authentication inside the Keycloak browser flow.
 *
 * <h3>Flow</h3>
 * <ol>
 *   <li>Backend calls {@code POST /realms/{realm}/magic-link} — no changes required.</li>
 *   <li>The app opens the returned action-token URL. {@link
 *       io.phasetwo.keycloak.magic.auth.token.MagicLinkActionTokenHandler} validates the JWT,
 *       stores a short-lived <em>resume token</em> in Infinispan, and redirects to the OIDC
 *       auth endpoint with {@code login_hint=mlbf-resume:{resumeId}}.</li>
 *   <li>The OIDC endpoint processes all parameters (including {@code acr_values}) correctly and
 *       starts the browser flow.</li>
 *   <li>This authenticator reads {@code login_hint}, consumes the resume token (single-use),
 *       sets the user and LOA, and calls {@code context.success()}.</li>
 *   <li>Subsequent authenticators (e.g. OTP for LOA=2) run in the same browser session —
 *       a single iOS {@code ASWebAuthenticationSession} suffices.</li>
 * </ol>
 *
 * <h3>LOA priority</h3>
 * <ol>
 *   <li>{@code force_session_loa} from the API request (in resume token) — explicit override,
 *       set directly in AcrStore regardless of what the flow conditions say.</li>
 *   <li>Level from the sibling {@code Condition - Level of Authentication} in the same parent
 *       sub-flow — only applies when placed inside a Conditional sub-flow.</li>
 * </ol>
 *
 * <h3>Placement</h3>
 * Add as <strong>ALTERNATIVE</strong> alongside username/password. When {@code login_hint}
 * does not start with {@code mlbf-resume:}, the authenticator calls {@code context.attempted()}
 * and lets other alternatives handle the request.
 */
@JBossLog
public class MagicLinkBFAuthenticator implements Authenticator {

  /**
   * Prefix in {@code login_hint} that signals a magic-link resume token.
   * Must stay in sync with {@link
   * io.phasetwo.keycloak.magic.auth.token.MagicLinkActionTokenHandler#RESUME_PREFIX}.
   */
  public static final String RESUME_PREFIX = "mlbf-resume:";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String loginHint = context.getAuthenticationSession()
        .getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

    if (loginHint == null || !loginHint.startsWith(RESUME_PREFIX)) {
      context.attempted();
      return;
    }

    completeWithResumeToken(context, loginHint.substring(RESUME_PREFIX.length()));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    authenticate(context);
  }

  // -------------------------------------------------------------------------

  private void completeWithResumeToken(AuthenticationFlowContext context, String resumeId) {
    // remove() reads AND deletes atomically — single-use guarantee
    Map<String, String> data = context.getSession()
        .getProvider(SingleUseObjectProvider.class)
        .remove(resumeId);

    if (data == null) {
      log.warnf("[MLBF] resume token not found or already used: '%s'", resumeId);
      context.attempted();
      return;
    }

    // Security: verify the token was issued for this realm
    String storedRealmId = data.get("realmId");
    if (storedRealmId != null && !storedRealmId.equals(context.getRealm().getId())) {
      log.warnf("[MLBF] realm mismatch for resume token '%s'", resumeId);
      context.attempted();
      return;
    }

    String userId = data.get("userId");
    if (userId == null) {
      log.warnf("[MLBF] resume token '%s' missing userId", resumeId);
      context.attempted();
      return;
    }

    UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
    if (user == null || !user.isEnabled()) {
      log.warnf("[MLBF] user '%s' not found or disabled", userId);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return;
    }

    context.setUser(user);
    context.getAuthenticationSession().setAuthenticatedUser(user);

    // --- LOA: force_session_loa takes priority, then sibling condition ---
    Integer loaLevel = resolveLoaLevel(context, data);
    if (loaLevel != null) {
      new AcrStore(context.getSession(), context.getAuthenticationSession())
          .setLevelAuthenticated(loaLevel);
      log.debugf("[MLBF] LOA %d set for user '%s'", loaLevel, userId);
    }

    if ("true".equals(data.get("rememberMe"))) {
      context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
    }

    log.debugf("[MLBF] authentication complete for user '%s'", userId);
    context.success();
  }

  /**
   * Resolves the LOA level to set in the AcrStore.
   *
   * <p>Priority:
   * <ol>
   *   <li>{@code force_session_loa} from the resume token — explicit override.</li>
   *   <li>Level from the sibling {@code Condition - Level of Authentication} in the same parent
   *       sub-flow — only applies when placed inside a Conditional sub-flow.</li>
   * </ol>
   */
  private Integer resolveLoaLevel(AuthenticationFlowContext context, Map<String, String> data) {
    // 1. force_session_loa from the magic-link token
    String loaStr = data.get("forceSessionLoa");
    if (loaStr != null && !loaStr.isBlank()) {
      try {
        return Integer.parseInt(loaStr.trim());
      } catch (NumberFormatException e) {
        log.warnf("[MLBF] invalid forceSessionLoa value: '%s'", loaStr);
      }
    }

    // 2. Sibling Condition - Level of Authentication (when inside a Conditional sub-flow)
    String parentFlowId = context.getExecution().getParentFlow();
    List<AuthenticationExecutionModel> loaConditions = AuthenticatorUtil.getExecutionsByType(
        context.getRealm(), parentFlowId, ConditionalLoaAuthenticatorFactory.PROVIDER_ID);

    if (!loaConditions.isEmpty()) {
      String configId = loaConditions.get(0).getAuthenticatorConfig();
      Integer level = LoAUtil.getLevelFromLoaConditionConfiguration(
          context.getRealm().getAuthenticatorConfigById(configId));
      if (level != null) {
        log.debugf("[MLBF] LOA %d read from sibling Condition - Level of Authentication", level);
        return level;
      }
    }

    return null;
  }

  // -------------------------------------------------------------------------

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
