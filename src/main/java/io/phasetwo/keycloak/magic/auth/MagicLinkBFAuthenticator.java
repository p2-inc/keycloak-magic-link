package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.token.MagicLinkV2Token.*;

import io.phasetwo.keycloak.magic.auth.token.MagicLinkV2Token;
import java.util.List;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorUtil;
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

/**
 * Authenticator that completes Magic Link v2 authentication inside the Keycloak browser flow.
 *
 * <h3>Flow</h3>
 * <ol>
 *   <li>Backend calls {@code POST /realms/{realm}/magic-link-v2} to obtain an OIDC authorization
 *       URL containing a UUID credential reference in {@code login_hint=mlv2:{uuid}}. The
 *       credential data is stored in {@link SingleUseObjectProvider} (Infinispan).</li>
 *   <li>The app opens that URL. The OIDC endpoint processes all parameters and starts the browser
 *       flow.</li>
 *   <li>This authenticator reads {@code login_hint}, looks up the credential by UUID, validates
 *       expiry and client, enforces single-use (unless {@code reusable=true}), sets the user and
 *       optional LOA, and calls {@code context.success()}.</li>
 *   <li>Subsequent authenticators (e.g. TOTP for LOA=2) run in the same browser session.</li>
 * </ol>
 *
 * <h3>LOA priority</h3>
 * <ol>
 *   <li>{@code loa} from the stored credential — explicit override.</li>
 *   <li>Level from the sibling {@code Condition - Level of Authentication} in the same parent
 *       sub-flow — fallback when the credential does not carry a LOA.</li>
 * </ol>
 *
 * <h3>Placement</h3>
 * Add as <strong>ALTERNATIVE</strong> alongside username/password. When {@code login_hint} does
 * not start with {@code mlv2:}, the authenticator calls {@code context.attempted()} and lets
 * other alternatives handle the request.
 */
@JBossLog
public class MagicLinkBFAuthenticator implements Authenticator {

  /**
   * Prefix in {@code login_hint} that signals a Magic Link v2 credential.
   * Must stay in sync with the value used in
   * {@link io.phasetwo.keycloak.magic.resources.MagicLinkV2Resource}.
   */
  public static final String RESUME_PREFIX = "mlv2:";

  /**
   * Prefix for SingleUseObjectProvider keys that store the credential data.
   * The full key is {@code DATA_KEY_PREFIX + tokenId}.
   */
  public static final String DATA_KEY_PREFIX = "mlv2:data:";

  /** Prefix for "already used" marker keys (for single-use enforcement). */
  private static final String USED_KEY_PREFIX = "mlv2:used:";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String loginHint =
        context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

    if (loginHint == null || !loginHint.startsWith(RESUME_PREFIX)) {
      context.attempted();
      return;
    }

    String tokenId = loginHint.substring(RESUME_PREFIX.length());
    completeWithTokenId(context, tokenId);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    authenticate(context);
  }

  // -------------------------------------------------------------------------

  private void completeWithTokenId(AuthenticationFlowContext context, String tokenId) {
    SingleUseObjectProvider singleUse =
        context.getSession().getProvider(SingleUseObjectProvider.class);
    String dataKey = DATA_KEY_PREFIX + tokenId;

    Map<String, String> notes = singleUse.get(dataKey);
    if (notes == null) {
      log.warnf("[MLv2] credential not found or expired for tokenId='%s'", tokenId);
      context.attempted();
      return;
    }

    // Validate expiry (belt-and-suspenders; Infinispan TTL covers this too)
    String expiryStr = notes.get(KEY_EXPIRY);
    if (expiryStr != null) {
      long expiry = Long.parseLong(expiryStr);
      if (System.currentTimeMillis() / 1000L > expiry) {
        log.warnf("[MLv2] credential expired for tokenId='%s'", tokenId);
        context.attempted();
        return;
      }
    }

    // Validate client
    String storedClientId = notes.get(KEY_CLIENT_ID);
    String sessionClientId = context.getAuthenticationSession().getClient().getClientId();
    if (storedClientId != null && !storedClientId.equals(sessionClientId)) {
      log.warnf("[MLv2] client mismatch: stored='%s', flow='%s'", storedClientId, sessionClientId);
      context.attempted();
      return;
    }

    // Single-use enforcement: atomically claim the "used" slot.
    boolean isReusable = "true".equalsIgnoreCase(notes.get(KEY_REUSABLE));
    if (!isReusable) {
      long remainingTtl = expiryStr != null
          ? Math.max(1L, Long.parseLong(expiryStr) - (System.currentTimeMillis() / 1000L))
          : 300L;
      String usedKey = USED_KEY_PREFIX + tokenId;
      if (!singleUse.putIfAbsent(usedKey, remainingTtl)) {
        log.warnf("[MLv2] token already used: '%s'", tokenId);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        return;
      }
    }

    // Resolve user
    String userId = notes.get(KEY_USER_ID);
    UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
    if (user == null || !user.isEnabled()) {
      log.warnf("[MLv2] user '%s' not found or disabled", userId);
      context.failure(AuthenticationFlowError.USER_DISABLED);
      return;
    }

    context.setUser(user);
    context.getAuthenticationSession().setAuthenticatedUser(user);
    if ("true".equalsIgnoreCase(notes.get(KEY_SEV))) {
      user.setEmailVerified(true);
      user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.name());
    }

    // LOA
    Integer loaLevel = resolveLoaLevel(context, notes);
    if (loaLevel != null) {
      new AcrStore(context.getSession(), context.getAuthenticationSession())
          .setLevelAuthenticated(loaLevel);
      log.debugf("[MLv2] LOA %d set for user '%s'", loaLevel, userId);
    }

    if ("true".equalsIgnoreCase(notes.get(KEY_REMEMBER_ME))) {
      context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
    }

    log.debugf("[MLv2] authentication complete for user '%s'", userId);
    context.success();
  }

  /**
   * Resolves the LOA level to set in the AcrStore.
   *
   * <p>Priority:
   * <ol>
   *   <li>{@code loa} from the stored credential — explicit override.</li>
   *   <li>Level from the sibling {@code Condition - Level of Authentication} in the same parent
   *       sub-flow — fallback when placed inside a Conditional sub-flow.</li>
   * </ol>
   */
  private Integer resolveLoaLevel(AuthenticationFlowContext context, Map<String, String> notes) {
    String loaStr = notes.get(KEY_LOA);
    if (loaStr != null) {
      try {
        return Integer.parseInt(loaStr);
      } catch (NumberFormatException ignored) {
        // fall through to flow-level resolution
      }
    }

    String parentFlowId = context.getExecution().getParentFlow();
    List<AuthenticationExecutionModel> loaConditions =
        AuthenticatorUtil.getExecutionsByType(
            context.getRealm(), parentFlowId, ConditionalLoaAuthenticatorFactory.PROVIDER_ID);

    if (!loaConditions.isEmpty()) {
      String configId = loaConditions.get(0).getAuthenticatorConfig();
      Integer level =
          LoAUtil.getLevelFromLoaConditionConfiguration(
              context.getRealm().getAuthenticatorConfigById(configId));
      if (level != null) {
        log.debugf("[MLv2] LOA %d read from sibling Condition - Level of Authentication", level);
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
