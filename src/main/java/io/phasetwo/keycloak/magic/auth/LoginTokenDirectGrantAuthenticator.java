package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.auth.LoginTokenHelper.DG_USER_DISABLED;
import static io.phasetwo.keycloak.magic.auth.LoginTokenHelper.RESUME_PREFIX;

import com.google.auto.service.AutoService;
import jakarta.ws.rs.core.Response;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Direct Grant (Resource Owner Password Credentials) authenticator that authenticates a request
 * using a Login Token reference, with no browser interaction.
 *
 * <h3>Flow</h3>
 *
 * <ol>
 *   <li>Backend calls {@code POST /realms/{realm}/login-token} to obtain a UUID credential
 *       reference ({@code lt:{uuid}}) stored in {@link
 *       org.keycloak.models.SingleUseObjectProvider}.
 *   <li>The caller sends a token request to {@code POST
 *       /realms/{realm}/protocol/openid-connect/token} with {@code grant_type=password} and the
 *       login token as the {@code login_token} form parameter (either {@code lt:{uuid}} or the bare
 *       {@code uuid}). No {@code username} / {@code password} is required.
 *   <li>This authenticator looks up and validates the token (expiry, client, user) via {@link
 *       LoginTokenHelper#verifyDirectGrant}, enforces single-use, sets the user and optional LOA,
 *       and completes the grant — Keycloak issues the tokens directly.
 * </ol>
 *
 * <h3>Placement</h3>
 *
 * Add as <strong>REQUIRED</strong> in the realm's Direct Grant flow. Unlike the browser-flow {@link
 * LoginTokenVerifier}, this authenticator never reads the OIDC {@code login_hint} client note (the
 * token endpoint is not reached through the authorization endpoint, so that note is never set) and
 * never performs a cookie user-switch or renders a form/redirect. On any failure it returns a
 * standard OAuth2 error response instead of throwing, so the caller receives a clean {@code 401
 * invalid_grant} rather than a server error.
 */
@JBossLog
@AutoService(AuthenticatorFactory.class)
public class LoginTokenDirectGrantAuthenticator extends AbstractDirectGrantAuthenticator {

  public static final String PROVIDER_ID = "direct-grant-login-token";

  /** Form parameter carrying the login token reference ({@code lt:{uuid}} or the bare uuid). */
  public static final String PARAM_LOGIN_TOKEN = "login_token";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String raw = context.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_LOGIN_TOKEN);
    if (raw == null || raw.isBlank()) {
      log.debugf("[LT] (direct grant) missing '%s' form parameter", PARAM_LOGIN_TOKEN);
      context.failure(
          AuthenticationFlowError.INVALID_CREDENTIALS,
          errorResponse(
              Response.Status.UNAUTHORIZED.getStatusCode(),
              "invalid_request",
              "Missing '" + PARAM_LOGIN_TOKEN + "' parameter"));
      return;
    }

    String tokenId = raw.startsWith(RESUME_PREFIX) ? raw.substring(RESUME_PREFIX.length()) : raw;

    String error = LoginTokenHelper.verifyDirectGrant(context, tokenId);
    if (error == null) {
      // verifyDirectGrant already called context.success()
      return;
    }

    if (DG_USER_DISABLED.equals(error)) {
      context.failure(
          AuthenticationFlowError.USER_DISABLED,
          errorResponse(
              Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account disabled"));
    } else {
      context.failure(
          AuthenticationFlowError.INVALID_CREDENTIALS,
          errorResponse(
              Response.Status.UNAUTHORIZED.getStatusCode(),
              "invalid_grant",
              "Invalid or expired login token"));
    }
  }

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
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Login Token Direct Grant";
  }

  @Override
  public String getHelpText() {
    return "Authenticates a Resource Owner Password Credentials (direct grant) request using a"
        + " Login Token reference passed as the '"
        + PARAM_LOGIN_TOKEN
        + "' form parameter (lt:{uuid} or bare uuid). No browser interaction.";
  }

  @Override
  public String getReferenceCategory() {
    return "magic-link";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED,
    };
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }
}
