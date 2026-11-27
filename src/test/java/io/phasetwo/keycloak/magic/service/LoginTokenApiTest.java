package io.phasetwo.keycloak.magic.service;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.LoginTokenTestSupport;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;

/**
 * Integration tests for the Login Token REST API ({@code POST /login-token}) and the
 * {@link io.phasetwo.keycloak.magic.auth.LoginTokenVerifier} browser-flow authenticator.
 *
 * <p>The test realm ({@code login-token-api-test-setup.json}) uses a simple browser flow
 * containing only {@code auth-cookie} and {@code login-token-verifier} as ALTERNATIVE
 * executions. This lets us verify:
 *
 * <ul>
 *   <li>The API returns a {@code login_hint} value with {@code lt:...} prefix.</li>
 *   <li>Following an OIDC auth URL built from the {@code login_hint} completes the browser flow
 *       and yields an authorization code.</li>
 *   <li>Explicit {@code loa} ends up as the {@code acr} claim in the ID token.</li>
 *   <li>A single-use token ({@code reusable=false}) is rejected on second use.</li>
 *   <li>A reusable token ({@code reusable=true}) can be followed more than once.</li>
 *   <li>{@code set_email_verified=true} marks the user's email as verified on redemption.</li>
 *   <li>Missing required fields return the appropriate HTTP error codes.</li>
 * </ul>
 */
@JBossLog
class LoginTokenApiTest extends AbstractLoginTokenApiTest {

  // -------------------------------------------------------------------------
  // API validation tests
  // -------------------------------------------------------------------------

  @Test
  void createLoginToken_returnsLoginHintAndUserId() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(
            Map.of(
                "email", TEST_EMAIL,
                "client_id", TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .body("login_hint", not(emptyOrNullString()));
  }

  @Test
  void createLoginToken_loginHintHasLtPrefix() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String loginHint = postLoginTokenRequest(buildRequest(null, null));

    assertTrue(loginHint.startsWith("lt:"), "login_hint must start with 'lt:', got: " + loginHint);
  }

  @Test
  void createLoginToken_missingClientId_createsUnboundToken() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    // client_id is optional: omitting it mints an unbound ("universal") token. Such tokens are
    // only redeemable by executions with "Client ID must match" switched OFF (default is ON).
    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Map.of("email", TEST_EMAIL))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .body("login_hint", not(emptyOrNullString()));
  }

  @Test
  void createLoginToken_unknownUser_returnsNotFound() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Map.of("email", "nobody@example.com", "client_id", TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(404);
  }

  @Test
  void createLoginToken_withUserId_returnsLoginHint() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String userId =
        keycloak.realm(TEST_REALM).users().searchByEmail(TEST_EMAIL, true).get(0).getId();

    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(
            Map.of(
                "user_id", userId,
                "client_id", TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .body("login_hint", not(emptyOrNullString()));
  }

  @Test
  void createLoginToken_userId_takesPrecedenceOverEmail() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String userId =
        keycloak.realm(TEST_REALM).users().searchByEmail(TEST_EMAIL, true).get(0).getId();

    // email points to a non-existent user — if user_id were ignored this would return 404
    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(
            Map.of(
                "user_id", userId,
                "email", "nobody@example.com",
                "client_id", TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200);
  }

  @Test
  void createLoginToken_unknownUserId_returnsNotFound() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Map.of("user_id", "00000000-0000-0000-0000-000000000000", "client_id", TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(404);
  }

  // -------------------------------------------------------------------------
  // Flow tests
  // -------------------------------------------------------------------------

  @Test
  void loginTokenFlow_completesSuccessfullyAndReturnsAuthCode() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String link = createLoginToken(Map.of("scope", "openid"));
    String code = followLinkToCode(link);

    assertNotNull(code, "authorization code must be returned after a successful login token flow");
  }

  @Test
  void loginTokenWithExplicitLoa_acrClaimMatchesRequestedLoa() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String link = createLoginToken(Map.of("scope", "openid"), 2, null);
    Map<String, Object> claims = redeemAndDecodeIdToken(link);

    assertEquals(
        "2",
        String.valueOf(claims.get("acr")),
        "acr claim must equal the loa value set in the login-token request");
  }

  @Test
  void loginTokenSingleUse_cannotBeRedeemedTwice() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String link = createLoginToken(Map.of(), null, false);

    String firstCode = followLinkToCode(link);
    assertNotNull(firstCode, "first redemption must return an authorization code");

    // Second attempt with a fresh HTTP client (no cookies) must fail
    String secondLocation =
        given().redirects().follow(false).get(link).then().extract().header("Location");

    assertTrue(
        secondLocation == null || secondLocation.contains("error"),
        "second redemption of a single-use login token must be rejected (Location: "
            + secondLocation
            + ")");
  }

  /**
   * An unknown {@code lt:} hint is not a credential. The verifier clears it, forwards {@code
   * loginTokenInvalid}, and calls {@code attempted()} so the username form is shown with an empty
   * username field.
   */
  @Test
  void invalidLoginHint_showsLoginFormWithMessageAndEmptyUsername() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-invalid-hint-test-setup.json");

    String loginHint = "lt:00000000-0000-0000-0000-000000000000";
    String link = buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI));
    String html = followUntilPage(link);

    assertTrue(html.contains("name=\"username\""), "username form must be shown");
    assertTrue(
        html.contains("Invalid or expired login token. Please try again."),
        "forwarded loginTokenInvalid message must be shown");
    assertFalse(
        html.contains("value=\"" + loginHint + "\""),
        "username field must not be prefilled with the invalid login hint");
  }

  @Test
  void loginTokenReusable_canBeRedeemedMultipleTimes() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    String link = createLoginToken(Map.of(), null, true);

    String firstCode = followLinkToCode(link);
    assertNotNull(firstCode, "first redemption must return an authorization code");

    // Fresh HTTP client — no session cookie carried over
    String secondCode = followLinkToCode(link);
    assertNotNull(secondCode, "second redemption of a reusable token must also succeed");
  }

  @Test
  void loginTokenSetEmailVerified_marksEmailVerifiedOnRedemption() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    UserRepresentation user =
        Helpers.createUser(
            keycloak,
            TEST_REALM,
            "unverified@test.com",
            "unverified@test.com",
            "Unverified",
            "User");

    UserRepresentation before =
        keycloak.realm(TEST_REALM).users().get(user.getId()).toRepresentation();
    assertFalse(
        Boolean.TRUE.equals(before.isEmailVerified()),
        "pre-condition: email must not be verified before the link is followed");

    LoginTokenRequest req = new LoginTokenRequest();
    req.setEmail("unverified@test.com");
    req.setClientId(TEST_CLIENT);
    req.setSetEmailVerified(true);

    String loginHint = postLoginTokenRequest(req);
    String link = buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI, "scope", "openid"));
    followLinkToCode(link);

    UserRepresentation after =
        keycloak.realm(TEST_REALM).users().get(user.getId()).toRepresentation();
    assertTrue(
        Boolean.TRUE.equals(after.isEmailVerified()),
        "email must be marked verified after following a link with set_email_verified=true");
  }

  /**
   * Regression test for the {@code remember_me} / "Session not active" bug.
   *
   * <p>Since Keycloak 26.5.0 (backported to 26.4.2 / 26.2.12),
   * {@code AuthenticationManager.isSessionValid()} treats any user session created with
   * {@code rememberMe=true} as invalid when the realm has remember me disabled. Because the test
   * realm does not enable remember me, a login token requesting {@code remember_me=true} used to
   * produce a session that failed the subsequent authorization-code exchange with
   * {@code invalid_grant: "Session not active"}.
   *
   * <p>The verifier now only sets the remember-me note when {@code realm.isRememberMe()} is true,
   * so the code exchange must succeed (HTTP 200) even though the token asked for remember me.
   */
  @Test
  void loginTokenRememberMe_realmRememberMeDisabled_codeExchangeSucceeds() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");

    LoginTokenRequest req = new LoginTokenRequest();
    req.setEmail(TEST_EMAIL);
    req.setClientId(TEST_CLIENT);
    req.setRememberMe(true);

    String loginHint = postLoginTokenRequest(req);
    String link = buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI, "scope", "openid"));
    String code = followLinkToCode(link);
    assertNotNull(code, "authorization code must be returned even when remember_me=true");

    given()
        .baseUri(getAuthUrl())
        .contentType("application/x-www-form-urlencoded")
        .formParam("grant_type", "authorization_code")
        .formParam("client_id", TEST_CLIENT)
        .formParam("code", code)
        .formParam("redirect_uri", REDIRECT_URI)
        .post(TOKEN_PATH)
        .then()
        .statusCode(200)
        .body("access_token", not(emptyOrNullString()));
  }

  // -------------------------------------------------------------------------
  // Token formats in the browser flow
  // -------------------------------------------------------------------------

  /** The legacy token format ({@code lt:{uuid}}) stays the default and keeps working. */
  @Test
  void legacyTokenFormat_isIssuedByDefaultAndRedeemsInBrowserFlow() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = postLoginTokenRequest(buildRequest(null, null));
    assertTrue(
        loginHint.matches(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN),
        "default login_hint must use the legacy format: " + loginHint);

    String code = followLinkToCode(buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI)));
    assertNotNull(code, "a legacy token must still yield an authorization code");
  }

  /**
   * A token whose uses are exhausted must be treated like an expired one: the login form is
   * shown with the "invalid or expired" message and an empty username field. In particular the
   * token must not end up as the suggested username.
   */
  @Test
  void usedUpLegacyToken_showsLoginFormWithMessageAndEmptyUsername() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-invalid-hint-test-setup.json");

    LoginTokenRequest req = buildRequest(null, null);
    req.setMaxUses(1);
    assertUsedUpTokenShowsCleanLoginForm(postLoginTokenRequest(req));
  }
}
