package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.LoginTokenTestSupport;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.Base64;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;

/**
 * Integration test for {@link io.phasetwo.keycloak.magic.auth.LoginTokenDirectGrantAuthenticator}.
 *
 * <p>Drives the full Direct Grant (Resource Owner Password Credentials) path end-to-end against a
 * real Keycloak container: a Login Token is minted via {@code POST /login-token}, then redeemed at
 * the token endpoint with {@code grant_type=password} and the token passed as the {@code
 * login_token} form parameter. No browser interaction and no username/password are involved.
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
public class LoginTokenDirectGrantTest extends AbstractMagicLinkTest {

  private static final String TEST_REALM = "test-realm-dg";
  private static final String TEST_CLIENT = "dg-test-client";
  private static final String TEST_EMAIL = "testuser@phasetwo.io";

  private static final String LOGIN_TOKEN_PATH = "realms/" + TEST_REALM + "/login-token";
  private static final String TOKEN_PATH =
      "realms/" + TEST_REALM + "/protocol/openid-connect/token";

  /**
   * Mints a Login Token via the admin API and returns the {@code login_hint} ({@code lt:{uuid}}).
   */
  private String createLoginToken(boolean reusable) throws Exception {
    return createLoginToken(TEST_CLIENT, reusable);
  }

  /**
   * Mints a Login Token bound to the given client ({@code null} = unbound "universal" token) and
   * returns the {@code login_hint} ({@code lt:{uuid}}).
   */
  private String createLoginToken(String clientId, boolean reusable) throws Exception {
    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId(clientId);
    request.setReusable(reusable);
    return mint(request);
  }

  /** A request for the test user bound to the test client; callers set the fields under test. */
  private static LoginTokenRequest request() {
    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId(TEST_CLIENT);
    return request;
  }

  private static LoginTokenRequest statelessRequest() {
    LoginTokenRequest request = request();
    request.setStateless(true);
    return request;
  }

  /** Posts the request to {@code /login-token} and returns the {@code login_hint}. */
  private String mint(LoginTokenRequest request) throws Exception {
    return given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Helpers.toJsonString(request))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getString("login_hint");
  }

  private Response redeem(String loginToken) {
    return given()
        .baseUri(getAuthUrl())
        .contentType("application/x-www-form-urlencoded")
        .formParam("grant_type", "password")
        .formParam("client_id", TEST_CLIENT)
        .formParam("scope", "openid")
        .formParam("login_token", loginToken)
        .post(TOKEN_PATH);
  }

  /** Decodes the (unverified) payload of a JWT into a {@link JsonPath} for claim assertions. */
  private static JsonPath decodeJwtPayload(String jwt) {
    String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    return new JsonPath(payload);
  }

  @Test
  public void validTokenYieldsAccessTokenWithAmr() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    String loginHint = createLoginToken(true);
    assertThat(loginHint, not(emptyOrNullString()));

    String accessToken =
        redeem(loginHint)
            .then()
            .statusCode(200)
            .body("access_token", not(emptyOrNullString()))
            .body("token_type", equalTo("Bearer"))
            .extract()
            .path("access_token");

    // The access token carries amr=["login_token"] (via the execution's default.reference.value
    // config + the oidc-amr-mapper) and acr=1 (LOA set by the authenticator).
    JsonPath claims = decodeJwtPayload(accessToken);
    assertThat(claims.getList("amr", String.class), hasItem("login_token"));
    assertThat(claims.getString("acr"), equalTo("1"));
  }

  @Test
  public void invalidTokenIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    redeem("lt:00000000-0000-0000-0000-000000000000")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void missingTokenIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    given()
        .baseUri(getAuthUrl())
        .contentType("application/x-www-form-urlencoded")
        .formParam("grant_type", "password")
        .formParam("client_id", TEST_CLIENT)
        .formParam("scope", "openid")
        .post(TOKEN_PATH)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void singleUseTokenCannotBeRedeemedTwice() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    String loginHint = createLoginToken(false);

    // First redemption succeeds.
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));

    // Second redemption of the same single-use token is rejected.
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  // ---------------------------------------------------------------------------
  // Client binding
  // ---------------------------------------------------------------------------

  @Test
  public void tokenBoundToOtherClientIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // Token bound to dg-other-client, redeemed by dg-test-client → client mismatch.
    String loginHint = createLoginToken("dg-other-client", true);

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void unboundTokenIsRejectedByDefault() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // Minting without client_id succeeds, but the default-strict execution rejects redemption.
    String loginHint = createLoginToken(null, true);
    assertThat(loginHint, not(emptyOrNullString()));

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void unboundTokenIsAcceptedWhenClientBindingOptional() throws Exception {
    importRealm("/realms/direct-grant-login-token-unbound-test-setup.json");

    String loginHint = createLoginToken(null, true);

    String accessToken =
        redeem(loginHint)
            .then()
            .statusCode(200)
            .body("access_token", not(emptyOrNullString()))
            .extract()
            .path("access_token");

    JsonPath claims = decodeJwtPayload(accessToken);
    assertThat(claims.getList("amr", String.class), hasItem("login_token"));
    assertThat(claims.getString("acr"), equalTo("1"));
  }

  @Test
  public void boundTokenIsStillEnforcedWhenClientBindingOptional() throws Exception {
    importRealm("/realms/direct-grant-login-token-unbound-test-setup.json");

    // A binding present on the token is enforced even when the execution allows unbound tokens.
    String mismatched = createLoginToken("dg-other-client", true);
    redeem(mismatched).then().statusCode(401).body("error", equalTo("invalid_grant"));

    // A correctly bound token keeps working with the permissive execution config.
    String matching = createLoginToken(TEST_CLIENT, true);
    redeem(matching).then().statusCode(200).body("access_token", not(emptyOrNullString()));
  }

  @Test
  public void unknownClientIdIsRejectedOnCreation() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId("does-not-exist");

    given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Helpers.toJsonString(request))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(404);
  }

  @Test
  public void singleUseTokenCannotBeRedeemedTwiceInvalidToken() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    String loginHint = createLoginToken(false);

    // First redemption succeeds.
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));

    // Second redemption of the same single-use token is rejected.
    redeem(loginHint)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_grant"))
        .body("error_description", equalTo("Invalid or expired login token"));
  }

  // ---------------------------------------------------------------------------
  // Legacy token format (lt:{uuid}, credential stored server-side)
  // ---------------------------------------------------------------------------

  @Test
  public void legacyFormatIsIssuedByDefault() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    // Even with a key provider in place, a request that does not ask for a stateless token keeps
    // getting the legacy format as long as the server default is unchanged.
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));
  }

  @Test
  public void legacyTokenWithoutUseLimitStaysReusable() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // Neither max_uses nor reusable set: unlimited, as before max_uses existed.
    String loginHint = mint(request());

    for (int i = 0; i < 3; i++) {
      redeem(loginHint).then().statusCode(200);
    }
  }

  @Test
  public void legacyTokenHonoursMaxUses() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    LoginTokenRequest request = request();
    request.setMaxUses(2);
    String loginHint = mint(request);
    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void legacyFormatIsTheFallbackWithoutKeyProvider() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // A stateless token is requested, but the realm has no "login-token" key provider: issuing
    // must not fail, the caller gets a working legacy token instead.
    String loginHint = mint(statelessRequest());

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));
  }

  // ---------------------------------------------------------------------------
  // Stateless token format (lt:v2.…, credential encrypted into the token)
  // ---------------------------------------------------------------------------

  @Test
  public void statelessTokenYieldsAccessTokenWithAmr() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(statelessRequest());

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
    assertThat(loginHint.length(), lessThanOrEqualTo(StatelessLoginToken.MAX_LOGIN_HINT_LENGTH));

    String accessToken =
        redeem(loginHint)
            .then()
            .statusCode(200)
            .body("access_token", not(emptyOrNullString()))
            .extract()
            .path("access_token");

    JsonPath claims = decodeJwtPayload(accessToken);
    assertThat(claims.getList("amr", String.class), hasItem("login_token"));
    assertThat(claims.getString("acr"), equalTo("1"));
  }

  @Test
  public void statelessTokenIsAcceptedWithoutLoginHintPrefix() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(statelessRequest());

    redeem(loginHint.substring("lt:".length())).then().statusCode(200);
  }

  @Test
  public void statelessTokenWithoutUseLimitIsReusable() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(statelessRequest());

    for (int i = 0; i < 3; i++) {
      redeem(loginHint).then().statusCode(200);
    }
  }

  @Test
  public void statelessSingleUseTokenCannotBeRedeemedTwice() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setMaxUses(1);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenMapsLegacyReusableFlagToSingleUse() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setReusable(false);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenHonoursMaxUses() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setMaxUses(3);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void modifiedStatelessTokenIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(statelessRequest());
    // Change one character in the middle of the encrypted part.
    int position = loginHint.length() / 2;
    char replacement = loginHint.charAt(position) == 'A' ? 'B' : 'A';
    String tampered =
        loginHint.substring(0, position) + replacement + loginHint.substring(position + 1);

    redeem(tampered).then().statusCode(401).body("error", equalTo("invalid_grant"));
    // The untouched token still works: a failed attempt does not consume it.
    redeem(loginHint).then().statusCode(200);
  }

  @Test
  public void expiredStatelessTokenIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setExpirationSeconds(1);
    String loginHint = mint(request);

    Thread.sleep(2500);

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenBoundToOtherClientIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setClientId("dg-other-client");
    String loginHint = mint(request);
    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void unboundStatelessTokenIsRejectedByDefault() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = statelessRequest();
    request.setClientId(null);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenStopsWorkingWhenItsKeyIsRemoved() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    String keyProviderId = LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(statelessRequest());
    redeem(loginHint).then().statusCode(200);

    // Removing the key provider is the kill switch for every outstanding stateless token.
    keycloak.realm(TEST_REALM).components().component(keyProviderId).remove();

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenSurvivesKeyRotation() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM, 10);

    String issuedUnderOldKey = mint(statelessRequest());

    // Rotation: a second provider with a higher priority encrypts new tokens, the old one stays
    // enabled so tokens issued under it remain valid.
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM, 20);
    String issuedUnderNewKey = mint(statelessRequest());

    redeem(issuedUnderOldKey).then().statusCode(200);
    redeem(issuedUnderNewKey).then().statusCode(200);
  }

  // ---------------------------------------------------------------------------
  // Request validation
  // ---------------------------------------------------------------------------

  @Test
  public void maxUsesAboveTheLimitIsRejectedOnCreation() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    LoginTokenRequest request = request();
    request.setMaxUses(StatelessLoginToken.MAX_USES_LIMIT + 1);

    postLoginToken(request).then().statusCode(400);
  }

  @Test
  public void nonPositiveExpirationIsRejectedOnCreation() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    LoginTokenRequest request = request();
    request.setExpirationSeconds(0);

    postLoginToken(request).then().statusCode(400);
  }

  private Response postLoginToken(LoginTokenRequest request) throws Exception {
    return given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Helpers.toJsonString(request))
        .post(LOGIN_TOKEN_PATH);
  }
}
