package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

import io.phasetwo.keycloak.magic.Helpers;
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
    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId(TEST_CLIENT);
    request.setReusable(reusable);

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
}
