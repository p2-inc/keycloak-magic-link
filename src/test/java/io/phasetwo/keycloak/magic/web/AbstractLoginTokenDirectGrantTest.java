package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.util.Base64;

/**
 * Shared fixtures for the Direct Grant Login Token tests: a Login Token is minted via {@code POST
 * /login-token}, then redeemed at the token endpoint with {@code grant_type=password} and the
 * token passed as the {@code login_token} form parameter.
 *
 * <p>Which token format the server issues is a server setting, so the tests are split by it:
 * {@link LoginTokenDirectGrantTest} runs against the default (legacy format), {@link
 * StatelessLoginTokenDirectGrantTest} against a server switched to stateless tokens.
 */
abstract class AbstractLoginTokenDirectGrantTest extends AbstractMagicLinkTest {

  protected static final String TEST_REALM = "test-realm-dg";
  protected static final String TEST_CLIENT = "dg-test-client";
  protected static final String TEST_EMAIL = "testuser@phasetwo.io";

  protected static final String LOGIN_TOKEN_PATH = "realms/" + TEST_REALM + "/login-token";
  protected static final String TOKEN_PATH =
      "realms/" + TEST_REALM + "/protocol/openid-connect/token";

  /** Mints a Login Token via the admin API and returns the {@code login_hint}. */
  protected String createLoginToken(boolean reusable) throws Exception {
    return createLoginToken(TEST_CLIENT, reusable);
  }

  /**
   * Mints a Login Token bound to the given client ({@code null} = unbound "universal" token) and
   * returns the {@code login_hint}.
   */
  protected String createLoginToken(String clientId, boolean reusable) throws Exception {
    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId(clientId);
    request.setReusable(reusable);
    return mint(request);
  }

  /** A request for the test user bound to the test client; callers set the fields under test. */
  protected static LoginTokenRequest request() {
    LoginTokenRequest request = new LoginTokenRequest();
    request.setEmail(TEST_EMAIL);
    request.setClientId(TEST_CLIENT);
    return request;
  }

  /** Posts the request to {@code /login-token} and returns the {@code login_hint}. */
  protected String mint(LoginTokenRequest request) throws Exception {
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

  protected Response redeem(String loginToken) {
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
  protected static JsonPath decodeJwtPayload(String jwt) {
    String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    return new JsonPath(payload);
  }

  /**
   * Posts a literal JSON body, so that what is absent, null or false on the wire is exactly what
   * the test says. {@code %s} placeholders are filled with the test email and client id.
   */
  protected String mintRaw(String jsonTemplate) {
    return given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(String.format(jsonTemplate, TEST_EMAIL, TEST_CLIENT))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getString("login_hint");
  }

  protected Response postLoginToken(LoginTokenRequest request) throws Exception {
    return given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Helpers.toJsonString(request))
        .post(LOGIN_TOKEN_PATH);
  }
}
