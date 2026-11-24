package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.LoginTokenTestSupport;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import io.restassured.path.json.JsonPath;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;

/**
 * Integration test for {@link io.phasetwo.keycloak.magic.auth.LoginTokenDirectGrantAuthenticator}
 * against a server with default settings, which issues Login Tokens in the legacy format.
 *
 * <p>Drives the full Direct Grant (Resource Owner Password Credentials) path end-to-end against a
 * real Keycloak container. No browser interaction and no username/password are involved.
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
public class LoginTokenDirectGrantTest extends AbstractLoginTokenDirectGrantTest {

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
    // Even with a key provider in place, the server keeps issuing the legacy format as long as
    // the SPI option "legacy" is unchanged.
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));
  }

  @Test
  public void requestCannotSelectTheStatelessFormat() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // The format is a server setting. A "legacy" field in the body is not part of the API and is
    // ignored like any other unknown field.
    String loginHint = mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\",\"legacy\":false}");

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));
    assertThat(LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM), hasSize(0));
  }

  @Test
  public void legacyTokenWithoutUseLimitStaysReusable() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // The body an existing caller sends: no max_uses, no reusable. Unlimited, as it always was.
    String loginHint = mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\"}");

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    for (int i = 0; i < 3; i++) {
      redeem(loginHint).then().statusCode(200);
    }
  }

  @Test
  public void reusableFalseStaysSingleUse() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    String loginHint = mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\",\"reusable\":false}");

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void explicitNullReusableStaysSingleUse() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // Callers that serialize an unset optional as null got a single-use token before max_uses
    // existed; they must not silently get an unlimited one now.
    String loginHint = mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\",\"reusable\":null}");

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void maxUsesTakesPrecedenceOverReusable() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    String loginHint =
        mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\",\"reusable\":false,\"max_uses\":0}");

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
  public void legacyTokensNeverCreateAKeyProvider() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    mint(request());

    assertThat(LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM), hasSize(0));
  }

  // ---------------------------------------------------------------------------
  // Malformed tokens
  // ---------------------------------------------------------------------------

  @Test
  public void malformedTokenIdsAreRejectedCleanly() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // None of these is a token the plugin issues. Each must be answered like any other invalid
    // token — in particular ids ending in ".revoked", a key space Keycloak reserves in the
    // single-use store and answers with an exception (formerly an HTTP 500).
    for (String token :
        List.of(
            "lt:x.revoked",
            "x.revoked",
            "lt:00000000-0000-0000-0000-000000000000.revoked",
            "lt:lt:00000000-0000-0000-0000-000000000000",
            "lt:not-a-uuid",
            "lt:v2.",
            "lt:v2.x.revoked",
            "lt:")) {
      redeem(token)
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_grant"))
          .body("error_description", equalTo("Invalid or expired login token"));
    }
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
}
