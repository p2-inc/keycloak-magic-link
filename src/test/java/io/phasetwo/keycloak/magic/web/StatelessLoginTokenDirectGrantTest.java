package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.LoginTokenTestSupport;
import io.phasetwo.keycloak.magic.StatelessLoginTokenServer;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import io.restassured.path.json.JsonPath;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.ComponentRepresentation;

/**
 * Integration test for the stateless Login Token format ({@code lt:v2.…}, credential encrypted
 * into the token) on the Direct Grant path.
 *
 * <p>The format is selected on the server only, so {@link StatelessLoginTokenServer} starts Keycloak with the SPI
 * option {@code legacy=false}; every token it mints with an ordinary request is stateless.
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@ExtendWith(StatelessLoginTokenServer.class)
public class StatelessLoginTokenDirectGrantTest extends AbstractLoginTokenDirectGrantTest {

  @Test
  public void statelessTokenYieldsAccessTokenWithAmr() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

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
  public void keyProviderIsCreatedOnFirstStatelessToken() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    assertThat(LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM), hasSize(0));

    String first = mint(request());
    String second = mint(request());

    assertThat(first, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
    assertThat(second, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
    List<ComponentRepresentation> providers =
        LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM);
    assertThat(providers, hasSize(1));
    assertThat(providers.get(0).getProviderId(), equalTo("aes-generated"));
    // Below Keycloak's own key providers (100), so Keycloak never picks it for itself.
    assertThat(providers.get(0).getConfig().getFirst("priority"), equalTo("10"));

    redeem(first).then().statusCode(200);
    redeem(second).then().statusCode(200);
  }

  @Test
  public void concurrentFirstTokensShareOneKeyProvider() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    String accessToken = keycloak.tokenManager().getAccessTokenString();
    String body = Helpers.toJsonString(request());

    // Many requests race to create the provider. However the race ends, exactly one provider may
    // exist afterwards and every issued token — whichever format it got — must be redeemable.
    int requests = 12;
    ExecutorService pool = Executors.newFixedThreadPool(requests);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<String>> results = new ArrayList<>();
    for (int i = 0; i < requests; i++) {
      results.add(
          pool.submit(
              () -> {
                start.await();
                return given()
                    .baseUri(getAuthUrl())
                    .auth()
                    .oauth2(accessToken)
                    .contentType("application/json")
                    .body(body)
                    .post(LOGIN_TOKEN_PATH)
                    .then()
                    .statusCode(200)
                    .extract()
                    .jsonPath()
                    .getString("login_hint");
              }));
    }
    start.countDown();
    List<String> loginHints = new ArrayList<>();
    for (Future<String> result : results) {
      loginHints.add(result.get());
    }
    pool.shutdown();

    assertThat(LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM), hasSize(1));
    for (String loginHint : loginHints) {
      redeem(loginHint).then().statusCode(200);
    }
    // Once the provider exists, tokens are stateless.
    assertThat(mint(request()), matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
  }

  @Test
  public void statelessTokenIsAcceptedWithoutLoginHintPrefix() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

    redeem(loginHint.substring("lt:".length())).then().statusCode(200);
  }

  @Test
  public void statelessTokenWithoutUseLimitIsReusable() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

    for (int i = 0; i < 3; i++) {
      redeem(loginHint).then().statusCode(200);
    }
  }

  @Test
  public void statelessSingleUseTokenCannotBeRedeemedTwice() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = request();
    request.setMaxUses(1);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenMapsLegacyReusableFlagToSingleUse() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = request();
    request.setReusable(false);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenHonoursMaxUses() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = request();
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

    String loginHint = mint(request());
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

    LoginTokenRequest request = request();
    request.setExpirationSeconds(1);
    String loginHint = mint(request);

    Thread.sleep(2500);

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenBoundToOtherClientIsRejected() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = request();
    request.setClientId("dg-other-client");
    String loginHint = mint(request);
    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void unboundStatelessTokenIsRejectedByDefault() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest request = request();
    request.setClientId(null);
    String loginHint = mint(request);

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenStopsWorkingWhenItsKeyIsRemoved() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    String keyProviderId = LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());
    redeem(loginHint).then().statusCode(200);

    // Removing the key provider invalidates every outstanding stateless token.
    keycloak.realm(TEST_REALM).components().component(keyProviderId).remove();

    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));

    // The next stateless token gets a fresh provider with a new key; the old token stays dead.
    String afterRemoval = mint(request());
    assertThat(afterRemoval, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
    redeem(afterRemoval).then().statusCode(200);
    redeem(loginHint).then().statusCode(401).body("error", equalTo("invalid_grant"));
  }

  @Test
  public void statelessTokenSurvivesKeyRotation() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM, 10);

    String issuedUnderOldKey = mint(request());

    // Rotation: a second provider with a higher priority encrypts new tokens, the old one stays
    // enabled so tokens issued under it remain valid.
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM, 20);
    String issuedUnderNewKey = mint(request());

    redeem(issuedUnderOldKey).then().statusCode(200);
    redeem(issuedUnderNewKey).then().statusCode(200);
  }

  @Test
  public void requestCannotSelectTheLegacyFormat() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");

    // The format is a server setting. A "legacy" field in the body is not part of the API and is
    // ignored like any other unknown field.
    String loginHint = mintRaw("{\"email\":\"%s\",\"client_id\":\"%s\",\"legacy\":true}");

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200);
  }

  @Test
  public void legacyTokensStayValidWhileStatelessTokensAreIssued() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    // The server setting only decides what is issued. A legacy token — here obtained through the
    // fallback of a disabled key provider — is accepted next to stateless ones.
    String disabledProviderId =
        LoginTokenTestSupport.addDisabledLoginTokenKeyProvider(keycloak, TEST_REALM);
    String legacy = mint(request());
    assertThat(legacy, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));

    keycloak.realm(TEST_REALM).components().component(disabledProviderId).remove();
    String stateless = mint(request());
    assertThat(stateless, matchesPattern(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN));

    redeem(stateless).then().statusCode(200);
    redeem(legacy).then().statusCode(200);
  }

  @Test
  public void legacyFormatIsTheFallbackWhenKeyProviderIsDisabled() throws Exception {
    importRealm("/realms/direct-grant-login-token-test-setup.json");
    // A disabled provider is an administrator's decision: it is neither used nor replaced, and
    // issuing does not fail — the caller gets a working legacy token instead.
    LoginTokenTestSupport.addDisabledLoginTokenKeyProvider(keycloak, TEST_REALM);

    String loginHint = mint(request());

    assertThat(loginHint, matchesPattern(LoginTokenTestSupport.LEGACY_LOGIN_HINT_PATTERN));
    redeem(loginHint).then().statusCode(200).body("access_token", not(emptyOrNullString()));
    assertThat(LoginTokenTestSupport.loginTokenKeyProviders(keycloak, TEST_REALM), hasSize(1));
  }
}
