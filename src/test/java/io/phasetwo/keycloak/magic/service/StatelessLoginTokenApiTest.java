package io.phasetwo.keycloak.magic.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.magic.LoginTokenTestSupport;
import io.phasetwo.keycloak.magic.StatelessLoginTokenServer;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.Testcontainers;

/**
 * Browser-flow tests for the stateless Login Token format ({@code lt:v2.…}).
 *
 * <p>The format is selected on the server only, so {@link StatelessLoginTokenServer} starts Keycloak with the SPI
 * option {@code legacy=false}; every token it mints with an ordinary request is stateless.
 */
@JBossLog
@ExtendWith(StatelessLoginTokenServer.class)
class StatelessLoginTokenApiTest extends AbstractLoginTokenApiTest {

  @Test
  void statelessToken_redeemsInBrowserFlowWithRequestedLoa() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest req = buildRequest(2, null);
    String loginHint = postLoginTokenRequest(req);
    assertTrue(
        loginHint.matches(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN),
        "login_hint must use the stateless format: " + loginHint);

    Map<String, Object> claims =
        redeemAndDecodeIdToken(
            buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI, "scope", "openid")));

    assertEquals(
        "2",
        String.valueOf(claims.get("acr")),
        "acr claim must equal the loa carried inside the stateless token");
  }

  @Test
  void statelessTokenSingleUse_cannotBeRedeemedTwiceInBrowserFlow() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-api-test-setup.json");
    LoginTokenTestSupport.addLoginTokenKeyProvider(keycloak, TEST_REALM);

    LoginTokenRequest req = buildRequest(null, null);
    req.setMaxUses(1);
    String link = buildOidcUrl(postLoginTokenRequest(req), Map.of("redirect_uri", REDIRECT_URI));

    assertNotNull(followLinkToCode(link), "first redemption must return an authorization code");

    assertUsedUpTokenIsRefused(link);
  }

  @Test
  void usedUpStatelessToken_showsLoginFormWithMessageAndEmptyUsername() throws Exception {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/login-token-invalid-hint-test-setup.json");

    LoginTokenRequest req = buildRequest(null, null);
    req.setMaxUses(1);
    String loginHint = postLoginTokenRequest(req);
    assertTrue(loginHint.matches(LoginTokenTestSupport.STATELESS_LOGIN_HINT_PATTERN), loginHint);

    assertUsedUpTokenShowsCleanLoginForm(loginHint);
  }
}
