package io.phasetwo.keycloak.magic.web;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.MagicLinkV2Request;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testcontainers.Testcontainers;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyOrNullString;

/**
 * Cypress-based integration test for the Magic Link v2 browser-flow authenticator.
 *
 * <p>Generates a v2 link via {@code POST /magic-link-v2}, passes it to the Cypress container via
 * the {@code GENERATED_MAGIC_LINK_V2} environment variable, and verifies that following the link
 * completes the browser flow and yields an authorization code.
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class MagicLinkV2GeneratedWithPostRequestTest extends AbstractMagicLinkTest {

    private static final String TEST_REALM   = "test-realm-v2";
    private static final String TEST_CLIENT  = "v2-test-client";
    private static final String MAGIC_LINK_V2_PATH = "realms/" + TEST_REALM + "/magic-link-v2";

    @TestFactory
    public List<DynamicContainer> testMagicLinkV2Creation()
            throws IOException, InterruptedException, TimeoutException {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/magic-link-v2-api-test-setup.json");

        String redirectUri = "http://host.testcontainers.internal:"
                + container.getHttpPort() + "/callback";

        MagicLinkV2Request request = new MagicLinkV2Request();
        request.setEmail("testuser@phasetwo.io");
        request.setClientId(TEST_CLIENT);

        String loginHint = given()
                .baseUri(getAuthUrl())
                .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
                .contentType("application/json")
                .body(Helpers.toJsonString(request))
                .post(MAGIC_LINK_V2_PATH)
                .then()
                .statusCode(200)
                .extract().jsonPath().getString("login_hint");

        assertThat(loginHint, not(emptyOrNullString()));

        // Build the OIDC auth URL — the caller (Cypress / CLP) owns PKCE, state, etc.
        // Cypress runs in Docker: use host.testcontainers.internal to reach Keycloak.
        String dockerBase = getAuthUrl().replace(
                "http://localhost:" + container.getHttpPort(),
                "http://host.testcontainers.internal:" + container.getHttpPort());
        String dockerLink = dockerBase + "realms/" + TEST_REALM + "/protocol/openid-connect/auth"
                + "?client_id=" + TEST_CLIENT
                + "&response_type=code"
                + "&login_hint=" + loginHint
                + "&prompt=login"
                + "&scope=openid"
                + "&redirect_uri=" + redirectUri;
        log.info("Generated v2 link (docker-reachable): " + dockerLink);

        return runCypressTests(
                "cypress/e2e/pre-generated-magic-link-v2.cy.ts",
                Map.of("GENERATED_MAGIC_LINK_V2", dockerLink)
        );
    }
}
