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
 * Cypress-based integration tests for Magic Link v2 user-switch behaviour.
 *
 * <p>Two users (User A and User B) are created in the test realm. The browser flow has the
 * Magic Link Verifier placed <em>before</em> the Cookie authenticator so that the verifier
 * always evaluates {@code login_hint} before an existing session can short-circuit the flow.
 *
 * <p>Three scenarios are verified:
 * <ol>
 *   <li><b>Auto-logout (default):</b> Opening User B's link while User A is logged in silently
 *       expires the session cookies and completes authentication for User B — no screen shown.</li>
 *   <li><b>Confirmation form ({@code confirm_user_switch=true}):</b> The confirmation page is
 *       displayed; clicking "Sign out and continue" completes the flow for User B.</li>
 *   <li><b>Cancel:</b> Clicking "Cancel" on the confirmation page returns
 *       {@code error=access_denied} to the client.</li>
 * </ol>
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class MagicLinkV2UserSwitchTest extends AbstractMagicLinkTest {

    private static final String TEST_REALM  = "test-realm-v2-user-switch";
    private static final String TEST_CLIENT = "v2-user-switch-client";
    private static final String V2_PATH     = "realms/" + TEST_REALM + "/magic-link-v2";

    private static final String USER_A_EMAIL = "usera@phasetwo.io";
    private static final String USER_B_EMAIL = "userb@phasetwo.io";

    @TestFactory
    public List<DynamicContainer> testUserSwitchBehaviour()
            throws IOException, InterruptedException, TimeoutException,
                   com.fasterxml.jackson.core.JsonProcessingException {

        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/magic-link-v2-user-switch-test-setup.json");

        String redirectUri = "http://host.testcontainers.internal:"
                + container.getHttpPort() + "/callback";

        // User A link — reusable so it can establish a User A session in each Cypress test.
        String linkA = generateLink(USER_A_EMAIL, redirectUri, true, false);

        // User B — auto-logout (default, confirm_user_switch=false)
        String linkBAutoLogout = generateLink(USER_B_EMAIL, redirectUri, false, false);

        // User B — confirmation form, "Sign out and continue"
        String linkBConfirm = generateLink(USER_B_EMAIL, redirectUri, false, true);

        // User B — confirmation form, "Cancel"
        String linkBCancel  = generateLink(USER_B_EMAIL, redirectUri, false, true);

        log.info("User A link (reusable):       " + linkA);
        log.info("User B link (auto-logout):    " + linkBAutoLogout);
        log.info("User B link (confirm/continue): " + linkBConfirm);
        log.info("User B link (confirm/cancel): " + linkBCancel);

        return runCypressTests(
                "cypress/e2e/magic-link-v2-user-switch.cy.ts",
                Map.of(
                        "LINK_USER_A",         linkA,
                        "LINK_USER_B_AUTO",    linkBAutoLogout,
                        "LINK_USER_B_CONFIRM", linkBConfirm,
                        "LINK_USER_B_CANCEL",  linkBCancel
                )
        );
    }

    private String generateLink(String email, String redirectUri,
                                boolean reusable, boolean confirmUserSwitch)
            throws com.fasterxml.jackson.core.JsonProcessingException {
        MagicLinkV2Request req = new MagicLinkV2Request();
        req.setEmail(email);
        req.setClientId(TEST_CLIENT);
        req.setReusable(reusable);
        req.setConfirmUserSwitch(confirmUserSwitch);
        req.setAdditionalParameters(Map.of(
                "redirect_uri", redirectUri,
                "scope", "openid"
        ));

        String link = given()
                .baseUri(getAuthUrl())
                .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
                .contentType("application/json")
                .body(Helpers.toJsonString(req))
                .post(V2_PATH)
                .then()
                .statusCode(200)
                .extract().jsonPath().getString("link");

        assertThat(link, not(emptyOrNullString()));

        // Cypress runs in Docker: replace localhost with host.testcontainers.internal.
        return link.replace(
                "http://localhost:" + container.getHttpPort(),
                "http://host.testcontainers.internal:" + container.getHttpPort());
    }
}
