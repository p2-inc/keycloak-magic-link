package io.phasetwo.keycloak.magic;

import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the Magic Link REST API endpoint.
 *
 * <p>The test realm ({@code magic-link-api-test-setup.json}) contains a flow
 * {@code "magic-link-loa-flow"} with a {@code conditional-loa-authenticator} configured at
 * level 2 and an {@code ext-magic-form} execution as direct siblings. This lets us verify:
 *
 * <ul>
 *   <li>Explicit {@code loa} parameter ends up as the {@code acr} claim in the ID token.</li>
 *   <li>When only {@code flow_id} is supplied, the level is read from the
 *       {@code ConditionalLoaAuthenticator} sibling in the subflow.</li>
 *   <li>An explicit {@code loa} always overrides the flow-derived level — the bug fixed in
 *       {@code MagicLinkActionTokenHandler}.</li>
 *   <li>A single-use link ({@code reusable=false}) cannot be redeemed a second time.</li>
 * </ul>
 */
@JBossLog
@Testcontainers
class MagicLinkApiTest extends AbstractMagicLinkTest {

    private static final String TEST_REALM   = "test-realm-api";
    private static final String TEST_CLIENT  = "api-test-client";
    private static final String REDIRECT_URI = "http://localhost/callback";
    private static final String TEST_EMAIL   = "testuser@phasetwo.io";

    /**
     * Alias of the flow used for {@code flow_id} in the LOA tests.
     * {@code conditional-loa-authenticator} and {@code ext-magic-form} are direct siblings
     * in this top-level flow, so {@link #resolveFlowId} only needs {@code getFlows()}.
     */
    private static final String LOA_FLOW_ALIAS = "magic-link-loa-flow";

    private static final String MAGIC_LINK_PATH = "realms/" + TEST_REALM + "/magic-link";
    private static final String TOKEN_PATH      = "realms/" + TEST_REALM + "/protocol/openid-connect/token";

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void createMagicLink_returnsLinkAndUserId() {
        importRealm("/realms/magic-link-api-test-setup.json");

        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "email",        TEST_EMAIL,
                "client_id",    TEST_CLIENT,
                "redirect_uri", REDIRECT_URI
            ))
            .post(MAGIC_LINK_PATH)
            .then()
            .statusCode(200)
            .body("link",    not(emptyOrNullString()))
            .body("user_id", not(emptyOrNullString()))
            .body("sent",    is(false));
    }

    @Test
    void createMagicLinkWithExplicitLoa_acrClaimMatchesRequestedLoa() throws Exception {
        importRealm("/realms/magic-link-api-test-setup.json");

        String magicLink = createMagicLink(Map.of(
            "scope", "openid",
            "loa",   2
        ));

        Map<String, Object> claims = redeemAndDecodeIdToken(magicLink);
        assertEquals("2", String.valueOf(claims.get("acr")),
            "acr must equal the loa value explicitly set when creating the magic link");
    }

    @Test
    void createMagicLinkWithFlowId_loaReadFromConditionalLoaAuthenticator() throws Exception {
        importRealm("/realms/magic-link-api-test-setup.json");
        String loaFlowId = resolveFlowId(LOA_FLOW_ALIAS);

        // No explicit loa — level must be read from the ConditionalLoaAuthenticator in the flow
        String magicLink = createMagicLink(Map.of(
            "scope",   "openid",
            "flow_id", loaFlowId
        ));

        Map<String, Object> claims = redeemAndDecodeIdToken(magicLink);
        assertEquals("2", String.valueOf(claims.get("acr")),
            "acr must equal the level configured in the ConditionalLoaAuthenticator " +
            "when no explicit loa is provided but flow_id is set");
    }

    @Test
    void createMagicLinkWithExplicitLoa_overridesFlowLoa() throws Exception {
        importRealm("/realms/magic-link-api-test-setup.json");
        String loaFlowId = resolveFlowId(LOA_FLOW_ALIAS);

        // The subflow's ConditionalLoaAuthenticator is at level 2, but we explicitly request 1.
        // The explicit value must win — this is the bug fixed in MagicLinkActionTokenHandler.
        String magicLink = createMagicLink(Map.of(
            "scope",   "openid",
            "loa",     1,
            "flow_id", loaFlowId
        ));

        Map<String, Object> claims = redeemAndDecodeIdToken(magicLink);
        assertEquals("1", String.valueOf(claims.get("acr")),
            "explicit loa=1 must override the flow-derived level 2");
    }

    @Test
    void singleUseMagicLink_cannotBeRedeemedTwice() throws Exception {
        importRealm("/realms/magic-link-api-test-setup.json");

        String magicLink = createMagicLink(Map.of("reusable", false));

        // First redemption must succeed
        String code = followMagicLinkToCode(magicLink);
        assertNotNull(code, "first redemption must return an authorization code");

        // Second redemption must be rejected
        String secondLocation = given()
            .redirects().follow(false)
            .get(magicLink)
            .then()
            .extract().header("Location");

        assertTrue(
            secondLocation == null || secondLocation.contains("error"),
            "second redemption of a single-use magic link must be rejected (Location: " + secondLocation + ")"
        );
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Looks up the Keycloak-assigned UUID of a top-level authentication flow by its alias.
     * Uses the Keycloak admin client's {@code getFlows()} which returns only top-level flows
     * but reliably works in Keycloak 26.x.
     */
    private String resolveFlowId(String flowAlias) {
        return keycloak.realm(TEST_REALM).flows().getFlows().stream()
            .filter(f -> flowAlias.equals(f.getAlias()))
            .findFirst()
            .map(f -> f.getId())
            .orElseThrow(() -> new AssertionError(
                "Flow '" + flowAlias + "' not found in realm " + TEST_REALM));
    }

    private String createMagicLink(Map<String, Object> overrides) {
        var body = new java.util.HashMap<String, Object>();
        body.put("email",        TEST_EMAIL);
        body.put("client_id",    TEST_CLIENT);
        body.put("redirect_uri", REDIRECT_URI);
        body.putAll(overrides);

        return given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(body)
            .post(MAGIC_LINK_PATH)
            .then()
            .statusCode(200)
            .extract().jsonPath().getString("link");
    }

    private Map<String, Object> redeemAndDecodeIdToken(String magicLink) throws Exception {
        String code = followMagicLinkToCode(magicLink);
        assertNotNull(code, "authorization code must be present after redeeming the magic link");

        var tokenResponse = given()
            .baseUri(getAuthUrl())
            .contentType("application/x-www-form-urlencoded")
            .formParam("grant_type",   "authorization_code")
            .formParam("client_id",    TEST_CLIENT)
            .formParam("code",         code)
            .formParam("redirect_uri", REDIRECT_URI)
            .post(TOKEN_PATH)
            .then()
            .statusCode(200)
            .extract().response();

        String idToken = tokenResponse.jsonPath().getString("id_token");
        assertNotNull(idToken, "id_token must be present (scope=openid was requested)");
        return decodeJwtPayload(idToken);
    }

    /**
     * Follows the Keycloak action-token redirect chain until the {@link #REDIRECT_URI} is
     * reached with a {@code code} query parameter, then returns that code.
     *
     * <p>Uses {@link java.net.http.HttpClient} with a {@link java.net.CookieManager} so that
     * Keycloak's {@code AUTH_SESSION_ID} cookie is automatically maintained between requests.
     * This is required because Keycloak 26.x routes post-authentication through a
     * {@code /login-actions/required-action} page that looks up the auth session via cookie.
     * That page auto-submits a form via JavaScript; this method parses and POSTs the form.
     */
    private String followMagicLinkToCode(String magicLinkUrl) throws Exception {
        var cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
        var httpClient = java.net.http.HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
            .build();

        String nextUrl    = magicLinkUrl;
        String nextMethod = "GET";
        String nextBody   = null;
        StringBuilder debug = new StringBuilder("Redirect chain:\n");

        for (int attempt = 0; attempt < 15; attempt++) {
            java.net.http.HttpRequest.Builder reqBuilder =
                java.net.http.HttpRequest.newBuilder().uri(URI.create(nextUrl));

            if ("POST".equals(nextMethod)) {
                String body = nextBody != null ? nextBody : "";
                reqBuilder.header("Content-Type", "application/x-www-form-urlencoded")
                          .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body));
            } else {
                reqBuilder.GET();
            }

            var response = httpClient.send(reqBuilder.build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            String location = response.headers().firstValue("Location").orElse(null);
            debug.append(String.format("  [%d] %s %s → %d  Location: %s%n",
                attempt, nextMethod, nextUrl, status, location));

            nextMethod = "GET";
            nextBody   = null;

            if (status >= 300 && status < 400) {
                if (location == null) break;
                if (location.contains("code=")) return extractQueryParam(location, "code");
                nextUrl = location;
            } else if (status == 200) {
                // Keycloak 26.x shows a required-action HTML page that auto-submits via JS.
                // Parse the form action and hidden fields, then POST.
                String html = response.body();
                var actionMatch = java.util.regex.Pattern
                    .compile("action=\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(html);
                if (!actionMatch.find()) {
                    debug.append("  No form action found in HTML — giving up.\n");
                    break;
                }
                nextUrl    = actionMatch.group(1).replace("&amp;", "&");
                nextMethod = "POST";

                var sb = new StringBuilder();
                var inputMatch = java.util.regex.Pattern
                    .compile("<input([^>]*)>", java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(html);
                while (inputMatch.find()) {
                    String tag = inputMatch.group(1);
                    var nm = java.util.regex.Pattern.compile("name=\"([^\"]+)\"").matcher(tag);
                    var vm = java.util.regex.Pattern.compile("value=\"([^\"]*)\"").matcher(tag);
                    if (nm.find() && vm.find()) {
                        if (sb.length() > 0) sb.append('&');
                        sb.append(java.net.URLEncoder.encode(nm.group(1), java.nio.charset.StandardCharsets.UTF_8))
                          .append('=')
                          .append(java.net.URLEncoder.encode(vm.group(1), java.nio.charset.StandardCharsets.UTF_8));
                    }
                }
                nextBody = sb.toString();
                debug.append(String.format("  → POST form to: %s%n", nextUrl));
            } else {
                debug.append(String.format("  Unexpected status %d — giving up.%n", status));
                break;
            }
        }
        throw new AssertionError("Authorization code not found in magic link redirect chain.\n" + debug);
    }

    private static String extractQueryParam(String url, String param) throws Exception {
        String query = new URI(url).getQuery();
        if (query == null) return null;
        for (String part : query.split("&")) {
            if (part.startsWith(param + "=")) {
                return part.substring(param.length() + 1);
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeJwtPayload(String jwt) throws IOException {
        byte[] decoded = Base64.getUrlDecoder().decode(jwt.split("\\.")[1]);
        return JsonSerialization.readValue(decoded, Map.class);
    }
}
