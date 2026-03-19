package io.phasetwo.keycloak.magic.service;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

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
class LoginTokenApiTest extends AbstractMagicLinkTest {

    private static final String TEST_REALM          = "test-realm-v2";
    private static final String TEST_CLIENT         = "v2-test-client";
    private static final String REDIRECT_URI        = "http://localhost/callback";
    private static final String TEST_EMAIL          = "testuser@phasetwo.io";

    private static final String LOGIN_TOKEN_PATH    = "realms/" + TEST_REALM + "/login-token";
    private static final String TOKEN_PATH          = "realms/" + TEST_REALM + "/protocol/openid-connect/token";
    private static final String AUTH_PATH           = "realms/" + TEST_REALM + "/protocol/openid-connect/auth";

    // -------------------------------------------------------------------------
    // API validation tests
    // -------------------------------------------------------------------------

    @Test
    void createLoginToken_returnsLoginHintAndUserId() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/login-token-api-test-setup.json");

        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "email",     TEST_EMAIL,
                "client_id", TEST_CLIENT
            ))
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

        assertTrue(loginHint.startsWith("lt:"),
            "login_hint must start with 'lt:', got: " + loginHint);
    }

    @Test
    void createLoginToken_missingClientId_returnsBadRequest() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/login-token-api-test-setup.json");

        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of("email", TEST_EMAIL))
            .post(LOGIN_TOKEN_PATH)
            .then()
            .statusCode(400);
    }

    @Test
    void createLoginToken_unknownUser_returnsNotFound() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/login-token-api-test-setup.json");

        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "email",     "nobody@example.com",
                "client_id", TEST_CLIENT
            ))
            .post(LOGIN_TOKEN_PATH)
            .then()
            .statusCode(404);
    }

    @Test
    void createLoginToken_withUserId_returnsLoginHint() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/login-token-api-test-setup.json");

        String userId = keycloak.realm(TEST_REALM).users()
            .searchByEmail(TEST_EMAIL, true).get(0).getId();

        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "user_id",   userId,
                "client_id", TEST_CLIENT
            ))
            .post(LOGIN_TOKEN_PATH)
            .then()
            .statusCode(200)
            .body("login_hint", not(emptyOrNullString()));
    }

    @Test
    void createLoginToken_userId_takesPrecedenceOverEmail() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        importRealm("/realms/login-token-api-test-setup.json");

        String userId = keycloak.realm(TEST_REALM).users()
            .searchByEmail(TEST_EMAIL, true).get(0).getId();

        // email points to a non-existent user — if user_id were ignored this would return 404
        given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "user_id",   userId,
                "email",     "nobody@example.com",
                "client_id", TEST_CLIENT
            ))
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
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Map.of(
                "user_id",   "00000000-0000-0000-0000-000000000000",
                "client_id", TEST_CLIENT
            ))
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

        assertEquals("2", String.valueOf(claims.get("acr")),
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
        String secondLocation = given()
            .redirects().follow(false)
            .get(link)
            .then()
            .extract().header("Location");

        assertTrue(
            secondLocation == null || secondLocation.contains("error"),
            "second redemption of a single-use login token must be rejected (Location: " + secondLocation + ")");
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

        UserRepresentation user = Helpers.createUser(
            keycloak, TEST_REALM, "unverified@test.com", "unverified@test.com",
            "Unverified", "User");

        UserRepresentation before = keycloak.realm(TEST_REALM).users()
            .get(user.getId()).toRepresentation();
        assertFalse(Boolean.TRUE.equals(before.isEmailVerified()),
            "pre-condition: email must not be verified before the link is followed");

        LoginTokenRequest req = new LoginTokenRequest();
        req.setEmail("unverified@test.com");
        req.setClientId(TEST_CLIENT);
        req.setSetEmailVerified(true);

        String loginHint = postLoginTokenRequest(req);
        String link = buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI, "scope", "openid"));
        followLinkToCode(link);

        UserRepresentation after = keycloak.realm(TEST_REALM).users()
            .get(user.getId()).toRepresentation();
        assertTrue(Boolean.TRUE.equals(after.isEmailVerified()),
            "email must be marked verified after following a link with set_email_verified=true");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private LoginTokenRequest buildRequest(Integer loa, Boolean reusable) {
        LoginTokenRequest req = new LoginTokenRequest();
        req.setEmail(TEST_EMAIL);
        req.setClientId(TEST_CLIENT);
        req.setForceSessionLoa(loa);
        req.setReusable(reusable);
        return req;
    }

    private String createLoginToken(Map<String, String> additionalParams) throws Exception {
        return createLoginToken(additionalParams, null, null);
    }

    private String createLoginToken(
            Map<String, String> additionalParams,
            Integer loa,
            Boolean reusable) throws Exception {
        String loginHint = postLoginTokenRequest(buildRequest(loa, reusable));
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", REDIRECT_URI);
        params.putAll(additionalParams);
        return buildOidcUrl(loginHint, params);
    }

    /** Posts to {@code /login-token} and returns the {@code login_hint} from the response. */
    private String postLoginTokenRequest(LoginTokenRequest req) throws Exception {
        return given()
            .baseUri(getAuthUrl())
            .auth().oauth2(keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(Helpers.toJsonString(req))
            .post(LOGIN_TOKEN_PATH)
            .then()
            .statusCode(200)
            .extract().jsonPath().getString("login_hint");
    }

    /**
     * Constructs an OIDC authorization URL from the returned {@code login_hint}.
     * The caller is responsible for PKCE, state, nonce, etc. in the additionalParams.
     * {@code prompt=login} is always added to prevent session short-circuiting.
     */
    private String buildOidcUrl(String loginHint, Map<String, String> additionalParams) {
        StringBuilder url = new StringBuilder(getAuthUrl())
            .append(AUTH_PATH)
            .append("?client_id=").append(TEST_CLIENT)
            .append("&response_type=code")
            .append("&login_hint=").append(loginHint)
            .append("&prompt=login");
        additionalParams.forEach((k, v) -> url.append("&").append(k).append("=").append(v));
        return url.toString();
    }

    private Map<String, Object> redeemAndDecodeIdToken(String link) throws Exception {
        String code = followLinkToCode(link);
        assertNotNull(code, "authorization code must be present");

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
     * Follows all Keycloak redirects starting from the login token authorization URL until the
     * final redirect to {@link #REDIRECT_URI} containing a {@code code} query parameter.
     *
     * <p>A fresh {@link java.net.CookieManager} is used on every call so that sessions from
     * previous calls do not interfere (important for the single-use and reusable tests).
     * The {@code AUTH_SESSION_ID} cookie is maintained within the chain so that Keycloak 26.x's
     * required-action page can look up the auth session correctly.
     */
    private String followLinkToCode(String startUrl) throws Exception {
        var cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
        var httpClient = java.net.http.HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
            .build();

        String nextUrl    = startUrl;
        String nextMethod = "GET";
        String nextBody   = null;
        var debug = new StringBuilder("Redirect chain:\n");

        for (int attempt = 0; attempt < 15; attempt++) {
            var reqBuilder = java.net.http.HttpRequest.newBuilder().uri(URI.create(nextUrl));
            if ("POST".equals(nextMethod)) {
                String body = nextBody != null ? nextBody : "";
                reqBuilder
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body));
            } else {
                reqBuilder.GET();
            }

            var response = httpClient.send(
                reqBuilder.build(), java.net.http.HttpResponse.BodyHandlers.ofString());
            int    status   = response.statusCode();
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
                // Keycloak 26.x may show a required-action page that auto-submits via JS.
                // Parse the form action and hidden fields, then POST them.
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
                        sb.append(java.net.URLEncoder.encode(
                                nm.group(1), java.nio.charset.StandardCharsets.UTF_8))
                          .append('=')
                          .append(java.net.URLEncoder.encode(
                                vm.group(1), java.nio.charset.StandardCharsets.UTF_8));
                    }
                }
                nextBody = sb.toString();
            } else {
                debug.append(String.format("  Unexpected status %d — giving up.%n", status));
                debug.append("  Response body: ").append(response.body()).append("\n");
                break;
            }
        }
        throw new AssertionError("Authorization code not found in login token redirect chain.\n" + debug);
    }

    private static String extractQueryParam(String url, String param) throws Exception {
        String query = new URI(url).getQuery();
        if (query == null) return null;
        for (String part : query.split("&")) {
            if (part.startsWith(param + "=")) return part.substring(param.length() + 1);
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeJwtPayload(String jwt) throws IOException {
        byte[] decoded = Base64.getUrlDecoder().decode(jwt.split("\\.")[1]);
        return JsonSerialization.readValue(decoded, Map.class);
    }
}
