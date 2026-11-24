package io.phasetwo.keycloak.magic.service;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.LoginTokenRequest;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * Shared fixtures for the Login Token REST API and browser-flow tests.
 *
 * <p>Which token format the server issues is a server setting, so the tests are split by it:
 * {@link LoginTokenApiTest} runs against the default (legacy format), {@link
 * StatelessLoginTokenApiTest} against a server switched to stateless tokens.
 */
abstract class AbstractLoginTokenApiTest extends AbstractMagicLinkTest {

  protected static final String TEST_REALM = "test-realm-v2";
  protected static final String TEST_CLIENT = "v2-test-client";
  protected static final String REDIRECT_URI = "http://localhost/callback";
  protected static final String TEST_EMAIL = "testuser@phasetwo.io";

  protected static final String LOGIN_TOKEN_PATH = "realms/" + TEST_REALM + "/login-token";
  protected static final String TOKEN_PATH =
      "realms/" + TEST_REALM + "/protocol/openid-connect/token";
  protected static final String AUTH_PATH =
      "realms/" + TEST_REALM + "/protocol/openid-connect/auth";

  protected LoginTokenRequest buildRequest(Integer loa, Boolean reusable) {
    LoginTokenRequest req = new LoginTokenRequest();
    req.setEmail(TEST_EMAIL);
    req.setClientId(TEST_CLIENT);
    req.setForceSessionLoa(loa);
    req.setReusable(reusable);
    return req;
  }

  protected String createLoginToken(Map<String, String> additionalParams) throws Exception {
    return createLoginToken(additionalParams, null, null);
  }

  protected String createLoginToken(
      Map<String, String> additionalParams, Integer loa, Boolean reusable) throws Exception {
    String loginHint = postLoginTokenRequest(buildRequest(loa, reusable));
    Map<String, String> params = new HashMap<>();
    params.put("redirect_uri", REDIRECT_URI);
    params.putAll(additionalParams);
    return buildOidcUrl(loginHint, params);
  }

  /** Posts to {@code /login-token} and returns the {@code login_hint} from the response. */
  protected String postLoginTokenRequest(LoginTokenRequest req) throws Exception {
    return given()
        .baseUri(getAuthUrl())
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString())
        .contentType("application/json")
        .body(Helpers.toJsonString(req))
        .post(LOGIN_TOKEN_PATH)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getString("login_hint");
  }

  /**
   * Constructs an OIDC authorization URL from the returned {@code login_hint}.
   * The caller is responsible for PKCE, state, nonce, etc. in the additionalParams.
   * {@code prompt=login} is always added to prevent session short-circuiting.
   */
  protected String buildOidcUrl(String loginHint, Map<String, String> additionalParams) {
    String base = getAuthUrl().endsWith("/") ? getAuthUrl() : getAuthUrl() + "/";
    StringBuilder url =
        new StringBuilder(base)
            .append(AUTH_PATH)
            .append("?client_id=")
            .append(TEST_CLIENT)
            .append("&response_type=code")
            .append("&login_hint=")
            .append(loginHint)
            .append("&prompt=login");
    additionalParams.forEach((k, v) -> url.append("&").append(k).append("=").append(v));
    return url.toString();
  }

  protected Map<String, Object> redeemAndDecodeIdToken(String link) throws Exception {
    String code = followLinkToCode(link);
    assertNotNull(code, "authorization code must be present");

    var tokenResponse =
        given()
            .baseUri(getAuthUrl())
            .contentType("application/x-www-form-urlencoded")
            .formParam("grant_type", "authorization_code")
            .formParam("client_id", TEST_CLIENT)
            .formParam("code", code)
            .formParam("redirect_uri", REDIRECT_URI)
            .post(TOKEN_PATH)
            .then()
            .statusCode(200)
            .extract()
            .response();

    String idToken = tokenResponse.jsonPath().getString("id_token");
    assertNotNull(idToken, "id_token must be present (scope=openid was requested)");
    return decodeJwtPayload(idToken);
  }

  /**
   * Follows Keycloak redirects from an authorization URL until the first HTML page. Cookies are
   * kept so the auth session survives the redirect onto the login form.
   */
  protected String followUntilPage(String startUrl) throws Exception {
    var cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
    var httpClient =
        java.net.http.HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
            .build();

    String nextUrl = startUrl;
    var debug = new StringBuilder("Redirect chain:\n");
    for (int attempt = 0; attempt < 10; attempt++) {
      var response =
          httpClient.send(
              java.net.http.HttpRequest.newBuilder().uri(URI.create(nextUrl)).GET().build(),
              java.net.http.HttpResponse.BodyHandlers.ofString());
      int status = response.statusCode();
      String location = response.headers().firstValue("Location").orElse(null);
      debug.append(
          String.format("  [%d] GET %s → %d  Location: %s%n", attempt, nextUrl, status, location));
      if (status >= 300 && status < 400) {
        if (location == null) {
          break;
        }
        nextUrl = location;
        continue;
      }
      if (status == 200) {
        return response.body();
      }
      debug.append("  Response body: ").append(response.body()).append("\n");
      break;
    }
    throw new AssertionError("Login page not reached.\n" + debug);
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
  protected String followLinkToCode(String startUrl) throws Exception {
    var cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
    var httpClient =
        java.net.http.HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
            .build();

    String nextUrl = startUrl;
    String nextMethod = "GET";
    String nextBody = null;
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

      var response =
          httpClient.send(reqBuilder.build(), java.net.http.HttpResponse.BodyHandlers.ofString());
      int status = response.statusCode();
      String location = response.headers().firstValue("Location").orElse(null);
      debug.append(
          String.format(
              "  [%d] %s %s → %d  Location: %s%n", attempt, nextMethod, nextUrl, status, location));

      nextMethod = "GET";
      nextBody = null;

      if (status >= 300 && status < 400) {
        if (location == null) break;
        if (location.contains("code=")) return extractQueryParam(location, "code");
        nextUrl = location;
      } else if (status == 200) {
        // Keycloak 26.x may show a required-action page that auto-submits via JS.
        // Parse the form action and hidden fields, then POST them.
        String html = response.body();
        var actionMatch =
            java.util.regex.Pattern.compile(
                    "action=\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(html);
        if (!actionMatch.find()) {
          debug.append("  No form action found in HTML — giving up.\n");
          break;
        }
        nextUrl = actionMatch.group(1).replace("&amp;", "&");
        nextMethod = "POST";

        var sb = new StringBuilder();
        var inputMatch =
            java.util.regex.Pattern.compile(
                    "<input([^>]*)>", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(html);
        while (inputMatch.find()) {
          String tag = inputMatch.group(1);
          var nm = java.util.regex.Pattern.compile("name=\"([^\"]+)\"").matcher(tag);
          var vm = java.util.regex.Pattern.compile("value=\"([^\"]*)\"").matcher(tag);
          if (nm.find() && vm.find()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(
                    java.net.URLEncoder.encode(
                        nm.group(1), java.nio.charset.StandardCharsets.UTF_8))
                .append('=')
                .append(
                    java.net.URLEncoder.encode(
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
    throw new AssertionError(
        "Authorization code not found in login token redirect chain.\n" + debug);
  }

  protected static String extractQueryParam(String url, String param) throws Exception {
    String query = new URI(url).getQuery();
    if (query == null) return null;
    for (String part : query.split("&")) {
      if (part.startsWith(param + "=")) return part.substring(param.length() + 1);
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  protected static Map<String, Object> decodeJwtPayload(String jwt) throws IOException {
    byte[] decoded = Base64.getUrlDecoder().decode(jwt.split("\\.")[1]);
    return JsonSerialization.readValue(decoded, Map.class);
  }

  protected void assertUsedUpTokenShowsCleanLoginForm(String loginHint) throws Exception {
    String link = buildOidcUrl(loginHint, Map.of("redirect_uri", REDIRECT_URI));
    assertNotNull(followLinkToCode(link), "first redemption must return an authorization code");

    String html = followUntilPage(link);

    assertTrue(html.contains("name=\"username\""), "username form must be shown");
    assertTrue(
        html.contains("Invalid or expired login token. Please try again."),
        "the used-up token must be reported like an invalid one");
    assertFalse(html.contains(loginHint), "the token must not appear anywhere in the login page");
  }

  /** Second redemption must not yield an authorization code. */
  protected void assertUsedUpTokenIsRefused(String link) {
    var second = given().redirects().follow(false).get(link);
    String location = second.header("Location");
    assertTrue(second.statusCode() < 500, "must not be a server error: " + second.statusCode());
    assertTrue(
        location == null || !location.contains("code="),
        "second redemption of a single-use token must not return a code (Location: "
            + location
            + ")");
  }
}
