package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;

/**
 * Integration tests for the Activation Gate browser authenticator and the Send Activation or
 * Reset Email reset-credentials authenticator. Drives the login pages over plain HTTP (no
 * Cypress) and reads sent mail from MailHog's REST API.
 */
@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
public class ActivationAuthenticatorsTest extends AbstractMagicLinkWithMailhogTest {

  private static final String TEST_REALM = "activation-test-realm";
  private static final String TEST_CLIENT = "gate-test-client";
  private static final String REDIRECT_URI = "http://localhost/callback";

  private static final String ACTIVATED_EMAIL = "activated@phasetwo.io";
  private static final String ACTIVATED_PASSWORD = "activated-password";
  private static final String PENDING_VERIFY_EMAIL = "pending-verify@phasetwo.io";
  private static final String PENDING_MIGRATED_EMAIL = "pending-migrated@phasetwo.io";
  private static final String UNKNOWN_EMAIL = "nobody@phasetwo.io";

  // substring of the activationSentConfirmation message key
  private static final String CONFIRMATION_TEXT = "sent activation instructions";
  // substring of Keycloak's generic Messages.EMAIL_SENT info message
  private static final String GENERIC_EMAIL_SENT_TEXT = "You should receive an email shortly";

  private static final Pattern FORM_ACTION =
      Pattern.compile("<form[^>]*action=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
  private static final Pattern ACTION_TOKEN_HREF =
      Pattern.compile("href=\"([^\"]*action-token[^\"]*)\"", Pattern.CASE_INSENSITIVE);
  private static final Pattern ACTION_TOKEN_LINK =
      Pattern.compile("https?://[^\\s\"'<>\\]]+action-token[^\\s\"'<>\\]]*");

  @BeforeEach
  public void setupRealmAndClearMail() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    importRealm("/realms/activation-gate-setup.json");
    // clear MailHog so each test asserts only its own messages
    given().baseUri(mailhogUrl()).delete("/api/v1/messages").then().statusCode(200);
  }

  // ---------------------------------------------------------------------------
  // Activation Gate (browser flow)
  // ---------------------------------------------------------------------------

  @Test
  public void activatedUser_seesPasswordForm_andLogsIn() throws Exception {
    HttpClient browser = newBrowser();

    String passwordFormHtml = submitEmail(browser, ACTIVATED_EMAIL);
    assertTrue(
        passwordFormHtml.contains("name=\"password\""),
        "activated user should be shown the password form");
    assertFalse(passwordFormHtml.contains(CONFIRMATION_TEXT));

    String action = formAction(passwordFormHtml);
    HttpResponse<String> response =
        postForm(browser, action, "password=" + enc(ACTIVATED_PASSWORD));
    String location = followUntilLocationStartsWith(browser, response, REDIRECT_URI);
    assertNotNull(location, "login should complete with a redirect to the client");
    assertTrue(location.contains("code="), "authorization code expected on " + location);
  }

  @Test
  public void pendingUnverifiedUser_getsActivationEmail_notPasswordForm() throws Exception {
    HttpClient browser = newBrowser();

    String html = submitEmail(browser, PENDING_VERIFY_EMAIL);
    assertTrue(html.contains(CONFIRMATION_TEXT), "confirmation screen expected");
    assertFalse(html.contains("name=\"password\""), "no password prompt for pending accounts");

    String body = waitForMail(PENDING_VERIFY_EMAIL, 1);
    assertTrue(body.contains("needs to be activated"), "activation email body expected");
    String link = extractActionTokenLink(body);
    assertNotNull(link, "activation email must carry an action token link");
  }

  @Test
  public void unknownEmail_getsSameScreen_andNoEmail() throws Exception {
    HttpClient browser = newBrowser();

    String html = submitEmail(browser, UNKNOWN_EMAIL);
    assertTrue(html.contains(CONFIRMATION_TEXT), "unknown email must get the same screen");
    assertFalse(html.contains("name=\"password\""));

    Thread.sleep(2000); // settle time before asserting that nothing was sent
    assertEquals(0, mailCount(UNKNOWN_EMAIL), "no email may be sent for unknown addresses");
  }

  @Test
  public void resend_isThrottledByCooldown() throws Exception {
    HttpClient browser = newBrowser();

    String html = submitEmail(browser, PENDING_VERIFY_EMAIL);
    waitForMail(PENDING_VERIFY_EMAIL, 1);

    // the fixture sets a 300s cooldown, so an immediate resend must not send again
    String action = formAction(html);
    HttpResponse<String> response = postForm(browser, action, "resend=resend");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains(CONFIRMATION_TEXT));

    Thread.sleep(2000);
    assertEquals(1, mailCount(PENDING_VERIFY_EMAIL), "resend within cooldown must be a no-op");
  }

  @Test
  public void migratedUser_completesActivationViaEmailLink_thenLogsIn() throws Exception {
    HttpClient browser = newBrowser();

    submitEmail(browser, PENDING_MIGRATED_EMAIL);
    String mailBody = waitForMail(PENDING_MIGRATED_EMAIL, 1);
    String link = extractActionTokenLink(mailBody);
    assertNotNull(link);

    // open the link in a fresh "browser" (new cookie jar), like a real email click
    HttpClient emailBrowser = newBrowser();
    String newPassword = "migrated-password-1";
    String finalLocation = completeActivation(emailBrowser, link, newPassword);
    assertTrue(
        finalLocation.startsWith(REDIRECT_URI),
        "after completing the actions the user must be returned to the client, got: "
            + finalLocation);

    // account state: verified, no outstanding required actions
    UserRepresentation user =
        keycloak.realm(TEST_REALM).users().searchByEmail(PENDING_MIGRATED_EMAIL, true).get(0);
    assertTrue(user.isEmailVerified(), "email must be verified after activation");
    assertTrue(
        user.getRequiredActions() == null || user.getRequiredActions().isEmpty(),
        "no required actions may remain after activation");

    // and the gate now routes the user to the password form
    HttpClient secondLogin = newBrowser();
    String passwordFormHtml = submitEmail(secondLogin, PENDING_MIGRATED_EMAIL);
    assertTrue(passwordFormHtml.contains("name=\"password\""));
    HttpResponse<String> response =
        postForm(secondLogin, formAction(passwordFormHtml), "password=" + enc(newPassword));
    String location = followUntilLocationStartsWith(secondLogin, response, REDIRECT_URI);
    assertNotNull(location);
    assertTrue(location.contains("code="));
  }

  // ---------------------------------------------------------------------------
  // Send Activation or Reset Email (reset credentials flow)
  // ---------------------------------------------------------------------------

  @Test
  public void forgotPassword_pendingUser_receivesActivationEmail() throws Exception {
    String html = submitForgotPassword(PENDING_MIGRATED_EMAIL);
    assertTrue(html.contains(GENERIC_EMAIL_SENT_TEXT), "generic info message expected");

    String body = waitForMail(PENDING_MIGRATED_EMAIL, 1);
    assertTrue(
        body.contains("needs to be activated"),
        "pending accounts must get activation instructions, not a reset email");
  }

  @Test
  public void forgotPassword_activatedUser_receivesStandardResetEmail() throws Exception {
    String html = submitForgotPassword(ACTIVATED_EMAIL);
    assertTrue(html.contains(GENERIC_EMAIL_SENT_TEXT));

    String body = waitForMail(ACTIVATED_EMAIL, 1);
    assertFalse(body.contains("needs to be activated"));
    assertNotNull(
        extractActionTokenLink(body), "reset email must carry the standard action token link");
  }

  @Test
  public void forgotPassword_unknownEmail_showsGenericMessage_andNoEmail() throws Exception {
    String html = submitForgotPassword(UNKNOWN_EMAIL);
    assertTrue(html.contains(GENERIC_EMAIL_SENT_TEXT));

    Thread.sleep(2000);
    assertEquals(0, mailCount(UNKNOWN_EMAIL));
  }

  // ---------------------------------------------------------------------------
  // flow drivers
  // ---------------------------------------------------------------------------

  /** Starts the browser flow and submits the email; returns the resulting page HTML. */
  private String submitEmail(HttpClient browser, String email) throws Exception {
    HttpResponse<String> login = get(browser, authorizationUrl());
    assertEquals(200, login.statusCode(), "auth endpoint should render the login page");
    assertTrue(login.body().contains("name=\"username\""), "email-only form expected");

    HttpResponse<String> response =
        postForm(browser, formAction(login.body()), "username=" + enc(email));
    assertEquals(200, response.statusCode(), () -> "username POST failed:\n" + response.body());
    return response.body();
  }

  /** Starts the reset-credentials flow and submits the email; returns the info page HTML. */
  private String submitForgotPassword(String email) throws Exception {
    HttpClient browser = newBrowser();
    String resetUrl =
        base()
            + "realms/"
            + TEST_REALM
            + "/login-actions/reset-credentials?client_id="
            + TEST_CLIENT;
    HttpResponse<String> resetPage = get(browser, resetUrl);
    assertEquals(200, resetPage.statusCode());
    assertTrue(resetPage.body().contains("name=\"username\""));

    HttpResponse<String> response =
        postForm(browser, formAction(resetPage.body()), "username=" + enc(email));
    // forkWithSuccessMessage redirects back to the login page with an info message
    while (response.statusCode() >= 300 && response.statusCode() < 400) {
      response = get(browser, response.headers().firstValue("Location").orElseThrow());
    }
    assertEquals(200, response.statusCode());
    return response.body();
  }

  /**
   * Follows the activation link: confirmation info page, then the required actions (filling the
   * update-password form when it appears), until Keycloak redirects back to the client. Returns
   * that final location.
   */
  private String completeActivation(HttpClient browser, String link, String newPassword)
      throws Exception {
    String nextUrl = link;
    String nextMethod = "GET";
    String nextBody = null;
    StringBuilder debug = new StringBuilder("Activation chain:\n");

    for (int attempt = 0; attempt < 15; attempt++) {
      HttpResponse<String> response =
          "POST".equals(nextMethod)
              ? postForm(browser, nextUrl, nextBody != null ? nextBody : "")
              : get(browser, nextUrl);
      int status = response.statusCode();
      String location = response.headers().firstValue("Location").orElse(null);
      debug.append(
          String.format(
              "  [%d] %s %s -> %d  Location: %s%n",
              attempt, nextMethod, nextUrl, status, location));
      nextMethod = "GET";
      nextBody = null;

      if (status >= 300 && status < 400) {
        if (location == null) break;
        if (location.startsWith(REDIRECT_URI)) return location;
        nextUrl = location;
        continue;
      }
      if (status != 200) {
        debug.append("  Unexpected status, body: ").append(response.body()).append('\n');
        break;
      }

      String html = response.body();
      if (html.contains("name=\"password-new\"")) {
        nextUrl = formAction(html);
        nextMethod = "POST";
        nextBody = "password-new=" + enc(newPassword) + "&password-confirm=" + enc(newPassword);
        continue;
      }
      Matcher confirm = ACTION_TOKEN_HREF.matcher(html);
      if (confirm.find()) {
        nextUrl = confirm.group(1).replace("&amp;", "&");
        continue;
      }
      // e.g. "Your account has been updated" page linking back to the application
      Matcher back =
          Pattern.compile("href=\"(" + Pattern.quote(REDIRECT_URI) + "[^\"]*)\"").matcher(html);
      if (back.find()) {
        return back.group(1).replace("&amp;", "&");
      }
      debug.append("  No way forward from this page, body: ").append(html).append('\n');
      break;
    }
    throw new AssertionError("Activation did not complete.\n" + debug);
  }

  private String followUntilLocationStartsWith(
      HttpClient browser, HttpResponse<String> response, String prefix) throws Exception {
    for (int i = 0; i < 10; i++) {
      if (response.statusCode() >= 300 && response.statusCode() < 400) {
        String location = response.headers().firstValue("Location").orElse(null);
        if (location == null) return null;
        if (location.startsWith(prefix)) return location;
        response = get(browser, location);
      } else {
        return null;
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // http helpers
  // ---------------------------------------------------------------------------

  private static HttpClient newBrowser() {
    return HttpClient.newBuilder()
        .cookieHandler(new TestCookieJar())
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  /**
   * Minimal cookie jar for single-host test traffic. Keycloak marks its auth cookies {@code
   * SameSite=None; Secure}, and the JDK's {@link CookieManager} never replays Secure cookies over
   * plain http (real browsers exempt localhost; the JDK does not), so the built-in manager
   * silently drops the auth session between requests.
   */
  private static final class TestCookieJar extends java.net.CookieHandler {
    private final java.util.Map<String, String> cookies = new java.util.LinkedHashMap<>();

    @Override
    public java.util.Map<String, List<String>> get(
        URI uri, java.util.Map<String, List<String>> requestHeaders) {
      if (cookies.isEmpty()) return java.util.Map.of();
      String header =
          cookies.entrySet().stream()
              .map(e -> e.getKey() + "=" + e.getValue())
              .collect(java.util.stream.Collectors.joining("; "));
      return java.util.Map.of("Cookie", List.of(header));
    }

    @Override
    public void put(URI uri, java.util.Map<String, List<String>> responseHeaders) {
      responseHeaders.forEach(
          (name, values) -> {
            if (!"set-cookie".equalsIgnoreCase(name)) return;
            for (String value : values) {
              String pair = value.split(";", 2)[0];
              int eq = pair.indexOf('=');
              if (eq > 0) {
                cookies.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
              }
            }
          });
    }
  }

  private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
    return client.send(
        HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private static HttpResponse<String> postForm(HttpClient client, String url, String body)
      throws Exception {
    return client.send(
        HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private static String base() {
    String base = getAuthUrl();
    return base.endsWith("/") ? base : base + "/";
  }

  private static String authorizationUrl() {
    return base()
        + "realms/"
        + TEST_REALM
        + "/protocol/openid-connect/auth?client_id="
        + TEST_CLIENT
        + "&redirect_uri="
        + enc(REDIRECT_URI)
        + "&response_type=code&scope=openid";
  }

  private static String formAction(String html) {
    Matcher m = FORM_ACTION.matcher(html);
    assertTrue(m.find(), "no form action found in page:\n" + html);
    return m.group(1).replace("&amp;", "&");
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  // ---------------------------------------------------------------------------
  // mailhog helpers
  // ---------------------------------------------------------------------------

  private static String mailhogUrl() {
    return "http://localhost:" + mailHog.getMappedPort(8025);
  }

  private static int mailCount(String to) {
    return given()
        .baseUri(mailhogUrl())
        .queryParam("kind", "to")
        .queryParam("query", to)
        .get("/api/v2/search")
        .jsonPath()
        .getInt("total");
  }

  /** Polls MailHog until {@code count} messages exist for {@code to}; returns the newest body. */
  private static String waitForMail(String to, int count) throws Exception {
    for (int i = 0; i < 40; i++) {
      if (mailCount(to) >= count) {
        List<String> bodies =
            given()
                .baseUri(mailhogUrl())
                .queryParam("kind", "to")
                .queryParam("query", to)
                .get("/api/v2/search")
                .jsonPath()
                .getList("items.Content.Body");
        return unfoldQuotedPrintable(bodies.get(0));
      }
      Thread.sleep(500);
    }
    int total = given().baseUri(mailhogUrl()).get("/api/v2/messages").jsonPath().getInt("total");
    String kcMailLogs =
        container
            .getLogs()
            .lines()
            .filter(
                l ->
                    l.toLowerCase().contains("mail")
                        || l.contains("EmailException")
                        || l.contains("ext-activation"))
            .reduce("", (a, b) -> a + "\n" + b);
    throw new AssertionError(
        "No email arrived for " + to + "; mailhog total=" + total + "; kc logs:" + kcMailLogs);
  }

  private static String unfoldQuotedPrintable(String body) {
    return body.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=");
  }

  private static String extractActionTokenLink(String mailBody) {
    Matcher m = ACTION_TOKEN_LINK.matcher(mailBody);
    if (!m.find()) return null;
    return m.group().replace("&amp;", "&");
  }
}
