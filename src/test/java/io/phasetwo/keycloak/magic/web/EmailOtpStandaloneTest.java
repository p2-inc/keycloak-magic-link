package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.response.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/** HTTP integration tests against real Keycloak and MailHog, without a custom theme. */
public class EmailOtpStandaloneTest extends AbstractMagicLinkWithMailhogTest {
  private static final String EMAIL = "testuser@phasetwo.io";
  private static final String CALLBACK = "http://localhost/otp-test-callback";
  private RealmResource realm;
  private String realmName;

  @BeforeEach
  public void configureStandaloneFlow() {
    realmName = "email-otp-standalone-" + UUID.randomUUID();
    importRealm("/realms/email-otp-basic-setup.json", realmName);
    realm = keycloak.realm(realmName);
    realm.flows().getExecutions("Email OTP forms").stream()
        .filter(e -> "auth-username-form".equals(e.getProviderId()))
        .forEach(e -> realm.flows().removeExecution(e.getId()));
    var client = new ClientRepresentation();
    client.setClientId("otp-test");
    client.setPublicClient(true);
    client.setStandardFlowEnabled(true);
    client.setRedirectUris(List.of(CALLBACK));
    try (var response = realm.clients().create(client)) {
      assertEquals(201, response.getStatus());
    }
    // Profile completion is orthogonal to email proof/registration.
    var profile = realm.flows().getRequiredAction("VERIFY_PROFILE");
    profile.setEnabled(false);
    realm.flows().updateRequiredAction("VERIFY_PROFILE", profile);
    given().delete(mailUrl() + "/api/v1/messages").then().statusCode(200);
  }

  @Test
  public void existingUserWrongCodeThenSuccessAndNoCrossSessionReuse() {
    var first = start().submit("kc-form-login", Map.of("username", EMAIL));
    assertCodeForm(first);
    var code = latestCode();
    var second = start().submit("kc-form-login", Map.of("username", EMAIL));
    var secondCode = latestCode();
    // An independently generated six-digit code can coincidentally match.
    if (!code.equals(secondCode)) {
      second.submit("kc-otp-login-form", Map.of("otp", code));
      assertCodeForm(second);
    }
    first.submit("kc-otp-login-form", Map.of("otp", "not-a-code"));
    assertCodeForm(first);
    first.submit("kc-otp-login-form", Map.of("otp", code));
    assertLoggedIn(first);
    assertTrue(user().isEmailVerified());
    second.submit("kc-otp-login-form", Map.of("otp", secondCode));
    assertLoggedIn(second);
  }

  @Test
  public void unknownAndDisabledUsersSeeCodeFormWithoutMailOrRegistration() {
    for (var address : List.of("unknown@phasetwo.io", EMAIL)) {
      if (address.equals(EMAIL)) {
        var user = user();
        user.setEnabled(false);
        realm.users().get(user.getId()).update(user);
      }
      var browser = start().submit("kc-form-login", Map.of("username", address));
      assertCodeForm(browser);
      browser.submit("kc-otp-login-form", Map.of("otp", "000000"));
      assertCodeForm(browser);
      browser.submit("kc-otp-login-form", Map.of("resend", ""));
      assertCodeForm(browser);
      assertEquals(0, mailCount());
    }
    assertTrue(realm.users().searchByEmail("unknown@phasetwo.io", true).isEmpty());
  }

  @Test
  public void invalidEmailStaysOnEmailFormAndDoesNotSendOrCreate() {
    forceCreate(true);
    for (var address : List.of("", " ", "not-an-email", "a".repeat(255) + "@example.com")) {
      var browser = start().submit("kc-form-login", Map.of("username", address));
      assertTrue(browser.html().contains("id=\"kc-form-login\""));
      assertFalse(browser.html().contains("id=\"kc-otp-login-form\""));
      assertEquals(0, mailCount());
    }
    assertEquals(1, realm.users().count());
  }

  @Test
  public void registrationUsesTrimmedEmailAndVerifiesOnlyAfterCorrectCode() {
    forceCreate(true);
    var browser = start().submit("kc-form-login", Map.of("username", " new@phasetwo.io "));
    assertCodeForm(browser);
    var created = realm.users().searchByEmail("new@phasetwo.io", true).getFirst();
    assertFalse(created.isEmailVerified());
    browser.submit("kc-otp-login-form", Map.of("otp", latestCode()));
    assertLoggedIn(browser);
    assertTrue(realm.users().get(created.getId()).toRepresentation().isEmailVerified());
  }

  @Test
  public void resendInvalidatesOldCodeAndCodePostCannotChangeUser() {
    var browser = start().submit("kc-form-login", Map.of("username", EMAIL));
    var oldCode = latestCode();
    browser.submit("kc-otp-login-form", Map.of("resend", ""));
    var newCode = latestCode();
    assertEquals(2, mailCount());
    if (!oldCode.equals(newCode)) {
      browser.submit("kc-otp-login-form", Map.of("otp", oldCode));
      assertCodeForm(browser);
    }
    browser.submit("kc-otp-login-form", Map.of("otp", newCode, "username", "other@phasetwo.io"));
    assertLoggedIn(browser);
    assertTrue(user().isEmailVerified());
    assertTrue(realm.users().searchByEmail("other@phasetwo.io", true).isEmpty());
  }

  @Test
  public void lockedUserCannotStartANewOtpLogin() throws Exception {
    var rep = realm.toRepresentation();
    rep.setBruteForceProtected(true);
    rep.setPermanentLockout(true);
    rep.setFailureFactor(2);
    realm.update(rep);
    var browser = start().submit("kc-form-login", Map.of("username", EMAIL));
    var code = latestCode();
    for (int i = 0; i < 2; i++) {
      browser.submit("kc-otp-login-form", Map.of("otp", "wrong"));
    }
    // Brute-force failure processing is asynchronous.
    for (int i = 0;
        i < 50
            && !Boolean.TRUE.equals(
                realm.attackDetection().bruteForceUserStatus(user().getId()).get("disabled"));
        i++) {
      Thread.sleep(100);
    }
    assertTrue(
        Boolean.TRUE.equals(
            realm.attackDetection().bruteForceUserStatus(user().getId()).get("disabled")));
    var fresh = start().submit("kc-form-login", Map.of("username", EMAIL));
    assertCodeForm(fresh);
    assertEquals(1, mailCount());
    fresh.submit("kc-otp-login-form", Map.of("otp", code));
    assertCodeForm(fresh);
  }

  @Test
  public void identifiedUserFlowStillWorks() {
    realm.flows().addExecution("Email OTP forms", Map.of("provider", "auth-username-form"));
    var username =
        realm.flows().getExecutions("Email OTP forms").stream()
            .filter(e -> "auth-username-form".equals(e.getProviderId()))
            .findFirst()
            .orElseThrow();
    username.setRequirement("REQUIRED");
    realm.flows().updateExecutions("Email OTP forms", username);
    realm.flows().raisePriority(username.getId());
    var browser = start().submit("kc-form-login", Map.of("username", EMAIL));
    assertCodeForm(browser);
    browser.submit("kc-otp-login-form", Map.of("otp", latestCode()));
    assertLoggedIn(browser);
  }

  @Test
  public void switchingMethodsCannotApplyCodeToAnotherUser() {
    var other = new UserRepresentation();
    other.setUsername("other@phasetwo.io");
    other.setEmail("other@phasetwo.io");
    other.setEnabled(true);
    try (var response = realm.users().create(other)) {
      assertEquals(201, response.getStatus());
    }
    realm
        .flows()
        .addExecutionFlow(
            "Email OTP forms",
            Map.of(
                "alias", "Password alternative", "type", "basic-flow", "provider", "basic-flow"));
    for (var execution : realm.flows().getExecutions("Email OTP forms")) {
      execution.setRequirement("ALTERNATIVE");
      realm.flows().updateExecutions("Email OTP forms", execution);
    }
    realm
        .flows()
        .addExecution("Password alternative", Map.of("provider", "auth-username-password-form"));
    var password = realm.flows().getExecutions("Password alternative").getFirst();
    password.setRequirement("REQUIRED");
    realm.flows().updateExecutions("Password alternative", password);
    var otp =
        realm.flows().getExecutions("Email OTP forms").stream()
            .filter(e -> "ext-email-otp".equals(e.getProviderId()))
            .findFirst()
            .orElseThrow();
    var browser = start().submit("kc-form-login", Map.of("username", EMAIL));
    var originalCode = latestCode();
    browser.submit("kc-otp-login-form", Map.of("authenticationExecution", password.getId()));
    assertTrue(browser.html().contains("id=\"password\""));
    browser.submit("kc-form-login", Map.of("username", "other@phasetwo.io", "password", "wrong"));
    browser.submit("kc-form-login", Map.of("authenticationExecution", otp.getId()));
    // Depending on Keycloak's reset semantics it may collect the email again.
    if (browser.html().contains("id=\"kc-form-login\"")) {
      browser.submit("kc-form-login", Map.of("username", "other@phasetwo.io"));
    }
    assertCodeForm(browser);
    // Keycloak pins the already identified user when switching methods. A forged
    // username on the password form must not change the recipient of the code.
    assertEquals(1, mailCount());
    browser.submit("kc-otp-login-form", Map.of("otp", originalCode));
    assertLoggedIn(browser);
    assertTrue(user().isEmailVerified());
    assertFalse(
        realm.users().searchByEmail("other@phasetwo.io", true).getFirst().isEmailVerified());
  }

  @Test
  public void changingEmailWhileCodePendingDoesNotVerifyNewAddress() {
    var browser = start().submit("kc-form-login", Map.of("username", EMAIL));
    var oldCode = latestCode();
    var changed = user();
    changed.setEmail("changed@phasetwo.io");
    realm.users().get(changed.getId()).update(changed);
    browser.submit("kc-otp-login-form", Map.of("otp", oldCode));
    assertCodeForm(browser);
    assertFalse(realm.users().get(changed.getId()).toRepresentation().isEmailVerified());
    assertEquals(2, mailCount());
    browser.submit("kc-otp-login-form", Map.of("otp", latestCode()));
    assertLoggedIn(browser);
    assertTrue(realm.users().get(changed.getId()).toRepresentation().isEmailVerified());
  }

  private UserRepresentation user() {
    return realm.users().searchByEmail(EMAIL, true).getFirst();
  }

  private void forceCreate(boolean enabled) {
    var execution = realm.flows().getExecutions("Email OTP forms").getFirst();
    var config = realm.flows().getAuthenticatorConfig(execution.getAuthenticationConfig());
    config.setConfig(Map.of("ext-magic-create-nonexistent-user", Boolean.toString(enabled)));
    realm.flows().updateAuthenticatorConfig(config.getId(), config);
  }

  private String mailUrl() {
    return "http://" + mailHog.getHost() + ":" + mailHog.getMappedPort(8025);
  }

  private int mailCount() {
    return given().get(mailUrl() + "/api/v2/messages").jsonPath().getInt("total");
  }

  private String latestCode() {
    String body =
        given().get(mailUrl() + "/api/v2/messages").jsonPath().getString("items[0].Content.Body");
    var matcher = Pattern.compile("Code:\\s*(\\d{6})").matcher(body);
    assertTrue(matcher.find(), "Expected an OTP email");
    return matcher.group(1);
  }

  private Browser start() {
    var browser = new Browser();
    browser.response =
        given()
            .cookies(browser.cookies)
            .redirects()
            .follow(false)
            .queryParam("client_id", "otp-test")
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", CALLBACK)
            .get(getAuthUrl() + "/realms/" + realmName + "/protocol/openid-connect/auth");
    browser.cookies.putAll(browser.response.cookies());
    assertTrue(browser.html().contains("id=\"kc-form-login\""));
    return browser;
  }

  private void assertCodeForm(Browser browser) {
    assertEquals(200, browser.response.statusCode());
    assertTrue(browser.html().contains("id=\"kc-otp-login-form\""));
  }

  private void assertLoggedIn(Browser browser) {
    assertEquals(302, browser.response.statusCode());
    assertTrue(browser.response.header("Location").startsWith(CALLBACK + "?"));
    assertTrue(browser.response.header("Location").contains("code="));
  }

  private static class Browser {
    // Explicit cookie jar: browsers send Secure cookies on loopback HTTP, but the
    // Apache HTTP client's CookieFilter does not. Requests stay on this test server.
    private final Map<String, String> cookies = new HashMap<>();
    private Response response;

    private String html() {
      return response.asString();
    }

    private Browser submit(String formId, Map<String, String> fields) {
      var form = Pattern.compile("<form\\b[^>]*id=\"" + formId + "\"[^>]*>").matcher(html());
      assertTrue(form.find(), "Expected form " + formId);
      var action = Pattern.compile("action=\"([^\"]+)\"").matcher(form.group());
      assertTrue(action.find());
      response =
          given()
              .cookies(cookies)
              .redirects()
              .follow(false)
              .formParams(fields)
              .post(action.group(1).replace("&amp;", "&"));
      cookies.putAll(response.cookies());
      return this;
    }
  }
}
