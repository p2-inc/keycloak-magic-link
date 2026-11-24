package io.phasetwo.keycloak.magic.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;

@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class EmailOtpSentInEmailTest extends AbstractMagicLinkWithMailhogTest {

  private static final String TEST_USER = "testuser@phasetwo.io";

  /** Matches {@code failureFactor} in the brute force realm. */
  private static final int FAILURE_FACTOR = 3;

  @TestFactory
  @DisplayName("Basic tests for the Email OTP authenticator")
  public List<DynamicContainer> testEmailOtpAuthentication()
      throws IOException, InterruptedException, TimeoutException {
    setupTestKeycloakInstance("/realms/email-otp-basic-setup.json");
    return runCypressTests(
        "cypress/e2e/email-otp.cy.ts", Map.of("MAILHOG_URL", "http://mailhog:8025"));
  }

  @TestFactory
  @DisplayName("Email OTP authenticator with brute force protection enabled")
  public List<DynamicContainer> testEmailOtpWithBruteForceProtection()
      throws IOException, InterruptedException, TimeoutException {
    setupTestKeycloakInstance("/realms/email-otp-brute-force-setup.json");
    return runCypressTests(
        "cypress/e2e/email-otp-brute-force.cy.ts", Map.of("MAILHOG_URL", "http://mailhog:8025"));
  }

  /**
   * Regression coverage for brute force protection never counting failed Email OTP attempts.
   * Keycloak discards a failure whose authenticator reports a reference category outside {@code
   * DefaultBruteForceProtector.ALLOWED_AUTHENTICATION_CATEGORIES}, so while {@code
   * EmailOtpAuthenticatorFactory.getReferenceCategory()} returned "alternate-auth" the counters
   * stayed at zero and the account was never locked out.
   */
  @TestFactory
  @DisplayName("Failed Email OTP attempts increment the brute force counters")
  public List<DynamicContainer> testEmailOtpIncrementsBruteForceCounters()
      throws IOException, InterruptedException, TimeoutException {
    final var testRealm = setupTestKeycloakInstance("/realms/email-otp-brute-force-setup.json");
    final var results =
        new ArrayList<>(
            runCypressTests(
                "cypress/e2e/email-otp-brute-force-counter.cy.ts",
                Map.of("MAILHOG_URL", "http://mailhog:8025")));
    results.add(
        DynamicContainer.dynamicContainer(
            "Brute force protection",
            List.of(
                DynamicTest.dynamicTest(
                    String.format(
                        "User is temporarily disabled after %d failed OTP codes", FAILURE_FACTOR),
                    () -> assertTemporarilyDisabled(testRealm.getRealm(), TEST_USER)))));
    return results;
  }

  private void assertTemporarilyDisabled(String realmName, String username) {
    final var realm = keycloak.realm(realmName);
    final var users = realm.users().search(username, true);
    assertEquals(1, users.size(), "expected exactly one user named " + username);

    final Map<String, Object> status =
        realm.attackDetection().bruteForceUserStatus(users.getFirst().getId());
    log.infof("brute force status for %s: %s", username, status);

    assertEquals(
        FAILURE_FACTOR,
        ((Number) status.get("numFailures")).intValue(),
        "brute force failure counter did not track the failed OTP attempts");
    assertTrue(
        Boolean.parseBoolean(String.valueOf(status.get("disabled"))),
        "user should be temporarily disabled after " + FAILURE_FACTOR + " failed OTP attempts");
  }

  private RealmRepresentation setupTestKeycloakInstance(String realmJsonPath) {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    RealmRepresentation testRealm = importRealm(realmJsonPath);
    assignEachUserAccountManagementRoles(testRealm);
    final var client =
        keycloak
            .realms()
            .realm(testRealm.getRealm())
            .clients()
            .findByClientId("account")
            .getFirst();
    client.setName("Account Console");
    keycloak.realms().realm(testRealm.getRealm()).clients().get(client.getId()).update(client);
    return testRealm;
  }
}
