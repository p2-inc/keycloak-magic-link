package io.phasetwo.keycloak.magic.web;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;

@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class EmailOtpSentInEmailTest extends AbstractMagicLinkWithMailhogTest {

  @TestFactory
  @DisplayName("Basic tests for the Email OTP authenticator")
  public List<DynamicContainer> testEmailOtpAuthentication()
      throws IOException, InterruptedException, TimeoutException {
    final var testRealm = setupTestKeycloakInstance();
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
    return runCypressTests(
        "cypress/e2e/email-otp.cy.ts", Map.of("MAILHOG_URL", "http://mailhog:8025"));
  }

  private RealmRepresentation setupTestKeycloakInstance() {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    RealmRepresentation testRealm = importRealm("/realms/email-otp-basic-setup.json");
    return testRealm;
  }
}
