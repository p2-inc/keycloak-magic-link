package io.phasetwo.keycloak.magic.web;

import io.phasetwo.keycloak.magic.Helpers;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;

@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class MagicLinkContinuationTest extends AbstractMagicLinkWithMailhogTest {

  @TestFactory
  @DisplayName("Magic link continuation does not disclose whether an email exists")
  public List<DynamicContainer> testWaitingPage()
      throws IOException, InterruptedException, TimeoutException {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    var realm =
        Helpers.loadJson(
            getClass().getResourceAsStream("/realms/magic-link-basic-setup.json"),
            RealmRepresentation.class);
    realm
        .getAuthenticationFlows()
        .forEach(
            flow ->
                flow.getAuthenticationExecutions()
                    .forEach(
                        execution -> {
                          if ("ext-magic-form".equals(execution.getAuthenticator())) {
                            execution.setAuthenticator("magic-link-continuation-form");
                          }
                        }));
    // Deliberately different from the email: the waiting page must not reveal it.
    realm.getUsers().getFirst().setUsername("existing-user");
    importRealm(realm, keycloak);
    try {
      return runCypressTests(
          "cypress/e2e/continuation.cy.ts", Map.of("MAILHOG_URL", "http://mailhog:8025"));
    } finally {
      keycloak.realm(realm.getRealm()).remove();
    }
  }
}
