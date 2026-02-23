package io.phasetwo.keycloak.magic.web;

import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeoutException;

@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class MagicLinkAuthenticatorTest extends AbstractMagicLinkTest {

    @TestFactory
    @DisplayName("Basic tests magic link authentication flow")
    public List<DynamicContainer> testMagicLinkAuthentication() throws IOException, InterruptedException, TimeoutException {
        final var testRealm = setupTestKeycloakInstance();
        assignEachUserAccountManagementRoles(testRealm);
        final var client = keycloak
                .realms()
                .realm(testRealm.getRealm())
                .clients()
                .findByClientId("account")
                .getFirst();
        client.setName("Account Console");
        keycloak.realms().realm(testRealm.getRealm()).clients().get(client.getId()).update(client);
        return runCypressTests("cypress/e2e/base.cy.ts");
    }

    private RealmRepresentation setupTestKeycloakInstance() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");
        return testRealm;
    }
}
