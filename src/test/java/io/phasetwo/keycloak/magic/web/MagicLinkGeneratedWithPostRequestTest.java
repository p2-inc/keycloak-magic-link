package io.phasetwo.keycloak.magic.web;

import com.fasterxml.jackson.core.type.TypeReference;
import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import lombok.extern.jbosslog.JBossLog;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.OutputFrame;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.hamcrest.MatcherAssert.assertThat;

@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class MagicLinkGeneratedWithPostRequestTest extends AbstractMagicLinkTest {

    public static final String CURL_IMAGE = "curlimages/curl:8.17.0";

    @TestFactory
    public List<DynamicContainer> testMagicLinkCreation() throws IOException, InterruptedException, TimeoutException {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");

        UserRepresentation user = Helpers.createUser(keycloak, testRealm.getRealm(), "user1", "user1@phasetwo.io", "Phase", "Two");
        MagicLinkRequest request = new MagicLinkRequest();

        request.setUsername(user.getUsername());
        request.setEmail(user.getEmail());
        request.setClientId("account");
        request.setRedirectUri("http://host.testcontainers.internal:" + container.getHttpPort() + "/auth/realms/" + testRealm.getRealm() + "/account/");
        request.setExpirationSeconds(60);
        request.setForceCreate(true);
        request.setSendEmail(false);
        request.setUpdateProfile(false);
        request.setUpdatePassword(false);
        request.setScope(null);
        request.setNonce(null);
        request.setCodeChallenge(null);
        request.setCodeChallengeMethod(null);
        request.setRememberMe(false);

        final var requestAsString = Helpers.toJsonString(request);

        /*
        All requests in this test - from the first to the last - must use the same hostname. There’s no `host:port`
            accessible from both host and Cypress container, so we use the Testcontainers network via
            `host.testcontainers.internal`.
            Not ideal, but no better solution was found.
         */
        var accessTokenCurlResponse = runHttpRequestWithCurl(
                "curl",
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", "client_id=admin-cli",
                "-d", "username=" + container.getAdminUsername(),
                "-d", "password=" + container.getAdminUsername(),
                "-d", "grant_type=password",
                "http://host.testcontainers.internal:" + container.getHttpPort() + "/auth/realms/master/protocol/openid-connect/token"
        );
        var accessTokenResponse = Helpers.mapper().readValue(accessTokenCurlResponse, new TypeReference<Map<String, String>>() {});
        var magicLinkCurlResponse = runHttpRequestWithCurl("curl",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-H", "Authorization: Bearer " + accessTokenResponse.get("access_token"),
                "-d", requestAsString,
                "http://host.testcontainers.internal:" + container.getHttpPort() + "/auth/realms/" + testRealm.getRealm() + "/magic-link"
        );
        log.info("Curl output was: " + magicLinkCurlResponse);

        MagicLinkResponse magicLinkResponse = Helpers.mapper().readValue(magicLinkCurlResponse, MagicLinkResponse.class);
        assertThat(magicLinkResponse.getLink(), CoreMatchers.notNullValue());

        return runCypressTests(
                "cypress/e2e/pre-generated-link.cy.ts",
                Map.of("GENERATED_MAGIC_LINK", magicLinkResponse.getLink())
        );
    }

    private static String runHttpRequestWithCurl(String... commandPart) {
        try (GenericContainer<?> curlContainer = new GenericContainer<>(CURL_IMAGE)) {
            curlContainer.withNetwork(network)
                    .withAccessToHost(true)
                    .withCommand(commandPart);
            curlContainer.start();
            return curlContainer.getLogs(OutputFrame.OutputType.STDOUT);
        }
    }
}
