package io.phasetwo.keycloak.magic.service;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@JBossLog
public class MagicLinkUsernameDiffersFromEmailTest extends AbstractMagicLinkTest {

    @Test
    void testMagicLinkCreation_whenUsernameDiffersFromEmail() throws IOException {
        // import realm with loginWithEmailAllowed=false
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-username-differs-from-email.json");

        // create user whose username is NOT their email address
        UserRepresentation user = Helpers.createUser(keycloak, testRealm.getRealm(), "jsmith", "john@example.com");

        // request magic link by email
        MagicLinkRequest request = new MagicLinkRequest();
        request.setEmail("john@example.com");
        request.setClientId("test-client");
        request.setRedirectUri("http://localhost");
        request.setExpirationSeconds(300);
        request.setForceCreate(false);
        request.setSendEmail(false);

        var response = postRequest(keycloak, request, testRealm.getRealm());
        assertThat(response.getStatusCode(), CoreMatchers.is(Response.Status.OK.getStatusCode()));

        MagicLinkResponse magicLinkResponse = Helpers.mapper()
                .readValue(response.getBody().asString(), MagicLinkResponse.class);
        assertNotNull(magicLinkResponse);
        assertTrue(magicLinkResponse.getUserId().equals(user.getId()));
        assertNotNull(magicLinkResponse.getLink());
    }
}
