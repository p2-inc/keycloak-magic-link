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
public class MagicLinkResourceTest extends AbstractMagicLinkTest {

    @Test
    void testMagicLinkCreation() throws IOException {
        //import realm
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");

        // create  user
        UserRepresentation user = Helpers.createUser(keycloak, testRealm.getRealm(), "user1", "user1@gmail.com");
        // add magic link
        MagicLinkRequest request = new MagicLinkRequest();

        request.setUsername("user1");
        request.setEmail("user1@gmail.com");
        request.setClientId("security-admin-console");
        request.setRedirectUri("https://localhost/auth/admin/test-realm/console/");
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

       var response =  postRequest(keycloak, request, testRealm.getRealm());
       assertThat(response.getStatusCode(), CoreMatchers.is(Response.Status.OK.getStatusCode()));

       MagicLinkResponse magicLinkResponse = Helpers.mapper()
               .readValue(response.getBody().asString(), MagicLinkResponse.class);
       assertNotNull(magicLinkResponse);
       assertTrue(magicLinkResponse.getUserId().equals(user.getId()));
       assertNotNull(magicLinkResponse.getLink());
    }
}
