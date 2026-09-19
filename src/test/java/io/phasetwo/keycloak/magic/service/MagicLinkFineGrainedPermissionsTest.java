package io.phasetwo.keycloak.magic.service;

import io.phasetwo.keycloak.magic.Helpers;
import io.phasetwo.keycloak.magic.representation.MagicLinkRequest;
import io.phasetwo.keycloak.magic.representation.MagicLinkResponse;
import jakarta.ws.rs.core.Response;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.testcontainers.Testcontainers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MagicLinkFineGrainedPermissionsTest extends AbstractMagicLinkTest {

    private static final String DELEGATED_ADMIN_USERNAME = "delegated-admin";
    private static final String DELEGATED_ADMIN_PASSWORD = "delegated-admin-password";

    @Test
    void testMagicLinkCreationWithFineGrainedUserManagement() throws IOException {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");

        String realmName = testRealm.getRealm();
        RealmResource realm = keycloak.realm(realmName);
        UserRepresentation managedUser =
                Helpers.createUser(keycloak, realmName, "managed-user", "managed-user@phasetwo.io");
        UserRepresentation unmanagedUser =
                Helpers.createUser(keycloak, realmName, "unmanaged-user", "unmanaged-user@phasetwo.io");
        UserRepresentation delegatedAdminUser = createDelegatedAdminUser(realm, realmName);
        String delegatedAdminUserId = delegatedAdminUser.getId();
        String delegatedAccessToken = getDelegatedUserAccessToken(realmName);

        configureV2FineGrainedPermissions(realm, managedUser, delegatedAdminUserId);

        var allowedResponse = postRequestWithToken(delegatedAccessToken, buildRequest(managedUser.getUsername()), realmName);
        assertThat(allowedResponse.getStatusCode(), CoreMatchers.is(Response.Status.OK.getStatusCode()));

        MagicLinkResponse allowedMagicLinkResponse =
                Helpers.mapper().readValue(allowedResponse.getBody().asString(), MagicLinkResponse.class);
        assertNotNull(allowedMagicLinkResponse);
        assertEquals(managedUser.getId(), allowedMagicLinkResponse.getUserId());
        assertNotNull(allowedMagicLinkResponse.getLink());

        var deniedResponse = postRequestWithToken(delegatedAccessToken, buildRequest(unmanagedUser.getUsername()), realmName);
        assertThat(deniedResponse.getStatusCode(), CoreMatchers.is(Response.Status.FORBIDDEN.getStatusCode()));
    }

    private void configureV2FineGrainedPermissions(
            RealmResource realm,
            UserRepresentation managedUser,
            String delegatedAdminUserId
    ) {
        RealmRepresentation realmRep = realm.toRepresentation();
        realmRep.setAdminPermissionsEnabled(true);
        realm.update(realmRep);

        AuthorizationResource authorization = authorizationForClient(realm, "admin-permissions");
        String delegatedAdminPolicyId =
                createUserPolicy(
                        authorization,
                        "magic-link-delegated-admin-policy-" + delegatedAdminUserId,
                        delegatedAdminUserId);

        ScopePermissionRepresentation scopePermission = new ScopePermissionRepresentation();
        scopePermission.setName("magic-link-manage-user-" + managedUser.getId());
        scopePermission.setResourceType("Users");
        scopePermission.setScopes(Set.of("manage"));
        scopePermission.setResources(Set.of(managedUser.getId()));
        scopePermission.setPolicies(Set.of(delegatedAdminPolicyId));
        scopePermission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        try (Response createScopePermission = authorization.permissions().scope().create(scopePermission)) {
            assertThat(createScopePermission.getStatus(), CoreMatchers.is(Response.Status.CREATED.getStatusCode()));
        }
    }

    private AuthorizationResource authorizationForClient(RealmResource realm, String clientId) {
        var realmClient = realm.clients().findByClientId(clientId).getFirst();
        return realm.clients().get(realmClient.getId()).authorization();
    }

    private String createUserPolicy(AuthorizationResource authorization, String policyName, String userId) {
        UserPolicyRepresentation userPolicy = new UserPolicyRepresentation();
        userPolicy.setName(policyName);
        userPolicy.setUsers(Set.of(userId));

        try (Response createPolicyResponse = authorization.policies().user().create(userPolicy)) {
            assertThat(createPolicyResponse.getStatus(), CoreMatchers.is(Response.Status.CREATED.getStatusCode()));
        }

        UserPolicyRepresentation createdPolicy = authorization.policies().user().findByName(policyName);
        assertNotNull(createdPolicy);
        assertNotNull(createdPolicy.getId());
        return createdPolicy.getId();
    }

    private UserRepresentation createDelegatedAdminUser(RealmResource realm, String realmName) {
        UserRepresentation user = Helpers.createUser(
                keycloak,
                realmName,
                DELEGATED_ADMIN_USERNAME,
                "delegated-admin@phasetwo.io",
                "Delegated",
                "Admin");

        UserRepresentation userRep = realm.users().get(user.getId()).toRepresentation();
        userRep.setEmailVerified(true);
        userRep.setRequiredActions(new ArrayList<>());
        realm.users().get(user.getId()).update(userRep);

        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setTemporary(false);
        password.setValue(DELEGATED_ADMIN_PASSWORD);
        realm.users().get(user.getId()).resetPassword(password);

        return user;
    }

    private String getDelegatedUserAccessToken(String realm) {
        var tokenResponse = given()
                .baseUri(container.getAuthServerUrl())
                .basePath("realms/" + realm + "/protocol/openid-connect/token")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", "admin-cli")
                .formParam("username", DELEGATED_ADMIN_USERNAME)
                .formParam("password", DELEGATED_ADMIN_PASSWORD)
                .when()
                .post()
                .then()
                .extract()
                .response();

        assertThat(tokenResponse.getStatusCode(), CoreMatchers.is(Response.Status.OK.getStatusCode()));
        return tokenResponse.path("access_token");
    }

    private io.restassured.response.Response postRequestWithToken(String accessToken, Object body, String realm)
            throws IOException {
        return given()
                .baseUri(container.getAuthServerUrl())
                .basePath("realms/" + realm + "/")
                .contentType("application/json")
                .auth()
                .oauth2(accessToken)
                .and()
                .body(Helpers.toJsonString(body))
                .post("magic-link")
                .then()
                .extract()
                .response();
    }

    private MagicLinkRequest buildRequest(String username) {
        MagicLinkRequest request = new MagicLinkRequest();
        request.setUsername(username);
        request.setClientId("security-admin-console");
        request.setRedirectUri("https://localhost/auth/admin/test-realm/console/");
        request.setExpirationSeconds(60);
        request.setForceCreate(true);
        request.setSendEmail(false);
        request.setUpdateProfile(false);
        request.setUpdatePassword(false);
        request.setRememberMe(false);
        return request;
    }
}
