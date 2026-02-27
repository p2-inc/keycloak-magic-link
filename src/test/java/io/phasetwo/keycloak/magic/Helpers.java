package io.phasetwo.keycloak.magic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.response.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;

import static io.restassured.RestAssured.given;

public final class Helpers {

    private static final ObjectMapper mapper;
    static {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private Helpers(){

    }

    public static ObjectMapper mapper() {
        return mapper;
    }

    public static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

    public static UserRepresentation createUser(Keycloak keycloak,
                                                String realm,
                                                String username,
                                                String email) {
        return createUser(keycloak, realm, username, email, null, null);
    }

    public static UserRepresentation createUser(
            Keycloak keycloak,
            String realm,
            String username,
            String email,
            String firstName,
            String lastName
    ) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);

        keycloak.realm(realm).users().create(user);
        return keycloak.realm(realm).users().search(user.getUsername()).get(0);
    }

    public static Response postRequest(String authServerUrl, Keycloak keycloak, Object body, String realm) throws JsonProcessingException {
        return given()
                .baseUri(authServerUrl)
                .basePath("realms/" + realm + "/")
                .contentType("application/json")
                .auth()
                .oauth2(keycloak.tokenManager().getAccessTokenString())
                .and()
                .body(toJsonString(body))
                .post("magic-link")
                .then()
                .extract()
                .response();
    }

    public static String toJsonString(Object representation) throws JsonProcessingException {
        return mapper.writer().withDefaultPrettyPrinter().writeValueAsString(representation);
    }
}
