package io.phasetwo.keycloak.magic;

import jakarta.ws.rs.core.Response;
import org.hamcrest.CoreMatchers;
import org.jetbrains.annotations.Nullable;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;

public final class Helpers {

    private Helpers(){

    }

    public static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }
}
