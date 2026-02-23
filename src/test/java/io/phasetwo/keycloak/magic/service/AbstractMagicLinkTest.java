package io.phasetwo.keycloak.magic.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.phasetwo.keycloak.magic.Helpers;
import io.restassured.response.Response;
import lombok.extern.jbosslog.JBossLog;
import org.hamcrest.CoreMatchers;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.images.PullPolicy;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;

@JBossLog
public abstract class AbstractMagicLinkTest {
    protected static final ObjectMapper mapper;
    static {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static final String KEYCLOAK_IMAGE =
            String.format(
                    "quay.io/keycloak/keycloak:%s", System.getProperty("keycloak-version", "26.5.3"));
    public static final String REALM = "master";

    public static final Network network = Network.newNetwork();
    public static final String ADMIN_CLI = "admin-cli";

    static final String[] deps = {};

    static List<File> getDeps() {
        List<File> dependencies = new ArrayList<>();
        for (String dep : deps) {
            dependencies.addAll(getDep(dep));
        }
        return dependencies;
    }

    static List<File> getDep(String pkg) {
        return Maven.resolver()
                .loadPomFromFile("./pom.xml")
                .resolve(pkg)
                .withoutTransitivity()
                .asList(File.class);
    }

    public static Keycloak keycloak;
    public static ResteasyClient resteasyClient;

    public static final KeycloakContainer container = initKeycloakContainer();
    public static final GenericContainer<?> mailHog = new GenericContainer<>("mailhog/mailhog:v1.0.1")
            .withNetwork(network)
            .withNetworkAliases("mailhog")
            .withExposedPorts(1025, 8025);

    private static KeycloakContainer initKeycloakContainer() {
        KeycloakContainer keycloakContainer = new KeycloakContainer(KEYCLOAK_IMAGE)
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withContextPath("/auth")
                .withReuse(true)
                .withProviderClassesFrom("target/classes")
                .withExposedPorts(8787, 9000, 8080)
                .withProviderLibsFrom(getDeps())
                .withNetwork(network)
                .withAccessToHost(true);

        return keycloakContainer.withEnv("JAVA_OPTS", "-agentlib:jdwp=transport=dt_socket,address=*:8787,server=y,suspend=n -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m");
    }

    protected static final int WEBHOOK_SERVER_PORT = 8083;

    @AfterAll
    public static void tearDown() throws IOException {
        String containerId = container.getContainerId();
        container.getDockerClient().stopContainerCmd(containerId).exec();

        container.stop();
        mailHog.stop();
        network.close();
    }

    @BeforeAll
    public static void beforeAll() {
        mailHog.start();
        container.start();

        Testcontainers.exposeHostPorts(WEBHOOK_SERVER_PORT);
        resteasyClient =
                new ResteasyClientBuilderImpl()
                        .disableTrustManager()
                        .readTimeout(60, TimeUnit.SECONDS)
                        .connectTimeout(10, TimeUnit.SECONDS)
                        .build();
        keycloak =
                getKeycloak(REALM, ADMIN_CLI, container.getAdminUsername(), container.getAdminPassword());
    }

    public static Keycloak getKeycloak(String realm, String clientId, String user, String pass) {
        return Keycloak.getInstance(getAuthUrl(), realm, user, pass, clientId);
    }

    public static String getAuthUrl() {
        return container.getAuthServerUrl();
    }

    public static UserRepresentation createUser(Keycloak keycloak,
                                                String realm,
                                                String username,
                                                String email) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(username);
        user.setEmail(email);

        keycloak.realm(realm).users().create(user);
        return keycloak.realm(realm).users().search(user.getUsername()).get(0);
    }

    protected Response postRequest(Keycloak keycloak, Object body, String realm)
            throws JsonProcessingException {

        return given()
                .baseUri(container.getAuthServerUrl())
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

    private static String toJsonString(Object representation) throws JsonProcessingException {
        return mapper.writer().withDefaultPrettyPrinter().writeValueAsString(representation);
    }

    private RealmRepresentation setupTestKeycloakInstance() {
        Testcontainers.exposeHostPorts(container.getHttpPort());
        RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");
        return testRealm;
    }

    protected final RealmRepresentation importRealm(String jsonRepresentationPath) {
        return importRealm(jsonRepresentationPath, null);
    }

    protected final RealmRepresentation importRealm(String jsonRepresentationPath, @Nullable String realmOverride) {
        RealmRepresentation realm =
                Helpers.loadJson(getClass().getResourceAsStream(jsonRepresentationPath),
                        RealmRepresentation.class);
        if (realmOverride != null) {
            realm.setRealm(realmOverride);
        }
        importRealm(realm, keycloak);
        knownRealms.add(realm.getRealm());
        log.info("realm imported successfully:" + realm.getRealm());
        return realm;
    }

    protected void importRealm(RealmRepresentation representation, Keycloak keycloak) {
        var response =
                given()
                        .baseUri(container.getAuthServerUrl())
                        .basePath("admin/realms/")
                        .contentType("application/json")
                        .auth()
                        .oauth2(keycloak.tokenManager().getAccessTokenString())
                        .and()
                        .body(representation)
                        .when()
                        .post()
                        .then()
                        .extract()
                        .response();
        assertThat(response.getStatusCode(), CoreMatchers.is(jakarta.ws.rs.core.Response.Status.CREATED.getStatusCode()));
    }

    private List<String> knownRealms;

    @BeforeEach
    public void setup() {
        knownRealms = new ArrayList<>();
    }

    @AfterEach
    public void cleanupKeycloakInstance() {
        List.copyOf(knownRealms)
                .forEach(realmName -> {
                    findRealmByName(realmName).remove();
                    knownRealms.remove(realmName);
                });
    }

    private static RealmResource findRealmByName(String realm) {
        return keycloak
                .realms()
                .realm(realm);
    }
}
