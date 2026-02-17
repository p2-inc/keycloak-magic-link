package io.phasetwo.keycloak.magic;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.github.wimdeblauwe.testcontainers.cypress.CypressContainer;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTest;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTestResults;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTestSuite;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.hamcrest.CoreMatchers;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.hamcrest.MatcherAssert.assertThat;
import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

@JBossLog
public abstract class AbstractMagicLinkTest {

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
                .withProviderLibsFrom(getDeps())
                .withNetwork(network)
                .withAccessToHost(true);
        if (isJacocoPresent()) {
            keycloakContainer = keycloakContainer.withCopyFileToContainer(
                            MountableFile.forHostPath("target/jacoco-agent/"),
                            "/jacoco-agent"
                    )
                    .withEnv("JAVA_OPTS", "-XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -javaagent:/jacoco-agent/org.jacoco.agent-runtime.jar=destfile=/tmp/jacoco.exec");
        } else {
            keycloakContainer = keycloakContainer.withEnv("JAVA_OPTS", "-XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m");
        }

        return keycloakContainer;
    }

    private static boolean isJacocoPresent() {
        return Files.exists(Path.of("target/jacoco-agent/org.jacoco.agent-runtime.jar"));
    }

    protected static final int WEBHOOK_SERVER_PORT = 8083;

    @AfterAll
    public static void tearDown() throws IOException {
        String containerId = container.getContainerId();
        String containerShortId;
        if (containerId.length() > 12) {
            containerShortId = containerId.substring(0, 12);
        } else {
            containerShortId = containerId;
        }
        container.getDockerClient().stopContainerCmd(containerId).exec();
        if (isJacocoPresent()) {
            Files.createDirectories(Path.of("target", "jacoco-report"));
            container.copyFileFromContainer("/tmp/jacoco.exec", "./target/jacoco-report/jacoco-%s.exec".formatted(containerShortId));
        }
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

    protected final RealmRepresentation importRealm(String jsonRepresentationPath) {
        return importRealm(jsonRepresentationPath, null);
    }

    public static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

    protected final RealmRepresentation importRealm(String jsonRepresentationPath, @Nullable String realmOverride) {
        RealmRepresentation realm =
                loadJson(getClass().getResourceAsStream(jsonRepresentationPath),
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
        assertThat(response.getStatusCode(), CoreMatchers.is(Response.Status.CREATED.getStatusCode()));
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

    protected void assignEachUserAccountManagementRoles(RealmRepresentation realmRepresentation) {
        var realm = keycloak.realm(realmRepresentation.getRealm());
        var client = realm
                .clients()
                .findByClientId("account")
                .getFirst();
        var roles = realm
                .clients()
                .get(client.getId())
                .roles()
                .list();
        realm.users().list().forEach(user -> {
            realm
                    .users()
                    .get(user.getId())
                    .roles()
                    .clientLevel(client.getId())
                    .add(roles);
        });
    }

    @NotNull List<DynamicContainer> runCypressTests(String cypressTestFile) throws InterruptedException, TimeoutException, IOException {
        List<DynamicContainer> dynamicContainers = new ArrayList<>();
        Path screenshotDirectory = Path.of("target", "cypress-output", "screenshots");
        Files.createDirectories(screenshotDirectory);
        try (CypressContainer cypressContainer =
                     new CypressContainer()
                             .withBaseUrl("http://host.testcontainers.internal:" + container.getHttpPort() + "/auth/")
                             .withEnv("MAILHOG_URL", "http://mailhog:8025")
                             .withLogConsumer(new JbossLogConsumer(log))
                             .withSpec(cypressTestFile)
                             .withNetwork(network)
                             .withFileSystemBind(screenshotDirectory.toAbsolutePath().toString(), "/e2e/cypress/screenshots/", BindMode.READ_WRITE)
                             .withBrowser("electron")) {
            cypressContainer.start();
            CypressTestResults testResults = cypressContainer.getTestResults();
            dynamicContainers.addAll(convertToJUnitDynamicTests(testResults));
        }
        return dynamicContainers;
    }

    private List<DynamicContainer> convertToJUnitDynamicTests(CypressTestResults testResults) {
        List<DynamicContainer> dynamicContainers = new ArrayList<>();
        List<CypressTestSuite> suites = testResults.getSuites();
        for (CypressTestSuite suite : suites) {
            createContainerFromSuite(dynamicContainers, suite);
        }
        return dynamicContainers;
    }

    void createContainerFromSuite(List<DynamicContainer> dynamicContainers, CypressTestSuite suite) {
        List<DynamicTest> dynamicTests = new ArrayList<>();
        for (CypressTest test : suite.getTests()) {
            dynamicTests.add(
                    DynamicTest.dynamicTest(
                            test.getDescription(),
                            () -> {
                                if (!test.isSuccess()) {
                                    log.error(test.getErrorMessage());
                                    log.error(test.getStackTrace());
                                }
                                Assertions.assertTrue(test.isSuccess());
                            }));
        }
        dynamicContainers.add(DynamicContainer.dynamicContainer(suite.getTitle(), dynamicTests));
    }
}
