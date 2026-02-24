package io.phasetwo.keycloak.magic.web;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.github.wimdeblauwe.testcontainers.cypress.CypressContainer;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTest;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTestResults;
import io.github.wimdeblauwe.testcontainers.cypress.CypressTestSuite;
import io.phasetwo.keycloak.magic.Helpers;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.hamcrest.CoreMatchers;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;

@JBossLog
public abstract class AbstractMagicLinkWithMailhogTest extends AbstractMagicLinkTest {

    public static final GenericContainer<?> mailHog = new GenericContainer<>("mailhog/mailhog:v1.0.1")
            .withNetwork(network)
            .withNetworkAliases("mailhog")
            .withExposedPorts(1025, 8025);

    @AfterAll
    public static void tearDown() throws IOException {
        mailHog.stop();
    }

    @BeforeAll
    public static void beforeAll() {
        mailHog.start();
    }
}
