package io.phasetwo.keycloak.magic;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.containers.GenericContainer;

/**
 * Starts the test class's Keycloak container with the SPI option {@code legacy=false}, so that
 * the server issues stateless Login Tokens. The format cannot be chosen per request, which is why
 * tests of the stateless format need their own server configuration.
 *
 * <p>Works on the public static {@code container} field of the test base classes. It runs before
 * their {@code @BeforeAll} starts the container and restores the shared container object after
 * their {@code @AfterAll} has stopped it.
 */
public class StatelessLoginTokenServer implements BeforeAllCallback, AfterAllCallback {

  @Override
  public void beforeAll(ExtensionContext context) throws Exception {
    container(context).withEnv(LoginTokenTestSupport.LEGACY_OPTION_ENV, "false");
  }

  @Override
  public void afterAll(ExtensionContext context) throws Exception {
    container(context).getEnvMap().remove(LoginTokenTestSupport.LEGACY_OPTION_ENV);
  }

  private static GenericContainer<?> container(ExtensionContext context) throws Exception {
    return (GenericContainer<?>) context.getRequiredTestClass().getField("container").get(null);
  }
}
