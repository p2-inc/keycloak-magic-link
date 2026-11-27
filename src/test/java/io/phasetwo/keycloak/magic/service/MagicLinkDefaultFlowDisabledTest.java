package io.phasetwo.keycloak.magic.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * With {@code --spi-authenticator--ext-magic-form--create-default-flow=false}, no realm gets the
 * built-in "magic link" flow, and the authenticator stays available for flows built by hand (issue
 * #241).
 *
 * <p>Runs its own Keycloak container: the provider option is read once at startup, so it cannot be
 * set on the container shared by {@link AbstractMagicLinkTest}.
 */
class MagicLinkDefaultFlowDisabledTest {

  private static final KeycloakContainer container =
      new KeycloakContainer(AbstractMagicLinkTest.KEYCLOAK_IMAGE)
          .withContextPath("/auth")
          .withProviderClassesFrom("target/classes")
          .withEnv("KC_SPI_AUTHENTICATOR__EXT_MAGIC_FORM__CREATE_DEFAULT_FLOW", "false");

  private static Keycloak keycloak;

  @BeforeAll
  static void startKeycloak() {
    container.start();
    keycloak = container.getKeycloakAdminClient();
  }

  @AfterAll
  static void stopKeycloak() {
    keycloak.close();
    container.stop();
  }

  @Test
  void newRealmHasNoMagicLinkFlow() {
    String realmName = "default-flow-disabled";
    RealmRepresentation realm = new RealmRepresentation();
    realm.setRealm(realmName);
    realm.setEnabled(true);
    keycloak.realms().create(realm);
    try {
      List<String> flows = topLevelFlowAliases(realmName);
      assertThat(flows, hasItem("browser"));
      assertThat(flows, not(hasItem("magic link")));
    } finally {
      keycloak.realm(realmName).remove();
    }
  }

  @Test
  void masterRealmHasNoMagicLinkFlow() {
    List<String> flows = topLevelFlowAliases("master");
    assertThat(flows, hasItem("browser"));
    assertThat(flows, not(hasItem("magic link")));
  }

  @Test
  void magicLinkAuthenticatorIsStillAvailable() {
    List<Object> authenticators =
        keycloak.realm("master").flows().getAuthenticatorProviders().stream()
            .map(provider -> provider.get("id"))
            .toList();
    assertThat(authenticators, hasItem("ext-magic-form"));
  }

  private static List<String> topLevelFlowAliases(String realmName) {
    return keycloak.realm(realmName).flows().getFlows().stream()
        .map(AuthenticationFlowRepresentation::getAlias)
        .toList();
  }
}
