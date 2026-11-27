package io.phasetwo.keycloak.magic.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Without any provider option, every new realm gets the built-in "magic link" flow. Disabling it
 * is covered by {@link MagicLinkDefaultFlowDisabledTest}.
 */
class MagicLinkDefaultFlowTest extends AbstractMagicLinkTest {

  @Test
  void newRealmGetsBuiltInMagicLinkFlow() {
    String realmName = "default-flow-enabled";
    RealmRepresentation realm = new RealmRepresentation();
    realm.setRealm(realmName);
    realm.setEnabled(true);
    keycloak.realms().create(realm);
    try {
      AuthenticationFlowRepresentation flow =
          keycloak.realm(realmName).flows().getFlows().stream()
              .filter(f -> "magic link".equals(f.getAlias()))
              .findFirst()
              .orElseThrow(() -> new AssertionError("\"magic link\" flow not created"));
      assertThat(flow.isBuiltIn(), is(true));
    } finally {
      keycloak.realm(realmName).remove();
    }
  }
}
