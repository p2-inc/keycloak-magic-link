package io.phasetwo.keycloak.magic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.phasetwo.keycloak.magic.auth.token.LoginTokenKeys;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;

/** Test helpers shared by the Login Token integration tests. */
public final class LoginTokenTestSupport {

  /** {@code login_hint} of the legacy token format: {@code lt:} followed by a UUID. */
  public static final String LEGACY_LOGIN_HINT_PATTERN =
      "lt:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

  /** {@code login_hint} of a stateless token: {@code lt:v2.} followed by base64url. */
  public static final String STATELESS_LOGIN_HINT_PATTERN = "lt:v2\\.[A-Za-z0-9_-]+";

  private LoginTokenTestSupport() {}

  /**
   * Adds the {@code aes-generated} key provider that stateless Login Tokens are encrypted with to
   * the realm, the way an administrator would under Realm settings → Keys.
   *
   * @return the id of the created component.
   */
  public static String addLoginTokenKeyProvider(Keycloak keycloak, String realm) {
    return addLoginTokenKeyProvider(keycloak, realm, 10);
  }

  public static String addLoginTokenKeyProvider(Keycloak keycloak, String realm, int priority) {
    MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
    config.putSingle("priority", String.valueOf(priority));
    config.putSingle("secretSize", "32");
    config.putSingle("enabled", "true");
    config.putSingle("active", "true");

    ComponentRepresentation component = new ComponentRepresentation();
    component.setName(LoginTokenKeys.KEY_PROVIDER_NAME);
    component.setProviderId("aes-generated");
    component.setProviderType("org.keycloak.keys.KeyProvider");
    component.setParentId(keycloak.realm(realm).toRepresentation().getId());
    component.setConfig(config);

    try (Response response = keycloak.realm(realm).components().add(component)) {
      assertEquals(201, response.getStatus(), "key provider must be created");
      return CreatedResponseUtil.getCreatedId(response);
    }
  }
}
