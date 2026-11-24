package io.phasetwo.keycloak.magic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.phasetwo.keycloak.magic.auth.token.LoginTokenKeys;
import jakarta.ws.rs.core.Response;
import java.util.List;
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

  /**
   * Environment variable form of the SPI option {@code
   * --spi-realm-restapi-extension--login-token--legacy}. Setting it to {@code "false"} makes the
   * server issue stateless tokens; there is no way to choose the format per request.
   */
  public static final String LEGACY_OPTION_ENV =
      "KC_SPI_REALM_RESTAPI_EXTENSION__LOGIN_TOKEN__LEGACY";

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
    return addLoginTokenKeyProvider(keycloak, realm, priority, true);
  }

  /** Adds the key provider in a disabled state: present, but offering no usable key. */
  public static String addDisabledLoginTokenKeyProvider(Keycloak keycloak, String realm) {
    return addLoginTokenKeyProvider(keycloak, realm, 10, false);
  }

  /** The realm's key providers named {@code login-token}. */
  public static List<ComponentRepresentation> loginTokenKeyProviders(
      Keycloak keycloak, String realm) {
    String realmId = keycloak.realm(realm).toRepresentation().getId();
    return keycloak
        .realm(realm)
        .components()
        .query(realmId, "org.keycloak.keys.KeyProvider", LoginTokenKeys.KEY_PROVIDER_NAME);
  }

  private static String addLoginTokenKeyProvider(
      Keycloak keycloak, String realm, int priority, boolean enabled) {
    MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
    config.putSingle("priority", String.valueOf(priority));
    config.putSingle("secretSize", "32");
    config.putSingle("enabled", String.valueOf(enabled));
    config.putSingle("active", String.valueOf(enabled));

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
