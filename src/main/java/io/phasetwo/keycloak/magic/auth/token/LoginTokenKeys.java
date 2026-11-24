package io.phasetwo.keycloak.magic.auth.token;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Resolves the AES keys used for stateless Login Tokens from the realm's key providers.
 *
 * <p>Only keys of a key provider <em>named</em> {@value #KEY_PROVIDER_NAME} are used (Realm
 * settings → Keys → Add providers → {@code aes-generated}). Keeping a dedicated provider means
 * rotating or removing the Login Token key never affects anything else Keycloak encrypts with the
 * realm's default AES key.
 *
 * <p>Rotation: add a second provider with the same name and a higher priority. New tokens are
 * encrypted with it, while tokens issued under the old key keep working until the old provider is
 * disabled or removed.
 */
public final class LoginTokenKeys {

  /** Name of the realm key provider(s) whose keys encrypt stateless Login Tokens. */
  public static final String KEY_PROVIDER_NAME = "login-token";

  private LoginTokenKeys() {}

  /** The key new tokens are encrypted with: the active key with the highest provider priority. */
  public static Optional<SecretKey> encryptionKey(KeycloakSession session, RealmModel realm) {
    return keys(session, realm)
        .filter(k -> k.getStatus().isActive())
        .max(Comparator.comparingLong(KeyWrapper::getProviderPriority))
        .map(LoginTokenKeys::toAesKey);
  }

  /** All keys a token may have been encrypted with: every enabled (active or passive) key. */
  public static List<SecretKey> decryptionKeys(KeycloakSession session, RealmModel realm) {
    return keys(session, realm)
        .sorted(Comparator.comparingLong(KeyWrapper::getProviderPriority).reversed())
        .map(LoginTokenKeys::toAesKey)
        .collect(Collectors.toList());
  }

  private static Stream<KeyWrapper> keys(KeycloakSession session, RealmModel realm) {
    Set<String> providerIds =
        realm
            .getComponentsStream(realm.getId(), KeyProvider.class.getName())
            .filter(c -> KEY_PROVIDER_NAME.equals(c.getName()))
            .map(ComponentModel::getId)
            .collect(Collectors.toSet());
    if (providerIds.isEmpty()) {
      return Stream.empty();
    }
    return session
        .keys()
        .getKeysStream(realm, KeyUse.ENC, Algorithm.AES)
        .filter(k -> providerIds.contains(k.getProviderId()))
        .filter(k -> k.getStatus() != null && k.getStatus().isEnabled())
        .filter(k -> k.getSecretKey() != null && isAesKeyLength(k.getSecretKey().getEncoded()));
  }

  private static boolean isAesKeyLength(byte[] key) {
    return key != null && (key.length == 16 || key.length == 24 || key.length == 32);
  }

  private static SecretKey toAesKey(KeyWrapper key) {
    return new SecretKeySpec(key.getSecretKey().getEncoded(), "AES");
  }
}
