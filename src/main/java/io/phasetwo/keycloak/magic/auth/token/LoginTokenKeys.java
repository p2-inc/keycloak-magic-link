package io.phasetwo.keycloak.magic.auth.token;

import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Resolves the AES keys used for stateless Login Tokens from the realm's key providers.
 *
 * <p>Only keys of a key provider <em>named</em> {@value #KEY_PROVIDER_NAME} are used. Keeping a
 * dedicated provider means rotating or removing the Login Token key never affects anything else
 * Keycloak encrypts with the realm's default AES key.
 *
 * <p>The provider is created on demand by {@link #ensureEncryptionKey} the first time a stateless
 * token is issued in a realm; it can also be added by hand (Realm settings → Keys → Add providers
 * → {@code aes-generated}). A provider that exists but is disabled is left alone — that is how an
 * administrator switches stateless tokens off for a realm.
 *
 * <p>Rotation: add a second provider with the same name and a higher priority. New tokens are
 * encrypted with it, while tokens issued under the old key keep working until the old provider is
 * disabled or removed.
 */
@JBossLog
public final class LoginTokenKeys {

  /** Name of the realm key provider(s) whose keys encrypt stateless Login Tokens. */
  public static final String KEY_PROVIDER_NAME = "login-token";

  /**
   * Priority of an automatically created provider. Keycloak's own key providers use 100; staying
   * below keeps Keycloak from ever selecting this key for its own purposes.
   */
  static final String AUTO_CREATED_PRIORITY = "10";

  private static final String AES_KEY_PROVIDER_ID = "aes-generated";

  private LoginTokenKeys() {}

  /** The key new tokens are encrypted with: the active key with the highest provider priority. */
  public static Optional<SecretKey> encryptionKey(KeycloakSession session, RealmModel realm) {
    return keys(session, realm)
        .filter(k -> k.getStatus().isActive())
        .max(Comparator.comparingLong(KeyWrapper::getProviderPriority))
        .map(LoginTokenKeys::toAesKey);
  }

  /**
   * Returns the encryption key, creating the realm's {@value #KEY_PROVIDER_NAME} key provider
   * first if the realm has none.
   *
   * <p>Creation runs in its own transaction under a component id derived from the realm id, so
   * concurrent requests — on this node or another — cannot end up with two providers: the database
   * accepts one insert and the others fail and read the winner's key. A node whose realm cache has
   * not seen the new provider yet gets an empty result once and issues a legacy token.
   *
   * @return the key, or empty if a provider exists but offers no active key (it was disabled or
   *     made passive on purpose) or creation is not possible.
   */
  public static Optional<SecretKey> ensureEncryptionKey(KeycloakSession session, RealmModel realm) {
    Optional<SecretKey> key = encryptionKey(session, realm);
    if (key.isPresent() || providerIds(realm).findAny().isPresent()) {
      return key;
    }
    String realmId = realm.getId();
    try {
      return KeycloakModelUtils.runJobInTransactionWithResult(
          session.getKeycloakSessionFactory(),
          s -> {
            RealmModel r = s.realms().getRealm(realmId);
            s.getContext().setRealm(r);
            if (providerIds(r).findAny().isEmpty()) {
              r.addComponentModel(newKeyProvider(r));
              log.infof(
                  "[LT] created key provider '%s' for stateless login tokens in realm '%s'",
                  KEY_PROVIDER_NAME, r.getName());
            }
            return encryptionKey(s, r);
          });
    } catch (RuntimeException e) {
      // Most likely a concurrent request created the provider first.
      log.debugf(e, "[LT] could not create key provider '%s', re-reading", KEY_PROVIDER_NAME);
    }
    try {
      return KeycloakModelUtils.runJobInTransactionWithResult(
          session.getKeycloakSessionFactory(),
          s -> {
            RealmModel r = s.realms().getRealm(realmId);
            s.getContext().setRealm(r);
            return encryptionKey(s, r);
          });
    } catch (RuntimeException e) {
      log.warnf(e, "[LT] could not read key provider '%s'", KEY_PROVIDER_NAME);
      return Optional.empty();
    }
  }

  private static ComponentModel newKeyProvider(RealmModel realm) {
    MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
    config.putSingle("priority", AUTO_CREATED_PRIORITY);
    config.putSingle("secretSize", "32");
    config.putSingle("enabled", "true");
    config.putSingle("active", "true");

    ComponentModel provider = new ComponentModel();
    provider.setId(autoCreatedProviderId(realm));
    provider.setName(KEY_PROVIDER_NAME);
    provider.setParentId(realm.getId());
    provider.setProviderId(AES_KEY_PROVIDER_ID);
    provider.setProviderType(KeyProvider.class.getName());
    provider.setConfig(config);
    return provider;
  }

  /** Deterministic per realm, so that only one automatically created provider can exist. */
  static String autoCreatedProviderId(RealmModel realm) {
    return UUID.nameUUIDFromBytes(
            ("login-token-key-provider:" + realm.getId()).getBytes(StandardCharsets.UTF_8))
        .toString();
  }

  /** All keys a token may have been encrypted with: every enabled (active or passive) key. */
  public static List<SecretKey> decryptionKeys(KeycloakSession session, RealmModel realm) {
    return keys(session, realm)
        .sorted(Comparator.comparingLong(KeyWrapper::getProviderPriority).reversed())
        .map(LoginTokenKeys::toAesKey)
        .collect(Collectors.toList());
  }

  private static Stream<KeyWrapper> keys(KeycloakSession session, RealmModel realm) {
    Set<String> providerIds = providerIds(realm).collect(Collectors.toSet());
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

  private static Stream<String> providerIds(RealmModel realm) {
    return realm
        .getComponentsStream(realm.getId(), KeyProvider.class.getName())
        .filter(c -> KEY_PROVIDER_NAME.equals(c.getName()))
        .map(ComponentModel::getId);
  }

  private static boolean isAesKeyLength(byte[] key) {
    return key != null && (key.length == 16 || key.length == 24 || key.length == 32);
  }

  private static SecretKey toAesKey(KeyWrapper key) {
    return new SecretKeySpec(key.getSecretKey().getEncoded(), "AES");
  }
}
