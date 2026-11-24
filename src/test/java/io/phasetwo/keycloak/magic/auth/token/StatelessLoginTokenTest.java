package io.phasetwo.keycloak.magic.auth.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class StatelessLoginTokenTest {

  private static final String REALM_ID = "5f0c1d0e-1a2b-4c3d-8e9f-0a1b2c3d4e5f";
  private static final String USER_ID = "3b241101-e2bb-4255-8caf-4136c566a962";

  private static SecretKey newKey() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return new SecretKeySpec(bytes, "AES");
  }

  private static StatelessLoginToken.Payload fullPayload() {
    return new StatelessLoginToken.Payload()
        .setUserId(USER_ID)
        .setClientId("expressvpn-web-client")
        .setExpiry(1_900_000_000L)
        .setLoa(2)
        .setMaxUses(3)
        .setRememberMe(true)
        .setSetEmailVerified(true)
        .setConfirmUserSwitch(true);
  }

  @Test
  void roundTripPreservesEveryField() {
    SecretKey key = newKey();
    String token = StatelessLoginToken.seal(key, REALM_ID, fullPayload());

    StatelessLoginToken.Payload opened =
        StatelessLoginToken.open(List.of(key), REALM_ID, token).orElseThrow();

    assertEquals(USER_ID, opened.getUserId());
    assertEquals("expressvpn-web-client", opened.getClientId());
    assertEquals(1_900_000_000L, opened.getExpiry());
    assertEquals(2, opened.getLoa());
    assertEquals(3, opened.getMaxUses());
    assertTrue(opened.isRememberMe());
    assertTrue(opened.isSetEmailVerified());
    assertTrue(opened.isConfirmUserSwitch());
  }

  @Test
  void optionalFieldsStayAbsent() {
    SecretKey key = newKey();
    String token =
        StatelessLoginToken.seal(
            key, REALM_ID, new StatelessLoginToken.Payload().setUserId(USER_ID).setExpiry(42L));

    StatelessLoginToken.Payload opened =
        StatelessLoginToken.open(List.of(key), REALM_ID, token).orElseThrow();

    assertNull(opened.getClientId());
    assertNull(opened.getLoa());
    assertEquals(0, opened.getMaxUses());
    assertFalse(opened.isRememberMe());
    assertFalse(opened.isSetEmailVerified());
    assertFalse(opened.isConfirmUserSwitch());
  }

  @Test
  void nonUuidUserIdIsSupported() {
    SecretKey key = newKey();
    String federatedId = "f:9c1f2a44-77aa-4d0e-b7a6-2f1f6a1f0c11:külli@example.com";
    String token =
        StatelessLoginToken.seal(
            key, REALM_ID, new StatelessLoginToken.Payload().setUserId(federatedId).setExpiry(1L));

    assertEquals(
        federatedId,
        StatelessLoginToken.open(List.of(key), REALM_ID, token).orElseThrow().getUserId());
  }

  @Test
  void notesMatchTheLegacyTokenShape() {
    SecretKey key = newKey();
    String token = StatelessLoginToken.seal(key, REALM_ID, fullPayload());

    Map<String, String> notes =
        StatelessLoginToken.open(List.of(key), REALM_ID, token).orElseThrow().toNotes();

    assertEquals(USER_ID, notes.get(LoginToken.KEY_USER_ID));
    assertEquals("expressvpn-web-client", notes.get(LoginToken.KEY_CLIENT_ID));
    assertEquals("1900000000", notes.get(LoginToken.KEY_EXPIRY));
    assertEquals("2", notes.get(LoginToken.KEY_LOA));
    assertEquals("3", notes.get(LoginToken.KEY_MAX_USES));
    assertEquals("true", notes.get(LoginToken.KEY_REMEMBER_ME));
    assertEquals("true", notes.get(LoginToken.KEY_SEV));
    assertEquals("true", notes.get(LoginToken.KEY_CONFIRM_USER_SWITCH));
  }

  @Test
  void loginHintStaysBelowKeycloaksLengthLimit() {
    String token = StatelessLoginToken.seal(newKey(), REALM_ID, fullPayload());

    assertTrue(token.startsWith(StatelessLoginToken.PREFIX));
    assertTrue(
        ("lt:" + token).length() <= StatelessLoginToken.MAX_LOGIN_HINT_LENGTH,
        "login hint is " + ("lt:" + token).length() + " characters");
    // The token must survive a URL query parameter unescaped.
    assertTrue(token.matches("[A-Za-z0-9._-]+"), token);
  }

  @Test
  void everyTokenIsUniqueAndHasItsOwnUseId() {
    SecretKey key = newKey();
    String first = StatelessLoginToken.seal(key, REALM_ID, fullPayload());
    String second = StatelessLoginToken.seal(key, REALM_ID, fullPayload());

    assertNotEquals(first, second);
    assertNotEquals(
        StatelessLoginToken.open(List.of(key), REALM_ID, first).orElseThrow().getUseId(),
        StatelessLoginToken.open(List.of(key), REALM_ID, second).orElseThrow().getUseId());
  }

  @Test
  void modifiedTokenIsRejected() {
    SecretKey key = newKey();
    String token = StatelessLoginToken.seal(key, REALM_ID, fullPayload());
    byte[] raw =
        Base64.getUrlDecoder().decode(token.substring(StatelessLoginToken.PREFIX.length()));

    // Flipping any single byte — nonce, ciphertext or tag — must invalidate the token.
    for (int i = 0; i < raw.length; i++) {
      byte[] tampered = raw.clone();
      tampered[i] ^= 0x01;
      String tamperedToken =
          StatelessLoginToken.PREFIX
              + Base64.getUrlEncoder().withoutPadding().encodeToString(tampered);
      assertEquals(
          Optional.empty(),
          StatelessLoginToken.open(List.of(key), REALM_ID, tamperedToken),
          "byte " + i + " was modified without detection");
    }
  }

  @Test
  void tokenOfAnotherKeyOrRealmIsRejected() {
    SecretKey key = newKey();
    String token = StatelessLoginToken.seal(key, REALM_ID, fullPayload());

    assertTrue(StatelessLoginToken.open(List.of(newKey()), REALM_ID, token).isEmpty());
    assertTrue(StatelessLoginToken.open(List.of(key), "another-realm", token).isEmpty());
    assertTrue(StatelessLoginToken.open(List.of(), REALM_ID, token).isEmpty());
  }

  @Test
  void tokenOfARotatedKeyStillOpens() {
    SecretKey oldKey = newKey();
    SecretKey newKey = newKey();
    String token = StatelessLoginToken.seal(oldKey, REALM_ID, fullPayload());

    assertTrue(StatelessLoginToken.open(List.of(newKey, oldKey), REALM_ID, token).isPresent());
  }

  @Test
  void malformedInputIsRejectedWithoutThrowing() {
    List<SecretKey> keys = List.of(newKey());

    assertTrue(StatelessLoginToken.open(keys, REALM_ID, "v2.").isEmpty());
    assertTrue(StatelessLoginToken.open(keys, REALM_ID, "v2.AAAA").isEmpty());
    assertTrue(StatelessLoginToken.open(keys, REALM_ID, "v2.not base64 !!").isEmpty());
    assertTrue(StatelessLoginToken.open(keys, REALM_ID, USER_ID).isEmpty());
    assertTrue(StatelessLoginToken.open(keys, REALM_ID, null).isEmpty());
  }

  @Test
  void legacyTokenIdIsNotStateless() {
    assertFalse(StatelessLoginToken.isStateless(USER_ID));
    assertFalse(StatelessLoginToken.isStateless(null));
    assertTrue(StatelessLoginToken.isStateless("v2.abc"));
  }

  @Test
  void unrepresentablePayloadIsRefused() {
    SecretKey key = newKey();

    assertThrows(
        IllegalArgumentException.class,
        () ->
            StatelessLoginToken.seal(
                key, REALM_ID, fullPayload().setMaxUses(StatelessLoginToken.MAX_USES_LIMIT + 1)));
    assertThrows(
        IllegalArgumentException.class,
        () -> StatelessLoginToken.seal(key, REALM_ID, fullPayload().setClientId("c".repeat(256))));
    assertThrows(
        IllegalArgumentException.class,
        () -> StatelessLoginToken.seal(key, REALM_ID, fullPayload().setExpiry(1L << 33)));
  }

  @Test
  void logIdRevealsOnlyTheNonce() {
    SecretKey key = newKey();
    String token = StatelessLoginToken.seal(key, REALM_ID, fullPayload());
    String logId = StatelessLoginToken.logId(token);

    assertEquals(
        "v2:" + StatelessLoginToken.open(List.of(key), REALM_ID, token).orElseThrow().getUseId(),
        logId);
    assertFalse(logId.contains(token.substring(StatelessLoginToken.PREFIX.length())));
    // A legacy token id is a lookup key, not the credential, and is logged as is.
    assertEquals(USER_ID, StatelessLoginToken.logId(USER_ID));
  }
}
