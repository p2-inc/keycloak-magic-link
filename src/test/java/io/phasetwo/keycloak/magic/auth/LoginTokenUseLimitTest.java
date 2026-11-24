package io.phasetwo.keycloak.magic.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.phasetwo.keycloak.magic.auth.token.LoginToken;
import io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

/**
 * Use-limit handling shared by legacy and stateless Login Tokens, including the notes written by
 * plugin versions that only knew the {@code reusable} flag.
 */
class LoginTokenUseLimitTest {

  private static final String USE_ID = "5d3f0b1c-6f43-4f7e-9a51-0d3b8f5f2a10";

  private InMemorySingleUseObjects store;
  private AuthenticationFlowContext context;

  @BeforeEach
  void setUp() {
    store = new InMemorySingleUseObjects();
    KeycloakSession session = mock(KeycloakSession.class);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
    context = mock(AuthenticationFlowContext.class);
    when(context.getSession()).thenReturn(session);
  }

  private static String expiryIn(long seconds) {
    return String.valueOf(System.currentTimeMillis() / 1000L + seconds);
  }

  private boolean redeem(Map<String, String> notes) {
    return LoginTokenHelper.reserveUse(context, USE_ID, notes, expiryIn(600));
  }

  // --- Notes of the legacy token format written before max_uses existed -----------------------

  @Test
  void legacyNotesWithReusableTrueAreUnlimited() {
    Map<String, String> notes = Map.of(LoginToken.KEY_REUSABLE, "true");

    assertEquals(0, LoginTokenHelper.maxUses(notes));
    for (int i = 0; i < 25; i++) {
      assertTrue(redeem(notes));
    }
    assertTrue(store.keys().isEmpty(), "an unlimited token must not store anything");
  }

  @Test
  void legacyNotesWithoutReusableAreSingleUse() {
    Map<String, String> notes = Map.of(LoginToken.KEY_USER_ID, "some-user");

    assertEquals(1, LoginTokenHelper.maxUses(notes));
    assertTrue(redeem(notes));
    assertFalse(redeem(notes));
  }

  @Test
  void singleUseKeepsTheLegacyMarkerKey() {
    // A token redeemed on an old node during a rolling upgrade must stay redeemed on a new one.
    Map<String, String> notes = Map.of(LoginToken.KEY_MAX_USES, "1");

    assertTrue(redeem(notes));
    assertEquals(Set.of("lt:used:" + USE_ID), store.keys());
  }

  // --- max_uses ------------------------------------------------------------------------------

  @Test
  void maxUsesTakesPrecedenceOverReusable() {
    Map<String, String> notes =
        Map.of(LoginToken.KEY_MAX_USES, "1", LoginToken.KEY_REUSABLE, "true");

    assertEquals(1, LoginTokenHelper.maxUses(notes));
  }

  @Test
  void tokenIsRejectedOnceEveryUseIsClaimed() {
    Map<String, String> notes = Map.of(LoginToken.KEY_MAX_USES, "3");

    assertTrue(redeem(notes));
    assertTrue(redeem(notes));
    assertTrue(redeem(notes));
    assertFalse(redeem(notes));
    assertFalse(redeem(notes));
    assertEquals(
        Set.of("lt:used:" + USE_ID, "lt:used:" + USE_ID + ":2", "lt:used:" + USE_ID + ":3"),
        store.keys());
  }

  @Test
  void zeroMeansUnlimited() {
    Map<String, String> notes = Map.of(LoginToken.KEY_MAX_USES, "0");

    for (int i = 0; i < 25; i++) {
      assertTrue(redeem(notes));
    }
    assertTrue(store.keys().isEmpty());
  }

  @Test
  void useMarkersLiveUntilTheTokenExpires() {
    Map<String, String> notes = Map.of(LoginToken.KEY_MAX_USES, "1");

    assertTrue(LoginTokenHelper.reserveUse(context, USE_ID, notes, expiryIn(600)));

    long ttl = store.lifespan("lt:used:" + USE_ID);
    assertTrue(ttl > 590 && ttl <= 600, "ttl was " + ttl);
  }

  @Test
  void outOfRangeOrMalformedValuesFailClosed() {
    assertEquals(
        StatelessLoginToken.MAX_USES_LIMIT,
        LoginTokenHelper.maxUses(Map.of(LoginToken.KEY_MAX_USES, "5000")));
    assertEquals(0, LoginTokenHelper.maxUses(Map.of(LoginToken.KEY_MAX_USES, "-4")));
    assertEquals(1, LoginTokenHelper.maxUses(Map.of(LoginToken.KEY_MAX_USES, "many")));
  }

  /** Minimal {@link SingleUseObjectProvider} with the same put-if-absent semantics. */
  private static final class InMemorySingleUseObjects implements SingleUseObjectProvider {
    private final Map<String, Map<String, String>> entries = new HashMap<>();
    private final Map<String, Long> lifespans = new HashMap<>();

    Set<String> keys() {
      return Set.copyOf(entries.keySet());
    }

    long lifespan(String key) {
      return lifespans.get(key);
    }

    @Override
    public void put(String key, long lifespanSeconds, Map<String, String> notes) {
      entries.put(key, notes);
      lifespans.put(key, lifespanSeconds);
    }

    @Override
    public Map<String, String> get(String key) {
      return entries.get(key);
    }

    @Override
    public Map<String, String> remove(String key) {
      lifespans.remove(key);
      return entries.remove(key);
    }

    @Override
    public boolean replace(String key, Map<String, String> notes) {
      return entries.replace(key, notes) != null;
    }

    @Override
    public boolean putIfAbsent(String key, long lifespanInSeconds) {
      if (entries.containsKey(key)) {
        return false;
      }
      put(key, lifespanInSeconds, Map.of());
      return true;
    }

    @Override
    public boolean contains(String key) {
      return entries.containsKey(key);
    }

    @Override
    public void close() {}
  }
}
