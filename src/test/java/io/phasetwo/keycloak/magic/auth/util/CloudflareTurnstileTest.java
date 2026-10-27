package io.phasetwo.keycloak.magic.auth.util;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_ACTION;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_SITE_KEY;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_SITE_SECRET;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.ACTION;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.completeConfig;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.configModel;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.configWithout;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.siteverifyBody;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.stubSiteverify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;

class CloudflareTurnstileTest {

  @Test
  void completeConfigIsConfigured() {
    assertTrue(CloudflareTurnstile.isTurnstileCaptchaConfigured(completeConfig()));
    assertTrue(CloudflareTurnstile.getMissingConfigKeys(completeConfig()).isEmpty());
  }

  @Test
  void nullConfigIsNotConfigured() {
    assertFalse(CloudflareTurnstile.isTurnstileCaptchaConfigured(null));
    assertEquals(
        List.of(CF_SITE_KEY, CF_SITE_SECRET, CF_ACTION),
        CloudflareTurnstile.getMissingConfigKeys(null));
  }

  @ParameterizedTest
  @ValueSource(strings = {CF_SITE_KEY, CF_SITE_SECRET, CF_ACTION})
  void missingRequiredKeyIsNotConfigured(String key) {
    AuthenticatorConfigModel config = configWithout(key);

    assertFalse(CloudflareTurnstile.isTurnstileCaptchaConfigured(config));
    assertEquals(List.of(key), CloudflareTurnstile.getMissingConfigKeys(config));
  }

  @ParameterizedTest
  @ValueSource(strings = {CF_SITE_KEY, CF_SITE_SECRET, CF_ACTION})
  void blankRequiredKeyIsNotConfigured(String key) {
    AuthenticatorConfigModel config = completeConfig();
    config.getConfig().put(key, "  ");

    assertFalse(CloudflareTurnstile.isTurnstileCaptchaConfigured(config));
  }

  @ParameterizedTest
  @ValueSource(strings = {CF_SITE_KEY, CF_SITE_SECRET})
  void configWithOnlyOneCredentialIsPartiallyConfigured(String key) {
    Map<String, String> config = new HashMap<>();
    config.put(key, "value");
    config.put(CF_ACTION, ACTION);

    assertTrue(CloudflareTurnstile.isTurnstileCaptchaPartiallyConfigured(configModel(config)));
  }

  @Test
  void configWithoutCredentialsIsNotPartiallyConfigured() {
    // The admin console pre-fills the action, so an untouched config still has it set.
    Map<String, String> config = new HashMap<>();
    config.put(CF_ACTION, ACTION);

    assertFalse(CloudflareTurnstile.isTurnstileCaptchaPartiallyConfigured(configModel(config)));
    assertFalse(CloudflareTurnstile.isTurnstileCaptchaPartiallyConfigured(null));
    assertFalse(CloudflareTurnstile.isTurnstileCaptchaPartiallyConfigured(completeConfig()));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"  "})
  void blankTokenFailsWithoutCallingSiteverify(String token) {
    KeycloakSession session = mock(KeycloakSession.class);

    assertFalse(CloudflareTurnstile.validate(config(), token, "127.0.0.1", session));
    verifyNoInteractions(session);
  }

  @Test
  void acceptedTokenWithMatchingActionPasses() throws Exception {
    KeycloakSession session = mock(KeycloakSession.class);
    stubSiteverify(session, 200, siteverifyBody(true, ACTION));

    assertTrue(CloudflareTurnstile.validate(config(), "token", "127.0.0.1", session));
  }

  @Test
  void rejectedTokenFails() throws Exception {
    KeycloakSession session = mock(KeycloakSession.class);
    stubSiteverify(session, 200, siteverifyBody(false, ACTION));

    assertFalse(CloudflareTurnstile.validate(config(), "token", "127.0.0.1", session));
  }

  @Test
  void acceptedTokenWithOtherActionFails() throws Exception {
    KeycloakSession session = mock(KeycloakSession.class);
    stubSiteverify(session, 200, siteverifyBody(true, "register"));

    assertFalse(CloudflareTurnstile.validate(config(), "token", "127.0.0.1", session));
  }

  @Test
  void siteverifyErrorStatusFails() throws Exception {
    KeycloakSession session = mock(KeycloakSession.class);
    stubSiteverify(session, 500, "");

    assertFalse(CloudflareTurnstile.validate(config(), "token", "127.0.0.1", session));
  }

  private static CloudflareTurnstile.Config config() {
    return CloudflareTurnstile.readConfig(completeConfig().getConfig());
  }
}
