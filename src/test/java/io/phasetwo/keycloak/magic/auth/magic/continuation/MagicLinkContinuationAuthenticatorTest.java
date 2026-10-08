package io.phasetwo.keycloak.magic.auth.magic.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class MagicLinkContinuationAuthenticatorTest {

  @Test
  void externalMagicLinkUrlUsesConfiguredUrlAndToken() {
    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            "https://capture.example.com/magic-login",
            () -> "signed-token",
            () -> "https://keycloak.example.com/default");

    assertEquals("https://capture.example.com/magic-login?key=signed-token", link);
  }

  @Test
  void externalMagicLinkUrlIsTrimmed() {
    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            "  https://capture.example.com/magic-login  ",
            () -> "signed-token",
            () -> "https://keycloak.example.com/default");

    assertEquals("https://capture.example.com/magic-login?key=signed-token", link);
  }

  @Test
  void externalMagicLinkUrlPreservesExistingQueryParameters() {
    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            "https://capture.example.com/magic-login?source=email",
            () -> "signed-token",
            () -> "https://keycloak.example.com/default");

    assertTrue(link.startsWith("https://capture.example.com/magic-login?"));
    assertTrue(link.contains("source=email"));
    assertTrue(link.contains("key=signed-token"));
  }

  @Test
  void nullExternalMagicLinkUrlUsesStandardLink() {
    AtomicBoolean tokenSerialized = new AtomicBoolean(false);

    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            null,
            () -> {
              tokenSerialized.set(true);
              return "signed-token";
            },
            () -> "https://keycloak.example.com/default");

    assertEquals("https://keycloak.example.com/default", link);
    assertFalse(tokenSerialized.get());
  }

  @Test
  void blankExternalMagicLinkUrlUsesStandardLink() {
    AtomicBoolean tokenSerialized = new AtomicBoolean(false);

    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            "   ",
            () -> {
              tokenSerialized.set(true);
              return "signed-token";
            },
            () -> "https://keycloak.example.com/default");

    assertEquals("https://keycloak.example.com/default", link);
    assertFalse(tokenSerialized.get());
  }

  @Test
  void configuredExternalMagicLinkDoesNotBuildStandardLink() {
    AtomicBoolean standardLinkBuilt = new AtomicBoolean(false);

    String link =
        MagicLinkContinuationAuthenticator.buildMagicLink(
            "https://capture.example.com/magic-login",
            () -> "signed-token",
            () -> {
              standardLinkBuilt.set(true);
              return "https://keycloak.example.com/default";
            });

    assertEquals("https://capture.example.com/magic-login?key=signed-token", link);
    assertFalse(standardLinkBuilt.get());
  }
}
