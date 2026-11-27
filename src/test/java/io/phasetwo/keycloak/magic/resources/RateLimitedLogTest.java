package io.phasetwo.keycloak.magic.resources;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.magic.resources.LoginTokenResource.RateLimitedLog;
import org.junit.jupiter.api.Test;

/** The limiter behind the "legacy token issued instead of a stateless one" error report. */
class RateLimitedLogTest {

  @Test
  void firstOccurrenceIsAlwaysReported() {
    RateLimitedLog limiter = new RateLimitedLog(60_000L);

    assertTrue(limiter.shouldLog(1_000L));
    assertEquals(0, limiter.takeSuppressed());
  }

  @Test
  void occurrencesWithinTheIntervalAreCountedNotReported() {
    RateLimitedLog limiter = new RateLimitedLog(60_000L);
    limiter.shouldLog(1_000L);

    assertFalse(limiter.shouldLog(1_001L));
    assertFalse(limiter.shouldLog(30_000L));
    assertFalse(limiter.shouldLog(60_999L));

    assertTrue(limiter.shouldLog(61_000L), "the interval has passed");
    assertEquals(3, limiter.takeSuppressed());
    assertEquals(0, limiter.takeSuppressed(), "the count restarts with every report");
  }
}
