package io.phasetwo.keycloak.magic.auth.token;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link MagicLinkActionToken}, focusing on the new
 * {@code forceSessionLoa} and {@code acrValues} fields introduced for
 * browser-flow step-up authentication support.
 */
class MagicLinkActionTokenTest {

    @Test
    void testNewFieldsSetViaFullConstructor() {
        MagicLinkActionToken token = new MagicLinkActionToken(
                "user-id", 3600, "client-id", "https://example.com/callback",
                "openid", "nonce", "state",
                null, null, false, true, null,
                1, "2");

        assertEquals(1, token.getForceSessionLoa());
        assertEquals("2", token.getAcrValues());
    }

    @Test
    void testNewFieldsAreNullWhenNotProvided() {
        MagicLinkActionToken token = new MagicLinkActionToken(
                "user-id", 3600, "client-id", "https://example.com/callback",
                "openid", "nonce", "state",
                null, null, false, true, null);

        assertNull(token.getForceSessionLoa());
        assertNull(token.getAcrValues());
    }

    @Test
    void testNewFieldsNullWhenPassedAsNull() {
        MagicLinkActionToken token = new MagicLinkActionToken(
                "user-id", 3600, "client-id", "https://example.com/callback",
                "openid", "nonce", "state",
                null, null, false, true, null,
                null, null);

        assertNull(token.getForceSessionLoa());
        assertNull(token.getAcrValues());
    }

    @Test
    void testSettersWork() {
        MagicLinkActionToken token = new MagicLinkActionToken(
                "user-id", 3600, "client-id", "https://example.com/callback");

        token.setForceSessionLoa(2);
        token.setAcrValues("gold");

        assertEquals(2, token.getForceSessionLoa());
        assertEquals("gold", token.getAcrValues());
    }

    @Test
    void testTokenType() {
        assertEquals("ext-magic-link", MagicLinkActionToken.TOKEN_TYPE);
    }
}
