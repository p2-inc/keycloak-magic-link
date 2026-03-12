package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link MagicLinkRequest} serialization/deserialization,
 * focusing on the new {@code loa} and {@code acr_values} parameters.
 */
class MagicLinkRequestTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testLoaDeserializedFromJsonField() throws Exception {
        String json = "{\"email\":\"user@example.com\",\"client_id\":\"test\","
                + "\"redirect_uri\":\"https://example.com\",\"loa\":2}";
        MagicLinkRequest request = mapper.readValue(json, MagicLinkRequest.class);
        assertEquals(2, request.getForceSessionLoa());
    }

    @Test
    void testAcrValuesDeserializedFromJsonField() throws Exception {
        String json = "{\"email\":\"user@example.com\",\"client_id\":\"test\","
                + "\"redirect_uri\":\"https://example.com\",\"acr_values\":\"2\"}";
        MagicLinkRequest request = mapper.readValue(json, MagicLinkRequest.class);
        assertEquals("2", request.getAcrValues());
    }

    @Test
    void testLoaAndAcrValuesCombined() throws Exception {
        String json = "{\"email\":\"user@example.com\",\"client_id\":\"test\","
                + "\"redirect_uri\":\"https://example.com\",\"loa\":1,\"acr_values\":\"2\"}";
        MagicLinkRequest request = mapper.readValue(json, MagicLinkRequest.class);
        assertEquals(1, request.getForceSessionLoa());
        assertEquals("2", request.getAcrValues());
    }

    @Test
    void testLoaIsNullByDefault() throws Exception {
        String json = "{\"email\":\"user@example.com\",\"client_id\":\"test\","
                + "\"redirect_uri\":\"https://example.com\"}";
        MagicLinkRequest request = mapper.readValue(json, MagicLinkRequest.class);
        assertNull(request.getForceSessionLoa());
        assertNull(request.getAcrValues());
    }

    @Test
    void testLoaSerializesWithCorrectFieldName() throws Exception {
        MagicLinkRequest request = new MagicLinkRequest();
        request.setForceSessionLoa(2);
        request.setAcrValues("2");
        String json = mapper.writeValueAsString(request);
        assertTrue(json.contains("\"loa\":2"), "Expected JSON field 'loa' for forceSessionLoa, got: " + json);
        assertTrue(json.contains("\"acr_values\":\"2\""), "Expected JSON field 'acr_values', got: " + json);
    }
}
