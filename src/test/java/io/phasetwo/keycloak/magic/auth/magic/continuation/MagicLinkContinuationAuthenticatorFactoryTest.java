package io.phasetwo.keycloak.magic.auth.magic.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class MagicLinkContinuationAuthenticatorFactoryTest {

  @Test
  void exposesExternalMagicLinkUrlConfiguration() {
    MagicLinkContinuationAuthenticatorFactory factory =
        new MagicLinkContinuationAuthenticatorFactory();

    List<ProviderConfigProperty> properties = factory.getConfigProperties();

    ProviderConfigProperty externalUrl =
        properties.stream()
            .filter(
                property ->
                    MagicLinkContinuationAuthenticatorFactory.EXTERNAL_MAGIC_LINK_URL.equals(
                        property.getName()))
            .findFirst()
            .orElse(null);

    assertNotNull(externalUrl);
    assertEquals(ProviderConfigProperty.STRING_TYPE, externalUrl.getType());
    assertEquals("External Magic Link URL", externalUrl.getLabel());
    assertNotNull(externalUrl.getHelpText());
    assertTrue(externalUrl.getHelpText().contains("standard Keycloak action-token URL"));
  }
}
