package io.phasetwo.keycloak.magic.auth.magic.continuation;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

class MagicLinkContinuationAuthenticatorFactoryTest {

  private final MagicLinkContinuationAuthenticatorFactory factory =
      new MagicLinkContinuationAuthenticatorFactory();

  @Test
  void createReturnsMagicLinkContinuationAuthenticator() {
    Authenticator authenticator = factory.create(null);

    assertNotNull(authenticator);
    assertInstanceOf(MagicLinkContinuationAuthenticator.class, authenticator);
  }

  @Test
  void providerIdIsCorrect() {
    assertEquals("magic-link-continuation-form", factory.getId());
  }

  @Test
  void referenceCategoryIsAlternateAuth() {
    assertEquals("alternate-auth", factory.getReferenceCategory());
  }

  @Test
  void authenticatorIsConfigurable() {
    assertTrue(factory.isConfigurable());
  }

  @Test
  void userSetupIsAllowed() {
    assertTrue(factory.isUserSetupAllowed());
  }

  @Test
  void requirementChoicesAreCorrect() {
    AuthenticationExecutionModel.Requirement[] expected = {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.ALTERNATIVE,
      AuthenticationExecutionModel.Requirement.DISABLED
    };

    assertArrayEquals(expected, factory.getRequirementChoices());
  }

  @Test
  void displayTypeIsCorrect() {
    assertEquals("Magic Link continuation", factory.getDisplayType());
  }

  @Test
  void helpTextIsPresent() {
    assertEquals(
        "Sign in with a magic link that will be sent to your email.", factory.getHelpText());
  }

  @Test
  void exposesForceCreateUserConfiguration() {
    ProviderConfigProperty property = findProperty(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);

    assertEquals(ProviderConfigProperty.BOOLEAN_TYPE, property.getType());
    assertEquals("Force create user", property.getLabel());
    assertEquals(true, property.getDefaultValue());
    assertNotNull(property.getHelpText());
    assertFalse(property.getHelpText().isBlank());
  }

  @Test
  void exposesTimeoutConfiguration() {
    ProviderConfigProperty property = findProperty(MagicLinkConstants.TIMEOUT);

    assertEquals(ProviderConfigProperty.STRING_TYPE, property.getType());
    assertEquals("Expiration time", property.getLabel());
    assertEquals("10", property.getDefaultValue());
    assertNotNull(property.getHelpText());
    assertTrue(property.getHelpText().contains("10 minutes"));
  }

  @Test
  void exposesExternalMagicLinkUrlConfiguration() {
    ProviderConfigProperty property =
        findProperty(MagicLinkContinuationAuthenticatorFactory.EXTERNAL_MAGIC_LINK_URL);

    assertEquals(ProviderConfigProperty.STRING_TYPE, property.getType());
    assertEquals("External Magic Link URL", property.getLabel());
    assertNotNull(property.getHelpText());
    assertTrue(property.getHelpText().contains("standard Keycloak action-token URL"));
  }

  @Test
  void configPropertiesContainAllExpectedEntries() {
    List<ProviderConfigProperty> properties = factory.getConfigProperties();

    assertEquals(3, properties.size());

    assertTrue(
        properties.stream()
            .anyMatch(
                property -> CREATE_NONEXISTENT_USER_CONFIG_PROPERTY.equals(property.getName())));

    assertTrue(
        properties.stream()
            .anyMatch(property -> MagicLinkConstants.TIMEOUT.equals(property.getName())));

    assertTrue(
        properties.stream()
            .anyMatch(
                property ->
                    MagicLinkContinuationAuthenticatorFactory.EXTERNAL_MAGIC_LINK_URL.equals(
                        property.getName())));
  }

  @Test
  void lifecycleMethodsDoNotThrow() {
    assertDoesNotThrow(() -> factory.init(null));
    assertDoesNotThrow(() -> factory.postInit(null));
    assertDoesNotThrow(factory::close);
  }

  private ProviderConfigProperty findProperty(String name) {
    return factory.getConfigProperties().stream()
        .filter(property -> name.equals(property.getName()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Configuration property not found: " + name));
  }
}
