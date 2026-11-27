package io.phasetwo.keycloak.magic.auth.magic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderEventListener;

class MagicLinkAuthenticatorFactoryTest {

  @Test
  void registersRealmCreationHookWhenOptionIsUnset() {
    KeycloakSessionFactory sessionFactory = initAndPostInit(Map.of());

    verify(sessionFactory).register(any(ProviderEventListener.class));
  }

  @Test
  void registersRealmCreationHookWhenOptionIsTrue() {
    KeycloakSessionFactory sessionFactory = initAndPostInit(Map.of("create-default-flow", "true"));

    verify(sessionFactory).register(any(ProviderEventListener.class));
  }

  @Test
  void skipsRealmCreationHookWhenOptionIsFalse() {
    KeycloakSessionFactory sessionFactory = initAndPostInit(Map.of("create-default-flow", "false"));

    verify(sessionFactory, never()).register(any(ProviderEventListener.class));
  }

  @Test
  void declaresCreateDefaultFlowOption() {
    ProviderConfigProperty option =
        new MagicLinkAuthenticatorFactory().getConfigMetadata().getFirst();

    assertThat(option.getName(), is("create-default-flow"));
    assertThat(option.getType(), is(ProviderConfigProperty.BOOLEAN_TYPE));
    assertThat(option.getDefaultValue(), is(true));
  }

  @Test
  void declaresOnlyCreateDefaultFlowOption() {
    assertThat(
        new MagicLinkAuthenticatorFactory()
            .getConfigMetadata().stream().map(ProviderConfigProperty::getName).toList(),
        contains("create-default-flow"));
  }

  private static KeycloakSessionFactory initAndPostInit(Map<String, String> options) {
    MagicLinkAuthenticatorFactory factory = new MagicLinkAuthenticatorFactory();
    KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
    factory.init(new MapScope(options));
    factory.postInit(sessionFactory);
    return sessionFactory;
  }

  /** Provider scope backed by a map, parsed the same way Keycloak parses real options. */
  private static final class MapScope extends Config.AbstractScope {
    private final Map<String, String> values;

    MapScope(Map<String, String> values) {
      this.values = values;
    }

    @Override
    public String get(String key) {
      return values.get(key);
    }

    @Override
    public Config.Scope scope(String... scope) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> getPropertyNames() {
      return values.keySet();
    }

    @Override
    public Config.Scope root() {
      throw new UnsupportedOperationException();
    }
  }
}
