package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@AutoService(RealmResourceProviderFactory.class)
public class TinyUrlResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "tinyurl";

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    return new TinyUrlResourceProvider(keycloakSession);
  }

  @Override
  public void init(Scope scope) {

  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
