package io.phasetwo.keycloak.magic.jpa;

import com.google.auto.service.AutoService;
import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(JpaEntityProviderFactory.class)
public class TinyUrlEntityProviderFactory implements JpaEntityProviderFactory {
  protected static final String ID = "tinyurl-entity-provider";

  @Override
  public JpaEntityProvider create(KeycloakSession session) {
    return new TinyUrlJpaEntityProvider();
  }

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public void init(Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
