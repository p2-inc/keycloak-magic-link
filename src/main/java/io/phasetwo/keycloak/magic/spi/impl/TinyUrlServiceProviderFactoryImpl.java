package io.phasetwo.keycloak.magic.spi.impl;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import io.phasetwo.keycloak.magic.spi.TinyUrlServiceProviderFactory;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(TinyUrlServiceProviderFactory.class)
public class TinyUrlServiceProviderFactoryImpl implements TinyUrlServiceProviderFactory {

  @Override
  public TinyUrlService create(KeycloakSession session) {
    return new TinyUrlServiceImpl(session);
  }

  @Override
  public void init(Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return "exampleServiceImpl";
  }
}
