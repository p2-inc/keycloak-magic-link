package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** */
@JBossLog
@AutoService(RealmResourceProviderFactory.class)
public class MagicLinkResourceProviderFactory implements RealmResourceProviderFactory {

  private static final String ID = "magic-link";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public void close() {}

  @Override
  public MagicLinkResourceProvider create(KeycloakSession session) {
    return new MagicLinkResourceProvider(session);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}
}
