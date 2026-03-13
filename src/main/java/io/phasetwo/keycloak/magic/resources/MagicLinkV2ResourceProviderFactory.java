package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@JBossLog
@AutoService(RealmResourceProviderFactory.class)
public class MagicLinkV2ResourceProviderFactory implements RealmResourceProviderFactory {

  private static final String ID = "magic-link-v2";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public MagicLinkV2ResourceProvider create(KeycloakSession session) {
    return new MagicLinkV2ResourceProvider(session);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
