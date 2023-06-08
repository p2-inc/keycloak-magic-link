package io.phasetwo.keycloak.magic.resources;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;

@JBossLog
public class TinyUrlResourceProvider extends BaseRealmResourceProvider {

  private final KeycloakSession session;

  public TinyUrlResourceProvider(KeycloakSession session) {
    super(session);
    this.session = session;
  }

  @Override
  public Object getRealmResource() {
    TinyUrlResource tinyUrl = new TinyUrlResource(session);
    return tinyUrl;
  }

  @Override
  public void close() {}
}
