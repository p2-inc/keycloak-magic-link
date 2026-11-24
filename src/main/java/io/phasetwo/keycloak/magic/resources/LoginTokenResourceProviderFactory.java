package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@JBossLog
@AutoService(RealmResourceProviderFactory.class)
public class LoginTokenResourceProviderFactory implements RealmResourceProviderFactory {

  private static final String ID = "login-token";

  /**
   * SPI option that sets the token format for requests that do not set {@code legacy} themselves.
   * Defaults to {@code true} (legacy format). {@code
   * --spi-realm-restapi-extension--login-token--legacy=false} makes stateless tokens the default;
   * set it only after every node runs a version that can verify stateless tokens.
   */
  static final String CONFIG_LEGACY = "legacy";

  private boolean legacyByDefault = true;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public LoginTokenResourceProvider create(KeycloakSession session) {
    return new LoginTokenResourceProvider(session, legacyByDefault);
  }

  @Override
  public void init(Config.Scope config) {
    legacyByDefault = config.getBoolean(CONFIG_LEGACY, true);
    log.infof("[LT] legacy login token format by default: %s", legacyByDefault);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
